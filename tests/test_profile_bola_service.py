"""Database-backed read-only BOLA test using caller-supplied profiles.

Uses an httpx.MockTransport, so no real network requests are made.
"""

import os

import httpx
import pytest
from sqlmodel import select

from api_security_system.auth import AuthIdentity, AuthProfile
from api_security_system.authz_bola import service
from api_security_system.authz_bola.candidate_selector import select_read_candidates
from api_security_system.db import (
    Endpoint,
    Finding,
    FindingEvidence,
    Scan,
    TestExecution,
    TestIdentity,
    Target,
    get_session,
)
from api_security_system.targets.service import _scan_findings

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set",
)

BASE_URL = "https://profile-bola.example"


def _cleanup(scan_id, target_id):
    if scan_id is not None:
        with get_session() as session:
            finding_ids = [
                row.id
                for row in session.exec(
                    select(Finding).where(Finding.scan_id == scan_id)
                ).all()
            ]
            for evidence in session.exec(
                select(FindingEvidence).where(
                    FindingEvidence.finding_id.in_(finding_ids)
                )
            ).all():
                session.delete(evidence)
            for finding in session.exec(
                select(Finding).where(Finding.scan_id == scan_id)
            ).all():
                session.delete(finding)
            for execution in session.exec(
                select(TestExecution).where(TestExecution.scan_id == scan_id)
            ).all():
                session.delete(execution)
            for identity in session.exec(
                select(TestIdentity).where(TestIdentity.scan_id == scan_id)
            ).all():
                session.delete(identity)
            for endpoint in session.exec(
                select(Endpoint).where(Endpoint.scan_id == scan_id)
            ).all():
                session.delete(endpoint)
            scan = session.get(Scan, scan_id)
            if scan is not None:
                session.delete(scan)
            session.commit()
    if target_id is not None:
        with get_session() as session:
            target = session.get(Target, target_id)
            if target is not None:
                session.delete(target)
            session.commit()


def test_profile_read_only_bola_confirms_cross_identity_read(monkeypatch):
    monkeypatch.setenv("APIVIGILANTE_ALLOW_USER_AUTHORIZED_TARGETS", "1")
    scan_id = None
    target_id = None
    try:
        with get_session() as session:
            target = Target(
                name="profile-bola-test",
                base_url=BASE_URL,
                openapi_spec_path="",
            )
            session.add(target)
            session.commit()
            session.refresh(target)
            target_id = target.id

            scan = Scan(target_id=target.id)
            session.add(scan)
            session.commit()
            session.refresh(scan)
            scan_id = scan.id

            session.add(
                Endpoint(
                    scan_id=scan.id,
                    path="/accounts/{account_id}",
                    method="GET",
                    operation_id="getAccount",
                    id_param_name="account_id",
                    raw_spec_fragment={
                        "security": [{"bearerAuth": []}],
                        "summary": "Get account",
                    },
                )
            )
            session.commit()

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/accounts/1"):
                return httpx.Response(
                    200, json={"id": "1", "username": "attacker"}
                )
            if request.url.path.endswith("/accounts/2"):
                return httpx.Response(
                    200, json={"id": "2", "username": "victim"}
                )
            return httpx.Response(404, json={"detail": "not found"})

        profile = AuthProfile(
            type="static",
            scheme="bearer",
            extra_headers={"X-Company-Key": "extra-secret"},
            identities=[
                AuthIdentity(
                    label="attacker",
                    token="attacker-token",
                    username="attacker",
                    path_values={"account_id": "1"},
                ),
                AuthIdentity(
                    label="victim",
                    token="victim-token",
                    username="victim",
                    path_values={"account_id": "2"},
                ),
            ],
        )

        result = service.run_bola_check(
            scan_id=scan_id,
            allow_identity_registration=True,
            llm_client=object(),
            executor_transport=httpx.MockTransport(handler),
            auth_profile=profile,
            authorized_for_active_testing=True,
        )

        assert result.requests_used == 2
        assert result.bfla_status == "not_supported"
        assert len(result.endpoint_results) == 1
        assert result.endpoint_results[0].outcome.value == "confirmed"
        assert result.endpoint_results[0].finding_id is not None

        response_findings = _scan_findings(scan_id)
        assert len(response_findings) == 1
        assert response_findings[0]["finding_type"] == "bola"
        assert response_findings[0]["status"] == "confirmed"
        assert response_findings[0]["path"] == "/accounts/{account_id}"
        assert response_findings[0]["evidence_execution_ids"]

        with get_session() as session:
            session.add(
                Endpoint(
                    scan_id=scan_id,
                    path="/tenants/{tenant_id}/accounts/{account_id}",
                    method="GET",
                    operation_id="getTenantAccount",
                    raw_spec_fragment={
                        "security": [{"bearerAuth": []}],
                        "summary": "Get tenant account",
                    },
                )
            )
            session.commit()

        candidates = select_read_candidates(scan_id)
        multi_parameter = [
            candidate
            for candidate in candidates
            if candidate.path == "/tenants/{tenant_id}/accounts/{account_id}"
        ]
        assert len(multi_parameter) == 1
        assert multi_parameter[0].path_params == [
            "tenant_id",
            "account_id",
        ]

        with get_session() as session:
            finding = session.get(
                Finding, result.endpoint_results[0].finding_id
            )
            assert finding is not None
            assert finding.status == "confirmed"
            assert "read access to" in finding.description
            identities = session.exec(
                select(TestIdentity).where(TestIdentity.scan_id == scan_id)
            ).all()
            assert {row.role_label for row in identities} == {
                "bola_attacker",
                "bola_victim",
            }
            executions = session.exec(
                select(TestExecution).where(TestExecution.scan_id == scan_id)
            ).all()
            persisted_headers = repr(
                [execution.request_headers for execution in executions]
            )
            assert "attacker-token" not in persisted_headers
            assert "extra-secret" not in persisted_headers
    finally:
        _cleanup(scan_id, target_id)
