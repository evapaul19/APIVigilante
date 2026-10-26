"""Database-backed assessment workflow coverage with target I/O stubbed."""

import json
import os
from uuid import uuid4

import pytest
from sqlmodel import select

from api_security_system.db import (
    AssessmentStage,
    Endpoint,
    Finding,
    FindingEvidence,
    Scan,
    Target,
    get_session,
)
from api_security_system.targets import service
from api_security_system.targets.security import ResolvedTarget
from api_security_system.targets.spec_fetch import FetchedSpec
from api_security_system.api import get_scan_report

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set",
)

BASE_URL = "http://localhost:5000"
PROVIDED_SPEC_URL = f"{BASE_URL}/custom/openapi.json"
SPEC_DOCUMENT = {
    "openapi": "3.0.3",
    "info": {"title": "Workflow regression API", "version": "1.0.0"},
    "servers": [{"url": BASE_URL}],
    "paths": {
        "/health": {
            "get": {
                "operationId": "getHealth",
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/accounts/{account_id}": {
            "get": {
                "operationId": "getAccount",
                "parameters": [
                    {
                        "name": "account_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {"200": {"description": "account"}},
            }
        },
    },
}


@pytest.mark.parametrize(
    "spec_url",
    [PROVIDED_SPEC_URL, None],
    ids=["provided-spec", "discovery-first"],
)
def test_assessment_persists_inventory_stages_and_report(
    monkeypatch, tmp_path, spec_url
):
    target_name = f"workflow-persistence-{uuid4().hex}"
    requested_specs = []
    spec_path = tmp_path / "openapi.json"
    spec_path.write_text(json.dumps(SPEC_DOCUMENT), encoding="utf-8")

    monkeypatch.setattr(
        service,
        "resolve_target",
        lambda _url: ResolvedTarget(
            base_url=BASE_URL,
            scheme="http",
            hostname="localhost",
            port=5000,
            addresses=("127.0.0.1",),
        ),
    )

    def acquire_spec(_base_url, requested_spec, *, resolved_target):
        requested_specs.append(requested_spec)
        assert resolved_target.addresses == ("127.0.0.1",)
        return FetchedSpec(
            document=SPEC_DOCUMENT,
            source_url=requested_spec or f"{BASE_URL}/openapi.json",
            raw=json.dumps(SPEC_DOCUMENT).encode("utf-8"),
            extension=".json",
            discovery_mode=requested_spec is None,
            limitations=(
                ["Bounded HTML discovery fixture."]
                if requested_spec is None
                else []
            ),
        )

    monkeypatch.setattr(service, "acquire_spec", acquire_spec)
    monkeypatch.setattr(service, "save_spec", lambda _spec: str(spec_path))

    try:
        result = service.create_assessment(
            base_url=BASE_URL,
            openapi_spec_url=spec_url,
            target_name=target_name,
            allow_identity_registration=False,
            classify=False,
        )
        scan_id = result["scan_id"]
        assert requested_specs == [spec_url]
        assert result["status"] == "completed"
        assert result["recon"]["endpoints_found"] == 2
        assert result["recon"]["endpoints_inserted"] == 2
        assert result["findings_count"] == 0

        with get_session() as session:
            scan = session.get(Scan, scan_id)
            assert scan is not None
            assert scan.status == "completed"
            assert scan.completed_at is not None

            endpoints = session.exec(
                select(Endpoint).where(Endpoint.scan_id == scan_id)
            ).all()
            assert {(item.method, item.path) for item in endpoints} == {
                ("GET", "/health"),
                ("GET", "/accounts/{account_id}"),
            }

            stages = {
                row.stage_name: row
                for row in session.exec(
                    select(AssessmentStage).where(
                        AssessmentStage.scan_id == scan_id
                    )
                ).all()
            }
            assert set(stages) == {
                "target_validation",
                "spec_discovery",
                "recon",
                "classification",
                "resource_graph",
                "authorization_checks",
                "sensitive_data_checks",
                "persistence",
                "report",
            }
            assert stages["spec_discovery"].status == (
                "discovery_only" if spec_url is None else "succeeded"
            )
            assert stages["recon"].status == "completed"
            assert stages["recon"].details["endpoints_inserted"] == 2
            assert stages["classification"].status == "not_requested"
            assert stages["persistence"].details["findings_persisted"] == 0

            report = get_scan_report(scan_id, session)
            assert report["status"] == "completed"
            assert report["total_endpoints"] == 2
            assert report["findings_count"] == 0
            assert report["findings"] == []
            assert report["zero_or_incomplete"]["zero_findings"] is True
            assert report["assessment"]["complete"] is False
            assert report["assessment"]["incomplete_reasons"]
    finally:
        with get_session() as session:
            target = session.exec(
                select(Target).where(Target.name == target_name)
            ).first()
            if target is not None:
                scans = session.exec(
                    select(Scan).where(Scan.target_id == target.id)
                ).all()
                for scan in scans:
                    for evidence in session.exec(
                        select(FindingEvidence).where(
                            FindingEvidence.finding_id.in_(
                                select(Finding.id).where(Finding.scan_id == scan.id)
                            )
                        )
                    ).all():
                        session.delete(evidence)
                    for model in (
                        Finding,
                        Endpoint,
                        AssessmentStage,
                    ):
                        for record in session.exec(
                            select(model).where(model.scan_id == scan.id)
                        ).all():
                            session.delete(record)
                    session.delete(scan)
                session.delete(target)
                session.commit()
