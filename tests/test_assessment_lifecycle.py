"""Lifecycle regression tests: terminal states, partial results, report truth.

These tests use the real database (skipped when DATABASE_URL is unset) but
stub all target I/O, so they are deterministic and make no network requests.
"""

import json
import os
from uuid import uuid4

import pytest
from sqlmodel import select

from api_security_system import api
from api_security_system.db import (
    AssessmentStage,
    Endpoint,
    Finding,
    FindingEvidence,
    Scan,
    ScanStatus,
    Target,
    get_session,
)
from api_security_system.targets import service
from api_security_system.targets.security import ResolvedTarget
from api_security_system.targets.spec_fetch import FetchedSpec

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set",
)

BASE_URL = "http://localhost:5000"
SPEC_DOCUMENT = {
    "openapi": "3.0.3",
    "info": {"title": "Lifecycle regression API", "version": "1.0.0"},
    "servers": [{"url": BASE_URL}],
    "paths": {
        "/health": {
            "get": {
                "operationId": "getHealth",
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
}


def _stub_target_io(monkeypatch, tmp_path):
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
        assert resolved_target.addresses == ("127.0.0.1",)
        return FetchedSpec(
            document=SPEC_DOCUMENT,
            source_url=requested_spec or f"{BASE_URL}/openapi.json",
            raw=json.dumps(SPEC_DOCUMENT).encode("utf-8"),
            extension=".json",
            discovery_mode=requested_spec is None,
            limitations=[],
        )

    monkeypatch.setattr(service, "acquire_spec", acquire_spec)
    monkeypatch.setattr(service, "save_spec", lambda _spec: str(spec_path))


def _cleanup_target(target_name: str) -> None:
    with get_session() as session:
        target = session.exec(
            select(Target).where(Target.name == target_name)
        ).first()
        if target is None:
            return
        for scan in session.exec(
            select(Scan).where(Scan.target_id == target.id)
        ).all():
            finding_ids = select(Finding.id).where(Finding.scan_id == scan.id)
            for evidence in session.exec(
                select(FindingEvidence).where(
                    FindingEvidence.finding_id.in_(finding_ids)
                )
            ).all():
                session.delete(evidence)
            for model in (Finding, Endpoint, AssessmentStage):
                for record in session.exec(
                    select(model).where(model.scan_id == scan.id)
                ).all():
                    session.delete(record)
            session.delete(scan)
        session.delete(target)
        session.commit()


def test_failed_security_stage_marks_scan_partial_and_report_is_consistent(
    monkeypatch, tmp_path
):
    target_name = f"lifecycle-partial-{uuid4().hex}"
    _stub_target_io(monkeypatch, tmp_path)

    # Force one security stage to fail without any target I/O. A scan that
    # still produced an inventory must be PARTIAL, never a clean COMPLETED.
    monkeypatch.setattr(
        service,
        "_sensitive_summary",
        lambda *_args, **_kwargs: {
            "status": "failed",
            "reason": "Sensitive-data checks failed: synthetic test failure.",
            "supported_for_target": True,
        },
    )

    try:
        result = service.create_assessment(
            base_url=BASE_URL,
            target_name=target_name,
            allow_identity_registration=False,
            classify=False,
        )
        scan_id = result["scan_id"]

        assert result["status"] == "partial"

        with get_session() as session:
            scan = session.get(Scan, scan_id)
            assert scan is not None
            assert scan.status == ScanStatus.PARTIAL
            assert scan.completed_at is not None

            stages = {
                row.stage_name: row
                for row in session.exec(
                    select(AssessmentStage).where(
                        AssessmentStage.scan_id == scan_id
                    )
                ).all()
            }
            assert stages["sensitive_data_checks"].status == "failed"
            assert stages["recon"].status == "completed"

            # Persist a finding so report/findings consistency is meaningful.
            endpoint = session.exec(
                select(Endpoint).where(Endpoint.scan_id == scan_id)
            ).first()
            assert endpoint is not None
            finding = Finding(
                scan_id=scan_id,
                endpoint_id=endpoint.id,
                finding_type="bola",
                severity="high",
                description="Synthetic confirmed BOLA finding.",
                status="confirmed",
                confidence=0.9,
            )
            session.add(finding)
            session.commit()
            session.refresh(finding)
            finding_id = finding.id

        with get_session() as session:
            report = api.get_scan_report(scan_id, session)
            findings = api.get_scan_findings(scan_id, session)

        assert report is not None
        assert report["status"] == "partial"
        assert report["summary"]["headline"] == "Assessment completed with limitations"
        assert report["summary"]["confirmed_findings"] == 1
        assert report["findings_count"] == 1
        assert [item["id"] for item in report["findings"]] == [finding_id]
        assert [item.id for item in findings] == [finding_id]
        report_finding = report["findings"][0]
        assert "Broken object-level authorization" in report_finding["title"]
        assert report_finding["remediation"]
        assert findings[0].remediation == report_finding["remediation"]
        assert "sensitive_data_checks" in report["assessment"]["failed_stages"]
    finally:
        _cleanup_target(target_name)


def test_unexpected_error_marks_scan_failed_and_persists_lifecycle_stage(
    monkeypatch, tmp_path
):
    target_name = f"lifecycle-failed-{uuid4().hex}"
    _stub_target_io(monkeypatch, tmp_path)
    monkeypatch.setattr(
        service,
        "_execute_assessment",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("synthetic pipeline crash")
        ),
    )

    try:
        provisioned = service.provision_assessment(
            base_url=BASE_URL,
            target_name=target_name,
        )
        result = service.run_assessment(provisioned, classify=False)

        assert result["status"] == "failed"

        with get_session() as session:
            scan = session.get(Scan, provisioned.scan_id)
            assert scan is not None
            assert scan.status == ScanStatus.FAILED
            assert scan.completed_at is not None

            stages = {
                row.stage_name: row
                for row in session.exec(
                    select(AssessmentStage).where(
                        AssessmentStage.scan_id == provisioned.scan_id
                    )
                ).all()
            }
            assert stages["lifecycle"].status == "failed"
            assert "unexpectedly" in (stages["lifecycle"].reason or "")

            # A failed scan is terminal, so the report endpoint is allowed to
            # answer, but it must not invent findings.
            report = api.get_scan_report(provisioned.scan_id, session)
            assert report is not None
            assert report["status"] == "failed"
            assert report["findings_count"] == 0
            assert report["summary"]["headline"] == "Assessment failed"
    finally:
        _cleanup_target(target_name)


def test_report_is_refused_while_scan_is_pending_or_running():
    target_name = f"lifecycle-running-{uuid4().hex}"
    target_id = None
    scan_id = None
    try:
        with get_session() as session:
            target = Target(
                name=target_name,
                base_url="https://running.example",
                openapi_spec_path="",
            )
            session.add(target)
            session.commit()
            session.refresh(target)
            target_id = target.id

            scan = Scan(target_id=target.id, status=ScanStatus.PENDING)
            session.add(scan)
            session.commit()
            session.refresh(scan)
            scan_id = scan.id

        with get_session() as session:
            with pytest.raises(api.HTTPException) as pending_error:
                api.get_scan_report(scan_id, session)
            assert pending_error.value.status_code == 409

            scan = session.get(Scan, scan_id)
            scan.status = ScanStatus.RUNNING
            session.add(scan)
            session.commit()

        with get_session() as session:
            with pytest.raises(api.HTTPException) as running_error:
                api.get_scan_report(scan_id, session)
            assert running_error.value.status_code == 409

            scan = session.get(Scan, scan_id)
            scan.status = ScanStatus.COMPLETED
            session.add(scan)
            session.commit()

            report = api.get_scan_report(scan_id, session)
            assert report is not None
            assert report["findings_count"] == 0
    finally:
        if scan_id is not None:
            with get_session() as session:
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
