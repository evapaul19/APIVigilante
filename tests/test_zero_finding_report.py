"""Regression test: a successfully inventoried scan with zero findings
must still expose a retrievable, explicit report."""

import os

import pytest
from sqlmodel import select

from api_security_system import api
from api_security_system.db import (
    Endpoint,
    Finding,
    Scan,
    ScanStatus,
    Target,
    get_session,
)

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set",
)


def test_zero_finding_report_is_retrievable():
    target_id = None
    scan_id = None
    try:
        with get_session() as session:
            target = Target(
                name="zero-finding-report-test",
                base_url="https://zero-finding.example",
                openapi_spec_path="",
            )
            session.add(target)
            session.commit()
            session.refresh(target)
            target_id = target.id

            scan = Scan(target_id=target.id, status=ScanStatus.COMPLETED)
            session.add(scan)
            session.commit()
            session.refresh(scan)
            scan_id = scan.id

            session.add(
                Endpoint(
                    scan_id=scan.id,
                    path="/health",
                    method="GET",
                    operation_id="getHealth",
                    raw_spec_fragment={},
                )
            )
            session.commit()

        with get_session() as session:
            report = api.get_scan_report(scan_id, session)

        assert report["findings_count"] == 0
        assert report["findings"] == []
        assert report["zero_or_incomplete"]["zero_findings"] is True
        assert report["total_endpoints"] == 1
        assert report["assessment"]["checks"]["report"]["status"] == "available"
    finally:
        if scan_id is not None:
            with get_session() as session:
                for finding in session.exec(
                    select(Finding).where(Finding.scan_id == scan_id)
                ).all():
                    session.delete(finding)
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
