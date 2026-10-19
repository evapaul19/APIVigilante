"""Tests for Recon orchestration (service.py).

Uses a real PostgreSQL database (skipped entirely if DATABASE_URL is
not set - same pattern as test_db_smoke.py) and a mocked LLMClient so
no real LLM API calls happen in this file.
"""

import os
from unittest.mock import MagicMock

import pytest
from sqlmodel import select

from api_security_system.db import Endpoint, Scan, Target, get_session
from api_security_system.llm import LLMResponse, Provider
from api_security_system.recon.service import ScanNotFoundError, run_recon

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="DATABASE_URL not set")

REAL_SPEC_PATH = "targets/vampi-openapi.yml"


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("api_security_system.recon.classifier.time.sleep", lambda s: None)


def _mock_llm_client(risk_level: str = "medium"):
    client = MagicMock()
    client.generate.return_value = LLMResponse(
        provider=Provider.GOOGLE,
        model="gemini-3.5-flash-lite",
        text=f'{{"risk_level": "{risk_level}", "rationale": "test"}}',
    )
    return client


@pytest.fixture
def scan_id():
    """Create a throwaway Target + Scan, yield its id, clean up after."""
    with get_session() as session:
        target = Target(name="recon-test-target", base_url="http://localhost:9999", openapi_spec_path=REAL_SPEC_PATH)
        session.add(target)
        session.commit()
        session.refresh(target)

        scan = Scan(target_id=target.id)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id_value = scan.id
        target_id_value = target.id

    yield scan_id_value

    with get_session() as session:
        for ep in session.exec(select(Endpoint).where(Endpoint.scan_id == scan_id_value)).all():
            session.delete(ep)
        db_scan = session.get(Scan, scan_id_value)
        if db_scan:
            session.delete(db_scan)
        db_target = session.get(Target, target_id_value)
        if db_target:
            session.delete(db_target)
        session.commit()


def test_run_recon_nonexistent_scan_raises():
    with pytest.raises(ScanNotFoundError):
        run_recon(scan_id=999999999, llm_client=_mock_llm_client())


def test_run_recon_persists_endpoints_and_classifies(scan_id):
    result = run_recon(scan_id=scan_id, llm_client=_mock_llm_client("high"))

    assert result.endpoints_found > 0
    assert result.endpoints_inserted == result.endpoints_found
    assert result.endpoints_skipped_duplicate == 0
    assert result.classifications_succeeded == result.endpoints_inserted
    assert result.classifications_failed == 0

    with get_session() as session:
        stored = session.exec(select(Endpoint).where(Endpoint.scan_id == scan_id)).all()
        assert len(stored) == result.endpoints_found
        assert all(ep.risk_classification == "high" for ep in stored)


def test_run_recon_rerun_skips_duplicates(scan_id):
    first = run_recon(scan_id=scan_id, llm_client=_mock_llm_client("high"))
    second = run_recon(scan_id=scan_id, llm_client=_mock_llm_client("low"))

    assert second.endpoints_inserted == 0
    assert second.endpoints_skipped_duplicate == first.endpoints_found

    with get_session() as session:
        stored = session.exec(select(Endpoint).where(Endpoint.scan_id == scan_id)).all()
        # Rerun does not refresh existing rows - stays "high" from the
        # first run even though the second run used a different mock.
        assert all(ep.risk_classification == "high" for ep in stored)


def test_run_recon_classification_failure_preserves_endpoint(scan_id):
    client = MagicMock()
    client.generate.return_value = LLMResponse(provider=Provider.GOOGLE, model="m", text="not json")

    result = run_recon(scan_id=scan_id, llm_client=client)

    assert result.endpoints_inserted == result.endpoints_found
    assert result.classifications_failed == result.endpoints_found
    assert result.classifications_succeeded == 0
    assert len(result.classification_failures) == result.endpoints_found

    with get_session() as session:
        stored = session.exec(select(Endpoint).where(Endpoint.scan_id == scan_id)).all()
        assert len(stored) == result.endpoints_found
        assert all(ep.risk_classification is None for ep in stored)
        assert all(ep.path and ep.method for ep in stored)