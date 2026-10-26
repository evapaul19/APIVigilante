"""Assessment API and OpenAPI-discovery error handling tests."""

import pytest
from fastapi.testclient import TestClient

from api_security_system import api
from api_security_system.db import Scan, Target
from api_security_system.recon.schemas import ReconCoverage
from api_security_system.recon.service import ReconResult
from api_security_system.targets import service, spec_fetch
from api_security_system.targets.security import ResolvedTarget, TargetValidationError


@pytest.mark.parametrize(
    ("exception", "expected_status"),
    [
        (TargetValidationError("Target URL is invalid."), 400),
        (spec_fetch.SpecUnavailableError("No usable OpenAPI specification."), 422),
        (
            service.AssessmentSchemaError("Could not inspect the database schema."),
            503,
        ),
    ],
    ids=["invalid-target", "inaccessible-or-missing-spec", "database-unavailable"],
)
def test_assessment_route_maps_target_and_discovery_errors(
    monkeypatch, exception, expected_status
):
    def fail_provision(**_kwargs):
        raise exception

    monkeypatch.setattr(api, "provision_assessment", fail_provision)

    response = TestClient(api.app).post(
        "/assessments",
        json={"base_url": "https://api.example.com", "classify": False},
    )

    assert response.status_code == expected_status
    assert exception.args[0] in response.json()["detail"]


def test_cors_preflight_allows_vite_assessment_submission():
    response = TestClient(api.app).options(
        "/assessments",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "content-type" in response.headers["access-control-allow-headers"].lower()


def test_cors_preflight_rejects_unconfigured_origins():
    response = TestClient(api.app).options(
        "/assessments",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_assessment_endpoint_returns_scan_identifier_before_background_run(monkeypatch):
    class Provisioned:
        scan_id = 22
        target_id = 11
        base_url = "https://api.example.com"
        origin = "https://api.example.com"
        display_name = "api.example.com"
        spec_url = None

    scheduled = {}

    def fake_run(provisioned, **_kwargs):
        scheduled["scan_id"] = provisioned.scan_id
        return {"scan_id": provisioned.scan_id, "status": "failed"}

    monkeypatch.setattr(api, "provision_assessment", lambda **_kwargs: Provisioned())
    monkeypatch.setattr(api, "run_assessment", fake_run)

    response = TestClient(api.app).post(
        "/assessments",
        json={"base_url": "https://api.example.com", "classify": False},
    )

    assert response.status_code == 201
    assert response.json()["scan_id"] == 22
    # The response is returned before the slow pipeline finishes; the UI polls
    # the scan and then retrieves the report for the same identifier.
    assert response.json()["status"] == "pending"
    assert scheduled["scan_id"] == 22


@pytest.mark.parametrize(
    ("failure", "expected_status", "expected_detail"),
    [
        (None, 200, "connected"),
        (TimeoutError("database timeout"), 503, "Database unavailable"),
    ],
    ids=["database-healthy", "database-unavailable"],
)
def test_health_reports_database_state(monkeypatch, failure, expected_status, expected_detail):
    class FakeSession:
        def exec(self, _statement):
            if failure:
                raise failure
            return 1

    def fake_database_session():
        yield FakeSession()

    api.app.dependency_overrides[api.database_session] = fake_database_session
    try:
        response = TestClient(api.app).get("/health")
    finally:
        api.app.dependency_overrides.pop(api.database_session, None)

    assert response.status_code == expected_status
    assert expected_detail in response.text


def test_discovery_falls_back_to_next_common_spec_path(monkeypatch):
    requested_urls = []

    def fake_fetch(url, _addresses):
        requested_urls.append(url)
        if url.endswith("/openapi.json"):
            raise spec_fetch.SpecUnavailableError("not found")
        return b'{"openapi":"3.0.3","info":{"title":"api","version":"1"},"paths":{}}'

    monkeypatch.setattr(spec_fetch, "_fetch", fake_fetch)

    result = spec_fetch.acquire_spec(
        "https://api.example.com",
        resolved_addresses=("93.184.216.34",),
    )

    assert requested_urls == [
        "https://api.example.com/openapi.json",
        "https://api.example.com/openapi.yaml",
    ]
    assert result.source_url == "https://api.example.com/openapi.yaml"


def test_failed_spec_discovery_persists_a_failed_assessment(monkeypatch):
    base_url = "https://api.example.com"
    resolved = ResolvedTarget(
        base_url=base_url,
        scheme="https",
        hostname="api.example.com",
        port=443,
        addresses=("93.184.216.34",),
    )
    class FakeSession:
        saved_target = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def add(self, record):
            if isinstance(record, Target):
                record.id = 11
                type(self).saved_target = record
            elif isinstance(record, Scan):
                record.id = 22

        def commit(self):
            return None

        def refresh(self, _record):
            return None

        def get(self, model, _record_id):
            return type(self).saved_target if model is Target else None

    saved_stages = []
    scan_updates = []

    monkeypatch.setattr(service, "resolve_target", lambda _url: resolved)
    monkeypatch.setattr(service, "_require_assessment_stage_table", lambda: None)

    def unavailable(*_args, **_kwargs):
        raise spec_fetch.SpecUnavailableError("No usable OpenAPI specification.")

    monkeypatch.setattr(service, "acquire_spec", unavailable)
    monkeypatch.setattr(service, "get_session", FakeSession)
    monkeypatch.setattr(
        service,
        "_persist_stage_outcomes",
        lambda _scan_id, stages: saved_stages.append(stages),
    )
    monkeypatch.setattr(
        service,
        "_update_scan",
        lambda scan_id, status, completed=False: scan_updates.append(
            (scan_id, status.value, completed)
        ),
    )

    result = service.create_assessment(base_url=base_url, classify=False)

    assert result["scan_id"] == 22
    assert result["status"] == "failed"
    assert result["stages"]["spec_discovery"]["status"] == "failed"
    assert saved_stages[0]["report"]["status"] == "available"
    assert scan_updates == [(22, "failed", True)]


def test_no_spec_discovers_only_bounded_same_origin_html_links(monkeypatch):
    requested = []

    def fake_fetch(url, _addresses):
        requested.append(url)
        if url.endswith("/"):
            return b'<html><a href="/v1">API</a><a href="https://other.example/secret">outside</a></html>'
        if url.endswith("/v1"):
            return b'<html><a href="/v1/users">Users</a></html>'
        if url.endswith("/v1/users"):
            return b"<html>Users</html>"
        raise spec_fetch.SpecUnavailableError("not found")

    monkeypatch.setattr(spec_fetch, "_fetch", fake_fetch)
    result = spec_fetch.acquire_spec(
        "https://public.example",
        resolved_addresses=("93.184.216.34",),
    )

    assert result.discovery_mode is True
    assert set(result.document["paths"]) == {"/", "/v1", "/v1/users"}
    assert all("other.example" not in url for url in requested)
    assert "same-origin HTML links" in result.limitations[0]


def test_discovery_with_no_linked_routes_is_persisted_as_failed(monkeypatch):
    base_url = "https://public.example"

    class FakeSession:
        saved_target = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def add(self, record):
            if isinstance(record, Target):
                record.id = 11
                type(self).saved_target = record
            elif isinstance(record, Scan):
                record.id = 22

        def commit(self):
            return None

        def refresh(self, _record):
            return None

        def get(self, model, _record_id):
            return type(self).saved_target if model is Target else None

    persisted_stages = []
    updated_scans = []
    spec = spec_fetch.FetchedSpec(
        document={"openapi": "3.0.3", "info": {"title": "discovery", "version": "1"}, "paths": {}},
        source_url=base_url,
        raw=b'{"openapi":"3.0.3","paths":{}}',
        extension=".json",
        discovery_mode=True,
        limitations=["No linked routes were found."],
    )
    recon = ReconResult(
        scan_id=22,
        endpoints_found=0,
        endpoints_inserted=0,
        endpoints_skipped_duplicate=0,
        classifications_succeeded=0,
        classifications_failed=0,
        coverage=ReconCoverage(),
    )

    monkeypatch.setattr(
        service,
        "resolve_target",
        lambda _url: ResolvedTarget(
            base_url=base_url,
            scheme="https",
            hostname="public.example",
            port=443,
            addresses=("93.184.216.34",),
        ),
    )
    monkeypatch.setattr(service, "_require_assessment_stage_table", lambda: None)
    monkeypatch.setattr(service, "get_session", FakeSession)
    monkeypatch.setattr(service, "acquire_spec", lambda *_args, **_kwargs: spec)
    monkeypatch.setattr(service, "save_spec", lambda _spec: "targets/discovery.json")
    monkeypatch.setattr(service, "run_recon", lambda *_args, **_kwargs: recon)
    monkeypatch.setattr(
        service,
        "_resource_graph_summary",
        lambda _scan_id: {
            "status": "not_built",
            "reason": "No endpoints were discovered.",
            "resources": [],
            "endpoint_count": 0,
            "edge_count": 0,
            "identifies_count": 0,
            "may_relate_count": 0,
        },
    )
    monkeypatch.setattr(service, "_identity_contract_supported", lambda *_args: False)
    monkeypatch.setattr(
        service,
        "_authorization_summary",
        lambda *_args, **_kwargs: {"status": "not_supported", "reason": "No supported identity contract."},
    )
    monkeypatch.setattr(
        service,
        "_sensitive_summary",
        lambda *_args, **_kwargs: {"status": "not_run", "reason": "No endpoints."},
    )
    monkeypatch.setattr(service, "_scan_findings", lambda _scan_id: [])
    monkeypatch.setattr(
        service,
        "_persist_stage_outcomes",
        lambda _scan_id, stages: persisted_stages.append(stages),
    )
    monkeypatch.setattr(
        service,
        "_update_scan",
        lambda scan_id, status, completed=False: updated_scans.append(
            (scan_id, status.value, completed)
        ),
    )

    result = service.create_assessment(base_url=base_url, classify=False)

    assert result["status"] == "failed"
    assert result["scan_id"] == 22
    assert result["recon"]["status"] == "no_endpoints"
    assert persisted_stages[0]["spec_discovery"]["status"] == "discovery_only"
    assert persisted_stages[0]["recon"]["status"] == "no_endpoints"
    assert persisted_stages[0]["report"]["status"] == "available"
    assert updated_scans == [(22, "failed", True)]
