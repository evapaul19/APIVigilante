"""Regression tests for runtime-selected targets and custom spec paths."""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from api_security_system import api
from api_security_system import targets
from api_security_system.targets import service
from api_security_system.targets import spec_fetch


PUBLIC_V4 = "93.184.216.34"


def test_spec_url_accepts_custom_same_origin_paths():
    assert (
        targets.validate_spec_url(
            "https://api.example.com/v1",
            "/metadata/openapi.yaml",
        )
        == "https://api.example.com/metadata/openapi.yaml"
    )
    assert (
        targets.validate_spec_url(
            "https://api.example.com/v1",
            "metadata/openapi.yaml",
        )
        == "https://api.example.com/v1/metadata/openapi.yaml"
    )


def test_spec_url_rejects_cross_origin_custom_path():
    with pytest.raises(targets.TargetValidationError):
        targets.validate_spec_url(
            "https://api.example.com",
            "https://other.example.com/metadata/openapi.yaml",
        )


def test_acquire_spec_uses_user_selected_target_and_custom_path(monkeypatch):
    calls = []

    def fake_fetch(url, resolved_addresses):
        calls.append((url, resolved_addresses))
        return b'{"openapi": "3.0.0", "paths": {}}'

    monkeypatch.setattr(spec_fetch, "_fetch", fake_fetch)

    fetched = spec_fetch.acquire_spec(
        "https://different.example/v2",
        "https://different.example/v2/custom/spec.yaml",
        resolved_addresses=(PUBLIC_V4,),
    )

    assert fetched.source_url == "https://different.example/v2/custom/spec.yaml"
    assert calls == [
        (
            "https://different.example/v2/custom/spec.yaml",
            (PUBLIC_V4,),
        )
    ]


def test_acquire_spec_does_not_silently_fall_back_to_discovery(monkeypatch):
    calls = []

    def fake_fetch(url, resolved_addresses):
        calls.append(url)
        raise spec_fetch.SpecUnavailableError(f"Could not fetch {url}: not found")

    monkeypatch.setattr(spec_fetch, "_fetch", fake_fetch)

    with pytest.raises(spec_fetch.SpecUnavailableError) as exc_info:
        spec_fetch.acquire_spec(
            "https://different.example",
            "https://different.example/custom/only.yaml",
            resolved_addresses=(PUBLIC_V4,),
        )

    assert calls == ["https://different.example/custom/only.yaml"]
    assert "custom/only.yaml" in str(exc_info.value)


def test_assessment_endpoint_forwards_user_target_and_spec(monkeypatch):
    captured = {}

    def fake_create_assessment(**kwargs):
        captured.update(kwargs)
        return {"scan_id": 123}

    monkeypatch.setattr(api, "create_assessment", fake_create_assessment)

    response = api.start_assessment(
        api.AssessmentCreate(
            base_url="https://different.example/v2",
            openapi_spec_url="https://different.example/v2/custom/openapi.yaml",
            target_name="different-api",
            allow_identity_registration=False,
            classify=False,
        )
    )

    assert response == {"scan_id": 123}
    assert captured["base_url"] == "https://different.example/v2"
    assert (
        captured["openapi_spec_url"]
        == "https://different.example/v2/custom/openapi.yaml"
    )
    assert captured["target_name"] == "different-api"


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeSession:
    def __init__(self, rows):
        self._rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def exec(self, _statement):
        return _FakeResult(self._rows)


def test_identity_contract_detection_requires_both_registration_and_login(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "get_session",
        lambda: _FakeSession(
            [
                ("POST", "/users/v1/register"),
                ("POST", "/users/v1/login"),
                ("GET", "/me"),
            ]
        ),
    )

    assert service._identity_contract_supported(
        1, "https://api.example.com/v2"
    )


def test_identity_contract_detection_honors_target_base_path(monkeypatch):
    monkeypatch.setattr(
        service,
        "get_session",
        lambda: _FakeSession(
            [
                ("POST", "/api/users/v1/register"),
                ("POST", "/api/users/v1/login"),
            ]
        ),
    )

    assert service._identity_contract_supported(
        1, "https://api.example.com/api"
    )


def test_identity_contract_detection_fails_closed_for_other_auth(monkeypatch):
    monkeypatch.setattr(
        service,
        "get_session",
        lambda: _FakeSession(
            [
                ("POST", "/auth/register"),
                ("POST", "/auth/login"),
            ]
        ),
    )

    assert not service._identity_contract_supported(
        1, "https://api.example.com"
    )


def test_authorization_summary_does_not_guess_unsupported_auth(monkeypatch):
    monkeypatch.setattr(service, "is_authorized_origin", lambda _url: True)
    monkeypatch.setattr(
        service,
        "run_bola_check",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("authorization checks must not run")
        ),
    )

    summary = service._authorization_summary(
        1,
        "https://api.example.com",
        True,
        10,
        identity_contract_supported=False,
    )

    assert summary["status"] == "unsupported"
    assert summary["supported_for_target"] is False
    assert summary["identity_contract_supported"] is False
    assert "different authentication mechanism" in summary["reason"]


def test_sensitive_summary_uses_unauthenticated_mode_without_contract(
    monkeypatch,
):
    captured = {}
    monkeypatch.setattr(service, "is_authorized_origin", lambda _url: True)

    def fake_run_sensitive_data_check(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            status="performed",
            requests_used=2,
            request_budget=10,
            reason=None,
            confirmed_findings=0,
            candidate_findings=0,
            results=[],
        )

    monkeypatch.setattr(
        service, "run_sensitive_data_check", fake_run_sensitive_data_check
    )

    summary = service._sensitive_summary(
        1,
        "https://api.example.com",
        True,
        10,
        identity_contract_supported=False,
    )

    assert summary["status"] == "performed"
    assert summary["identity_contract_supported"] is False
    assert captured["provision_identity_enabled"] is False


def test_authorization_summary_uses_auth_profile_without_vampi_contract(
    monkeypatch,
):
    from api_security_system.auth import AuthIdentity, AuthProfile
    from api_security_system.authz_bola.schemas import (
        AttemptOutcome,
        BolaCheckResult,
        EndpointTestResult,
    )

    monkeypatch.setattr(service, "is_authorized_origin", lambda _url: True)
    captured = {}

    def fake_run_bola_check(**kwargs):
        captured.update(kwargs)
        return BolaCheckResult(
            scan_id=1,
            target_base_url="https://api.example.com",
            requests_used=2,
            request_budget=10,
            endpoint_results=[
                EndpointTestResult(
                    operation_id="get_account",
                    path="/accounts/{id}",
                    outcome=AttemptOutcome.CONFIRMED,
                    finding_id=9,
                )
            ],
            bfla_status="not_supported",
            bfla_reason="profile BFLA is not supported",
        )

    monkeypatch.setattr(service, "run_bola_check", fake_run_bola_check)
    profile = AuthProfile(
        type="static",
        scheme="bearer",
        identities=[
            AuthIdentity(label="attacker", token="a", path_values={"id": "1"}),
            AuthIdentity(label="victim", token="b", path_values={"id": "2"}),
        ],
    )

    summary = service._authorization_summary(
        1,
        "https://api.example.com",
        True,
        10,
        identity_contract_supported=False,
        auth_profile=profile,
        authorized_for_active_testing=True,
    )

    assert summary["status"] == "performed"
    assert summary["identity_contract_supported"] is False
    assert summary["auth_profile_supported"] is True
    assert summary["auth_scheme"] == "bearer"
    assert captured["auth_profile"] is profile
    assert captured["authorized_for_active_testing"] is True


def test_validation_errors_do_not_echo_auth_profile_secrets():
    client = TestClient(api.app)
    response = client.post(
        "/assessments",
        json={
            "base_url": "https://api.example.com",
            "auth_profile": {
                "type": "static",
                "scheme": "bearer",
                "identities": [
                    {"label": "duplicate", "token": "SUPERSECRET-ONE"},
                    {"label": "duplicate", "token": "SUPERSECRET-TWO"},
                ],
            },
        },
    )

    assert response.status_code == 422
    assert "SUPERSECRET" not in response.text
    assert "input" not in response.text


def test_assessment_endpoint_forwards_auth_profile(monkeypatch):
    from api_security_system.auth import AuthIdentity, AuthProfile

    captured = {}

    def fake_create_assessment(**kwargs):
        captured.update(kwargs)
        return {"scan_id": 123}

    monkeypatch.setattr(api, "create_assessment", fake_create_assessment)
    profile = AuthProfile(
        type="static",
        scheme="bearer",
        identities=[
            AuthIdentity(label="attacker", token="a", path_values={"id": "1"}),
            AuthIdentity(label="victim", token="b", path_values={"id": "2"}),
        ],
    )

    response = api.start_assessment(
        api.AssessmentCreate(
            base_url="https://api.example.com",
            authorized_for_active_testing=True,
            auth_profile=profile,
        )
    )

    assert response == {"scan_id": 123}
    assert captured["auth_profile"] is profile
    assert captured["authorized_for_active_testing"] is True


def test_sensitive_summary_forwards_auth_profile(monkeypatch):
    from api_security_system.auth import AuthIdentity, AuthProfile

    monkeypatch.setattr(service, "is_authorized_origin", lambda _url: True)
    captured = {}

    def fake_run_sensitive_data_check(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            status="performed",
            requests_used=1,
            request_budget=10,
            reason=None,
            confirmed_findings=0,
            candidate_findings=0,
            results=[],
        )

    monkeypatch.setattr(
        service, "run_sensitive_data_check", fake_run_sensitive_data_check
    )
    profile = AuthProfile(
        type="static",
        scheme="api_key",
        header_name="X-API-Key",
        identities=[AuthIdentity(label="probe", api_key="secret")],
    )

    summary = service._sensitive_summary(
        1,
        "https://api.example.com",
        True,
        10,
        identity_contract_supported=False,
        auth_profile=profile,
        authorized_for_active_testing=True,
    )

    assert summary["status"] == "performed"
    assert summary["auth_profile_supported"] is True
    assert captured["auth_profile"] is profile
    assert captured["provision_identity_enabled"] is False
    assert captured["authorized_for_active_testing"] is True


def test_authorization_summary_requires_two_profile_identities(monkeypatch):
    from api_security_system.auth import AuthIdentity, AuthProfile

    monkeypatch.setattr(service, "is_authorized_origin", lambda _url: True)
    monkeypatch.setattr(
        service,
        "run_bola_check",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("authorization checks must not run")
        ),
    )
    profile = AuthProfile(
        type="static",
        scheme="bearer",
        identities=[AuthIdentity(label="only", token="a", path_values={"id": "1"})],
    )

    summary = service._authorization_summary(
        1,
        "https://api.example.com",
        True,
        10,
        identity_contract_supported=False,
        auth_profile=profile,
    )

    assert summary["status"] == "not_applicable"
    assert summary["supported_for_target"] is True
    assert "at least two identities" in summary["reason"]


def test_authorization_summary_reports_why_no_profile_candidate_ran(monkeypatch):
    from api_security_system.auth import AuthIdentity, AuthProfile
    from api_security_system.authz_bola.schemas import BolaCheckResult

    monkeypatch.setattr(service, "is_authorized_origin", lambda _url: True)
    reason = (
        "No authenticated GET endpoint with at least one path parameter "
        "was found for profile-based BOLA."
    )

    def fake_run_bola_check(**_kwargs):
        return BolaCheckResult(
            scan_id=1,
            target_base_url="https://api.example.com",
            requests_used=0,
            request_budget=10,
            bfla_status="not_applicable",
            bfla_reason=reason,
        )

    monkeypatch.setattr(service, "run_bola_check", fake_run_bola_check)
    profile = AuthProfile(
        type="static",
        scheme="bearer",
        identities=[
            AuthIdentity(label="attacker", token="a", path_values={"id": "1"}),
            AuthIdentity(label="victim", token="b", path_values={"id": "2"}),
        ],
    )

    summary = service._authorization_summary(
        1,
        "https://api.example.com",
        True,
        10,
        identity_contract_supported=False,
        auth_profile=profile,
    )

    assert summary["status"] == "not_applicable"
    assert summary["reason"] == reason
    assert summary["bola_status"] == "not_applicable"
