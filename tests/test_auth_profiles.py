"""Unit tests for caller-supplied auth profiles and profile-based BOLA.

No database and no network: static header construction, login extraction,
and the read-only profile runner are exercised with fake executors. The
database-backed identity persistence is covered by the service tests.
"""

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from api_security_system.auth import (
    AuthIdentity,
    AuthProfile,
    AuthenticationError,
    ProfileIdentity,
    headers_for_identity,
)
from api_security_system.authz_bola import service
from api_security_system.authz_bola.schemas import BolaCandidate


class _Response:
    def __init__(self, status, body):
        self.response_status = status
        self.response_body = body
        self.response_headers = {}
        self.request_headers = {}
        self.request_body = None
        self.latency_ms = 1


class _LoginExecutor:
    def __init__(self, status=200, body=None):
        self.status = status
        self.body = body if body is not None else {
            "data": {"access_token": "token-value"}
        }
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        return _Response(self.status, self.body)


def test_static_bearer_profile_builds_authorization_header():
    profile = AuthProfile(
        type="static",
        scheme="bearer",
        identities=[AuthIdentity(label="alice", token="abc", subject="alice")],
    )

    assert headers_for_identity(profile, profile.identities[0]) == {
        "Authorization": "Bearer abc"
    }


def test_static_custom_headers_are_returned_as_plain_request_values():
    profile = AuthProfile(
        type="static",
        scheme="custom",
        identities=[
            AuthIdentity(
                label="alice",
                headers={"X-Company-Key": "secret-key", "X-Tenant": "tenant-a"},
            )
        ],
    )

    assert headers_for_identity(profile, profile.identities[0]) == {
        "X-Company-Key": "secret-key",
        "X-Tenant": "tenant-a",
    }
    assert "secret-key" not in repr(profile.identities[0])


def test_static_bearer_profile_merges_extra_headers():
    profile = AuthProfile(
        type="static",
        scheme="bearer",
        extra_headers={"X-Tenant": "tenant-a", "X-API-Version": "2026-01"},
        identities=[AuthIdentity(label="alice", token="abc")],
    )

    assert headers_for_identity(profile, profile.identities[0]) == {
        "X-Tenant": "tenant-a",
        "X-API-Version": "2026-01",
        "Authorization": "Bearer abc",
    }


def test_extra_headers_are_case_insensitive_and_auth_wins():
    profile = AuthProfile(
        type="static",
        scheme="bearer",
        extra_headers={"authorization": "stale", "x-tenant": "tenant-a"},
        identities=[AuthIdentity(label="alice", token="abc")],
    )

    assert headers_for_identity(profile, profile.identities[0]) == {
        "Authorization": "Bearer abc",
        "x-tenant": "tenant-a",
    }


def test_static_api_key_profile_uses_configurable_header():
    profile = AuthProfile(
        type="static",
        scheme="api_key",
        header_name="X-Company-Key",
        identities=[AuthIdentity(label="alice", api_key="key-123")],
    )

    assert headers_for_identity(profile, profile.identities[0]) == {
        "X-Company-Key": "key-123"
    }


def test_static_basic_profile_encodes_credentials():
    profile = AuthProfile(
        type="static",
        scheme="basic",
        identities=[
            AuthIdentity(label="alice", username="alice", password="hunter2")
        ],
    )

    headers = headers_for_identity(profile, profile.identities[0])
    assert headers["Authorization"].startswith("Basic ")
    assert headers["Authorization"] != "Basic hunter2"


def test_login_profile_extracts_nested_token():
    executor = _LoginExecutor(
        body={"data": {"access_token": "nested-token"}}
    )
    profile = AuthProfile(
        type="login",
        scheme="bearer",
        login_path="/auth/login",
        token_path="data.access_token",
        identities=[
            AuthIdentity(label="alice", username="alice", password="hunter2")
        ],
    )

    headers = headers_for_identity(profile, profile.identities[0], executor)

    assert headers == {"Authorization": "Bearer nested-token"}
    assert executor.requests[0].path == "/auth/login"
    assert executor.requests[0].json_body == {
        "username": "alice",
        "password": "hunter2",
    }


def test_login_profile_sends_extra_headers_on_login_and_authenticated_requests():
    executor = _LoginExecutor(body={"access_token": "token-value"})
    profile = AuthProfile(
        type="login",
        scheme="bearer",
        login_path="/auth/login",
        token_path="access_token",
        extra_headers={"X-Tenant": "tenant-a", "X-API-Key": "login-key"},
        identities=[
            AuthIdentity(label="alice", username="alice", password="hunter2")
        ],
    )

    headers = headers_for_identity(profile, profile.identities[0], executor)

    assert executor.requests[0].headers == {
        "X-Tenant": "tenant-a",
        "X-API-Key": "login-key",
    }
    assert headers == {
        "X-Tenant": "tenant-a",
        "X-API-Key": "login-key",
        "Authorization": "Bearer token-value",
    }


def test_login_profile_rejects_invalid_credentials():
    executor = _LoginExecutor(status=401, body={"detail": "invalid"})
    profile = AuthProfile(
        type="login",
        scheme="bearer",
        login_path="/auth/login",
        identities=[
            AuthIdentity(label="alice", username="alice", password="wrong")
        ],
    )

    with pytest.raises(AuthenticationError, match="HTTP 401"):
        headers_for_identity(profile, profile.identities[0], executor)


def test_login_profile_rejects_basic_token_extraction():
    with pytest.raises(ValidationError):
        AuthProfile(
            type="login",
            scheme="basic",
            login_path="/auth/login",
            identities=[
                AuthIdentity(label="alice", username="alice", password="hunter2")
            ],
        )


def test_profile_rejects_unsafe_extra_headers_and_redacts_values():
    with pytest.raises(ValidationError):
        AuthProfile(
            type="static",
            scheme="bearer",
            extra_headers={"X-Forwarded-For": "127.0.0.1"},
            identities=[AuthIdentity(label="alice", token="abc")],
        )

    profile = AuthProfile(
        type="static",
        scheme="bearer",
        extra_headers={"X-Company-Key": "extra-secret"},
        identities=[AuthIdentity(label="alice", token="abc")],
    )
    assert "extra-secret" not in repr(profile)


def test_login_profile_missing_token_fails_closed():
    executor = _LoginExecutor(body={"data": {}})
    profile = AuthProfile(
        type="login",
        login_path="/auth/login",
        token_path="data.access_token",
        identities=[
            AuthIdentity(label="alice", username="alice", password="hunter2")
        ],
    )

    with pytest.raises(AuthenticationError):
        headers_for_identity(profile, profile.identities[0], executor)


def test_static_profile_without_secret_fails_closed():
    profile = AuthProfile(
        type="static",
        scheme="bearer",
        identities=[AuthIdentity(label="alice")],
    )

    with pytest.raises(ValueError):
        headers_for_identity(profile, profile.identities[0])


def test_profile_rejects_path_delimiters_in_identifier_values():
    with pytest.raises(ValidationError):
        AuthIdentity(
            label="alice",
            subject="alice",
            path_values={"account_id": "../admin"},
        )


def test_profile_rejects_encoded_path_delimiters_and_traversal():
    for value in ("%2e%2e", "..%2fadmin", "id%3Fnext=1", "%5cadmin"):
        with pytest.raises(ValidationError):
            AuthIdentity(label="alice", path_values={"account_id": value})


def test_profile_rejects_encoded_traversal_in_login_path():
    with pytest.raises(ValidationError):
        AuthProfile(
            type="login",
            scheme="bearer",
            login_path="/%2e%2e/admin",
            identities=[AuthIdentity(label="alice", username="a", password="b")],
        )


def test_profile_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        AuthProfile(
            type="static",
            scheme="bearer",
            identities=[AuthIdentity(label="alice", token="abc")],
            logn_path="/typo",
        )
    with pytest.raises(ValidationError):
        AuthIdentity(label="alice", token="abc", extra_field="ignored")


def test_profile_rejects_proxy_and_hop_by_hop_headers():
    for name in ("Host", "X-Forwarded-For", "Connection", "Content-Length"):
        with pytest.raises(ValidationError):
            AuthIdentity(label="alice", headers={name: "value"})


def test_profile_rejects_duplicate_labels():
    with pytest.raises(ValidationError):
        AuthProfile(
            type="static",
            scheme="bearer",
            identities=[
                AuthIdentity(label="same", token="a"),
                AuthIdentity(label="same", token="b"),
            ],
        )


def test_profile_repr_redacts_secret_values():
    profile = AuthProfile(
        type="static",
        scheme="bearer",
        identities=[
            AuthIdentity(
                label="alice",
                token="super-secret",
                headers={"X-Company-Key": "also-secret"},
            )
        ],
    )

    rendered = repr(profile) + repr(profile.identities[0])
    assert "super-secret" not in rendered
    assert "also-secret" not in rendered


class _ReadExecutor:
    def __init__(self):
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        if request.path == "/accounts/1":
            return _Response(
                200,
                {"id": 1, "username": "alice", "email": "alice@example.invalid"},
            )
        if request.path == "/accounts/2":
            return _Response(
                200,
                {"id": 2, "username": "bob", "email": "bob@example.invalid"},
            )
        raise AssertionError(request.path)


def _candidate():
    return BolaCandidate(
        endpoint_id=5,
        method="GET",
        path="/accounts/{account_id}",
        operation_id="getAccount",
        id_param_name="account_id",
    )


def test_profile_read_bola_uses_configured_identifiers(monkeypatch):
    created = []
    monkeypatch.setattr(service, "_persist_execution", lambda *args, **kwargs: 1)
    monkeypatch.setattr(
        service,
        "_create_finding",
        lambda *args, **kwargs: created.append(args) or 999,
    )
    attacker = ProfileIdentity(
        identity_id=1,
        label="attacker",
        subject="alice",
        username="alice",
        headers={"Authorization": "Bearer attacker"},
        path_values={"account_id": "1"},
    )
    victim = ProfileIdentity(
        identity_id=2,
        label="victim",
        subject="bob",
        username="bob",
        headers={"Authorization": "Bearer victim"},
        path_values={"account_id": "2"},
    )
    executor = _ReadExecutor()

    results, stopped, reason = service._run_profile_read_checks(
        1, executor, attacker, victim, [_candidate()], None
    )

    assert stopped is False
    assert reason is None
    assert results[0].outcome.value == "confirmed"
    assert results[0].finding_id == 999
    assert [request.path for request in executor.requests] == [
        "/accounts/1",
        "/accounts/2",
    ]
    assert all(request.method == "GET" for request in executor.requests)
    assert all(
        request.headers["Authorization"] == "Bearer attacker"
        for request in executor.requests
    )
    assert created


def test_profile_read_bola_skips_when_identifier_is_missing(monkeypatch):
    monkeypatch.setattr(
        service,
        "_persist_execution",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("no request should be persisted")
        ),
    )
    attacker = ProfileIdentity(
        identity_id=1,
        label="attacker",
        subject="alice",
        username="alice",
        headers={"Authorization": "Bearer attacker"},
        path_values={},
    )
    victim = ProfileIdentity(
        identity_id=2,
        label="victim",
        subject="bob",
        username="bob",
        headers={"Authorization": "Bearer victim"},
        path_values={"account_id": "2"},
    )

    results, stopped, reason = service._run_profile_read_checks(
        1, _ReadExecutor(), attacker, victim, [_candidate()], None
    )

    assert stopped is False
    assert reason is None
    assert results[0].outcome.value == "not_applicable"
    assert "no configured value" in results[0].rationale


def test_profile_none_is_anonymous():
    profile = AuthProfile(type="none")
    assert profile.identities == []

class _MultiReadExecutor:
    def __init__(self):
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        if request.path == "/tenants/t1/accounts/1":
            return _Response(200, {"username": "alice", "id": "1"})
        if request.path == "/tenants/t2/accounts/2":
            return _Response(200, {"username": "bob", "id": "2"})
        raise AssertionError(request.path)


def _multi_candidate():
    return BolaCandidate(
        endpoint_id=6,
        method="GET",
        path="/tenants/{tenant_id}/accounts/{account_id}",
        operation_id="getTenantAccount",
        id_param_name="tenant_id",
        path_params=["tenant_id", "account_id"],
    )


def _multi_identities(victim_values=None):
    attacker = ProfileIdentity(
        identity_id=1,
        label="attacker",
        subject="alice",
        username="alice",
        headers={"Authorization": "Bearer attacker"},
        path_values={"tenant_id": "t1", "account_id": "1"},
    )
    victim = ProfileIdentity(
        identity_id=2,
        label="victim",
        subject="bob",
        username="bob",
        headers={"Authorization": "Bearer victim"},
        path_values=victim_values
        if victim_values is not None
        else {"tenant_id": "t2", "account_id": "2"},
    )
    return attacker, victim


def test_profile_read_bola_substitutes_multiple_path_parameters(monkeypatch):
    created = []
    monkeypatch.setattr(service, "_persist_execution", lambda *args, **kwargs: 1)
    monkeypatch.setattr(
        service,
        "_create_finding",
        lambda *args, **kwargs: created.append(args) or 999,
    )
    attacker, victim = _multi_identities()
    executor = _MultiReadExecutor()

    results, stopped, reason = service._run_profile_read_checks(
        1,
        executor,
        attacker,
        victim,
        [_multi_candidate()],
        None,
    )

    assert stopped is False
    assert reason is None
    assert results[0].outcome.value == "confirmed"
    assert [request.path for request in executor.requests] == [
        "/tenants/t1/accounts/1",
        "/tenants/t2/accounts/2",
    ]
    assert created


def test_profile_read_bola_skips_when_any_path_identifier_is_missing(monkeypatch):
    monkeypatch.setattr(
        service,
        "_persist_execution",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("no request should be persisted")
        ),
    )
    attacker, victim = _multi_identities({"account_id": "2"})
    executor = _MultiReadExecutor()

    results, stopped, reason = service._run_profile_read_checks(
        1,
        executor,
        attacker,
        victim,
        [_multi_candidate()],
        None,
    )

    assert stopped is False
    assert reason is None
    assert executor.requests == []
    assert results[0].outcome.value == "not_applicable"
    assert "tenant_id" in results[0].rationale
    assert "no request was sent" in results[0].rationale
