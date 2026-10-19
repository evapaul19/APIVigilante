"""Tests for AuthModule. All use httpx.MockTransport via a real
RequestExecutor - no real network calls, no dependency on a live
VAmPI instance."""

import base64
import json
import time

import httpx
import pytest

from api_security_system.auth import (
    AuthContext,
    AuthenticationError,
    AuthModule,
    Credentials,
    TokenExpiredError,
)
from api_security_system.request_executor import RequestExecutor, TransportError

BASE_URL = "http://localhost:5000"


def _fake_jwt(exp_offset_seconds: int = 3600) -> str:
    """Build a JWT-shaped token with a real 'exp' claim, no valid
    signature - sufficient for testing _decode_jwt_exp, which never
    verifies signatures."""
    header = base64.urlsafe_b64encode(json.dumps({"typ": "JWT", "alg": "HS256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + exp_offset_seconds, "sub": "test"}).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesignature"


def _auth_module(handler) -> AuthModule:
    executor = RequestExecutor(base_url=BASE_URL, transport=httpx.MockTransport(handler))
    return AuthModule(executor)


# ---- login() ----


def test_login_success_returns_auth_context_with_bearer_header_and_expiry():
    token = _fake_jwt(exp_offset_seconds=3600)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/users/v1/login"
        return httpx.Response(200, json={"auth_token": token, "message": "Successfully logged in.", "status": "success"})

    auth = _auth_module(handler)
    context = auth.login(Credentials(username="alice", password="pw"), role_label="user_a")

    assert context.auth_header_value == f"Bearer {token}"
    assert context.username == "alice"
    assert context.role_label == "user_a"
    assert context.expires_at is not None


def test_login_invalid_credentials_raises_authentication_error_without_leaking_password():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400, json={"status": "fail", "message": "Password is not correct for the given username."}
        )

    auth = _auth_module(handler)
    with pytest.raises(AuthenticationError) as exc_info:
        auth.login(Credentials(username="alice", password="super-secret-pw"), role_label="user_a")

    assert "super-secret-pw" not in str(exc_info.value)
    assert "not correct" in str(exc_info.value)


def test_login_success_status_but_missing_auth_token_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": "Successfully logged in.", "status": "success"})

    auth = _auth_module(handler)
    with pytest.raises(AuthenticationError, match="missing auth_token"):
        auth.login(Credentials(username="alice", password="pw"), role_label="user_a")


def test_login_transport_failure_propagates_unmodified():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    auth = _auth_module(handler)
    with pytest.raises(TransportError):
        auth.login(Credentials(username="alice", password="pw"), role_label="user_a")


# ---- register() ----


def test_register_success_does_not_raise():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/users/v1/register"
        return httpx.Response(200, json={"message": "Successfully registered.", "status": "success"})

    auth = _auth_module(handler)
    auth.register(Credentials(username="alice", password="pw", email="alice@example.com"))


def test_register_failure_raises_authentication_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"status": "fail", "message": "User already exists."})

    auth = _auth_module(handler)
    with pytest.raises(AuthenticationError, match="already exists"):
        auth.register(Credentials(username="alice", password="pw"))


# ---- get_auth_headers() ----


def test_get_auth_headers_returns_bearer_header_for_valid_context():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    auth = _auth_module(handler)
    context = AuthContext(role_label="user_a", username="alice", auth_header_value="Bearer abc123", expires_at=None)

    headers = auth.get_auth_headers(context)
    assert headers == {"Authorization": "Bearer abc123"}


def test_get_auth_headers_raises_on_expired_context():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    auth = _auth_module(handler)
    from datetime import datetime, timedelta, timezone

    expired_context = AuthContext(
        role_label="user_a",
        username="alice",
        auth_header_value="Bearer abc123",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    with pytest.raises(TokenExpiredError):
        auth.get_auth_headers(expired_context)


# ---- JWT decode edge cases ----


def test_login_with_malformed_token_sets_expires_at_none_and_does_not_raise():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"auth_token": "not-a-real-jwt", "status": "success"})

    auth = _auth_module(handler)
    context = auth.login(Credentials(username="alice", password="pw"), role_label="user_a")

    assert context.expires_at is None
    assert context.auth_header_value == "Bearer not-a-real-jwt"


# ---- Redaction ----


def test_credentials_repr_redacts_password():
    creds = Credentials(username="alice", password="super-secret-pw")
    rendered = repr(creds)
    assert "super-secret-pw" not in rendered
    assert "REDACTED" in rendered
    assert str(creds) == rendered


def test_auth_context_repr_redacts_token():
    context = AuthContext(role_label="user_a", username="alice", auth_header_value="Bearer abc123xyz")
    rendered = repr(context)
    assert "abc123xyz" not in rendered
    assert "REDACTED" in rendered
    assert str(context) == rendered