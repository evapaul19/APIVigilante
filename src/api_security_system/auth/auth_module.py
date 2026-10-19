"""Deterministic authentication-context management for VAmPI.

Manages test identities by registering and logging them in against
VAmPI's real register/login endpoints, then producing ready-to-use
Authorization headers for RequestExecutor to attach to subsequent
requests. Reuses the existing RequestExecutor to send these requests -
does not create any separate HTTP mechanism. No LLM calls. No
persistence to the database - credentials and tokens live only in
process memory for as long as the caller holds the AuthContext.

VAmPI's auth contract, confirmed directly from targets/vampi-openapi.yml:
  POST /users/v1/register  {username, password, email} -> {message, status}
  POST /users/v1/login     {username, password} -> {auth_token, message, status}
  bearerAuth security scheme: Authorization: Bearer <JWT>
"""

import base64
import json
from datetime import datetime, timezone
from typing import Optional

from api_security_system.request_executor import ExecutionRequest, RequestExecutor

from .schemas import AuthContext, AuthenticationError, Credentials, TokenExpiredError

REGISTER_PATH = "/users/v1/register"
LOGIN_PATH = "/users/v1/login"


def _decode_jwt_exp(token: str) -> Optional[datetime]:
    """Best-effort extraction of the 'exp' claim from a JWT's payload
    segment. No signature verification - this is proactive expiry
    bookkeeping only, never used for a trust or authorization
    decision. Returns None on any decode failure rather than raising,
    since expiry tracking is a convenience, not a requirement."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(payload_bytes)
        exp = payload.get("exp")
        if exp is None:
            return None
        return datetime.fromtimestamp(exp, tz=timezone.utc)
    except Exception:
        return None


class AuthModule:
    """Registers and logs in test identities against VAmPI, producing
    AuthContext objects whose headers RequestExecutor can use directly.

    Does not wrap or auto-call RequestExecutor.execute() for arbitrary
    requests, and does not auto-relogin on an expired/401 token - both
    deliberately left to the caller for this step, to keep this module
    narrowly scoped to authentication itself.
    """

    def __init__(self, executor: RequestExecutor) -> None:
        self._executor = executor

    def register(self, credentials: Credentials) -> None:
        """Register a new user. Raises AuthenticationError on failure.
        TransportError from the executor propagates unmodified."""
        response = self._executor.execute(
            ExecutionRequest(
                method="POST",
                path=REGISTER_PATH,
                json_body={
                    "username": credentials.username,
                    "password": credentials.password,
                    "email": credentials.email,
                },
            )
        )
        body = response.response_body or {}
        if response.response_status != 200 or body.get("status") != "success":
            message = body.get("message", "Registration failed with no message from server.")
            raise AuthenticationError(
                f"Registration failed for user '{credentials.username}': {message}"
            )

    def login(self, credentials: Credentials, role_label: str) -> AuthContext:
        """Log in and return an AuthContext with a usable Authorization
        header. Raises AuthenticationError on invalid credentials, an
        unsuccessful response, or a success response missing
        auth_token. TransportError from the executor propagates
        unmodified."""
        response = self._executor.execute(
            ExecutionRequest(
                method="POST",
                path=LOGIN_PATH,
                json_body={
                    "username": credentials.username,
                    "password": credentials.password,
                },
            )
        )
        body = response.response_body or {}
        if response.response_status != 200 or body.get("status") != "success":
            message = body.get("message", "Login failed with no message from server.")
            raise AuthenticationError(
                f"Login failed for user '{credentials.username}': {message}"
            )

        token = body.get("auth_token")
        if not token:
            raise AuthenticationError(
                f"Login response for user '{credentials.username}' is missing auth_token."
            )

        return AuthContext(
            role_label=role_label,
            username=credentials.username,
            auth_header_value=f"Bearer {token}",
            expires_at=_decode_jwt_exp(token),
        )

    def get_auth_headers(self, context: AuthContext) -> dict[str, str]:
        """Return the Authorization header for an AuthContext. Raises
        TokenExpiredError if the token's decoded expiry has passed.
        If expiry could not be decoded (expires_at is None), the
        token is assumed usable until a live 401 proves otherwise."""
        if context.expires_at is not None and context.expires_at <= datetime.now(timezone.utc):
            raise TokenExpiredError(
                f"Token for '{context.username}' (role '{context.role_label}') "
                f"expired at {context.expires_at.isoformat()}."
            )
        return {"Authorization": context.auth_header_value}