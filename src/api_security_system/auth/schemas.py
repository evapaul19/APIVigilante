"""Pydantic schemas and exception types for the Auth Module."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel

REDACTED_VALUE = "***REDACTED***"


class AuthenticationError(Exception):
    """Raised for a failed register or login attempt - invalid
    credentials, an unsuccessful VAmPI response, or a malformed
    success response missing expected fields (e.g. auth_token).

    Distinct from RequestExecutor's TransportError, which indicates
    the request never completed at all - a TransportError during
    register/login is allowed to propagate unmodified rather than
    being wrapped here."""


class TokenExpiredError(Exception):
    """Raised by get_auth_headers() when the cached token's expiry
    (decoded from the JWT's own 'exp' claim) has passed. The caller
    is expected to log in again - this module does not auto-relogin."""


class Credentials(BaseModel):
    """Login/registration credentials for a single test identity.

    repr()/str() redact the password so it is never exposed through
    accidental logging, debugging, or exception context - the same
    pattern already used for ExecutionResult and ExecutionRequest
    headers in the RequestExecutor module.
    """

    username: str
    password: str
    email: Optional[str] = None

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(username={self.username!r}, "
            f"password={REDACTED_VALUE!r}, email={self.email!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


class AuthContext(BaseModel):
    """An authenticated identity's usable auth header, plus best-effort
    expiry tracking decoded from the JWT itself (no signature
    verification - this is bookkeeping only, never a trust decision).

    The real header value is still accessible via normal attribute
    access for authorized callers (e.g. passing it into
    ExecutionRequest.headers); repr()/str() redact it.
    """

    role_label: str
    username: str
    auth_header_value: str
    expires_at: Optional[datetime] = None

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(role_label={self.role_label!r}, "
            f"username={self.username!r}, auth_header_value={REDACTED_VALUE!r}, "
            f"expires_at={self.expires_at!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()