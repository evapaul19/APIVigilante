"""Auth Module: deterministic test-identity authentication and
caller-supplied auth profiles, routed through RequestExecutor. No LLM
calls. Profile secrets are not persisted.
"""

from .auth_module import AuthModule
from .profiles import (
    AuthIdentity,
    AuthProfile,
    AuthProfileError,
    ProfileIdentity,
    headers_for_identity,
    resolve_profile_identities,
)
from .schemas import AuthContext, AuthenticationError, Credentials, TokenExpiredError

__all__ = [
    "AuthModule",
    "AuthIdentity",
    "AuthProfile",
    "AuthProfileError",
    "ProfileIdentity",
    "Credentials",
    "AuthContext",
    "AuthenticationError",
    "TokenExpiredError",
    "headers_for_identity",
    "resolve_profile_identities",
]
