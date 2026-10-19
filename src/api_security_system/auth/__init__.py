"""Auth Module: deterministic test-identity authentication against
VAmPI's real login flow, via the existing RequestExecutor. No LLM
calls, no persistence.
"""

from .auth_module import AuthModule
from .schemas import AuthContext, AuthenticationError, Credentials, TokenExpiredError

__all__ = [
    "AuthModule",
    "Credentials",
    "AuthContext",
    "AuthenticationError",
    "TokenExpiredError",
]