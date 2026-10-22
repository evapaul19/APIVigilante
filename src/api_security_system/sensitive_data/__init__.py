"""Sensitive-data exposure checks over actual API responses.

Independent of the BOLA and BFLA detectors: this module inspects response
bodies for inappropriate disclosure of credentials, tokens, key material,
and personal information, and persists redacted evidence only.
"""

from .schemas import (
    SensitiveDataCheckResult,
    SensitiveEndpointResult,
    SensitiveFieldObservation,
    SensitiveOutcome,
)
from .service import (
    DEFAULT_SENSITIVE_REQUEST_BUDGET,
    run_sensitive_data_check,
    sanitize_for_persistence,
)

__all__ = [
    "run_sensitive_data_check",
    "sanitize_for_persistence",
    "DEFAULT_SENSITIVE_REQUEST_BUDGET",
    "SensitiveDataCheckResult",
    "SensitiveEndpointResult",
    "SensitiveFieldObservation",
    "SensitiveOutcome",
]
