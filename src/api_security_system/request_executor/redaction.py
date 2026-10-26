"""Secret redaction for logs and diagnostic output only.

This module never limits or mutates the real evidence available to
callers - it only produces redacted copies for anything that might be
logged, printed, or included in an exception message.
"""

import re

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

REDACTED_VALUE = "***REDACTED***"


def _is_sensitive_header_name(name: str) -> bool:
    lowered = str(name or "").strip().lower()
    if lowered in SENSITIVE_HEADER_NAMES:
        return True
    parts = re.split(r"[^a-z0-9]+", lowered)
    return any(
        part in {"auth", "authorization", "token", "key", "apikey", "secret", "cookie", "password"}
        for part in parts
    )


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with sensitive values replaced.
    Case-insensitive match on header name."""
    return {
        key: (REDACTED_VALUE if _is_sensitive_header_name(key) else value)
        for key, value in headers.items()
    }