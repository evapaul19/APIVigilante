"""Secret redaction for logs and diagnostic output only.

This module never limits or mutates the real evidence available to
callers - it only produces redacted copies for anything that might be
logged, printed, or included in an exception message.
"""

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

REDACTED_VALUE = "***REDACTED***"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with sensitive values replaced.
    Case-insensitive match on header name."""
    return {
        key: (REDACTED_VALUE if key.lower() in SENSITIVE_HEADER_NAMES else value)
        for key, value in headers.items()
    }