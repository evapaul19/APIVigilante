"""Shared redaction for data persisted to the database - distinct from
request_executor/redaction.py, which redacts only for logs/diagnostic
output while leaving the in-memory ExecutionResult fully intact. This
module redacts values BEFORE they are written to Postgres, since
TestExecution evidence rows are retained long-term and queried later,
unlike a transient log line.

Both functions return new objects and never mutate their input - any
caller holding a reference to the original dict (e.g. deterministic
verification logic that already ran before persistence) is unaffected.
"""

from typing import Optional

REDACTED_VALUE = "***REDACTED***"

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

SENSITIVE_BODY_FIELD_NAMES = {
    "password",
    "auth_token",
    "token",
    "access_token",
    "refresh_token",
}


def redact_headers_for_persistence(headers: dict) -> dict:
    """Case-insensitive match on header name. Returns a new dict."""
    return {
        key: (REDACTED_VALUE if key.lower() in SENSITIVE_HEADER_NAMES else value)
        for key, value in headers.items()
    }


def _redact_value(value):
    if isinstance(value, dict):
        return _redact_dict(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def _redact_dict(body: dict) -> dict:
    redacted = {}
    for key, value in body.items():
        if key.lower() in SENSITIVE_BODY_FIELD_NAMES:
            redacted[key] = REDACTED_VALUE
        else:
            redacted[key] = _redact_value(value)
    return redacted


def redact_body_for_persistence(body: Optional[dict]) -> Optional[dict]:
    """Case-insensitive, recursive match on field name through nested
    dicts and lists of dicts. Returns a new object; None passes
    through unchanged."""
    if body is None:
        return None
    return _redact_dict(body)