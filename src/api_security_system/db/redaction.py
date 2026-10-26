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

import os
import re
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
    "password_hash",
    "new_password",
    "old_password",
    "current_password",
    "password_confirmation",
    "passwd",
    "pwd",
    "auth_token",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "session_token",
    "api_key",
    "apikey",
    "client_secret",
    "secret",
    "private_key",
    "email",
    "email_address",
    "user_email",
    "e_mail",
    "phone",
    "phone_number",
    "ssn",
    "social_security_number",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "iban",
    "date_of_birth",
    "birthdate",
}


def _is_sensitive_header_name(name: str) -> bool:
    lowered = str(name or "").strip().lower()
    if lowered in SENSITIVE_HEADER_NAMES:
        return True
    parts = re.split(r"[^a-z0-9]+", lowered)
    return any(
        part in {"auth", "authorization", "token", "key", "apikey", "secret", "cookie", "password"}
        for part in parts
    )


def redact_headers_for_persistence(headers: dict) -> dict:
    """Case-insensitive match on header name. Returns a new dict."""
    return {
        key: (REDACTED_VALUE if _is_sensitive_header_name(key) else value)
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


def redact_body_for_persistence(body):
    """Case-insensitive, recursive match on field name through nested
    dicts and lists of dicts. Returns a new object; None passes
    through unchanged."""
    if body is None:
        return None
    return _redact_value(body)


_SECRET_ENV_SUFFIXES = ("_KEY", "_SECRET", "_PASSWORD", "_TOKEN")
_BEARER_OR_BASIC = re.compile(
    r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
    r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
_PRIVATE_KEY_OPEN = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*\Z",
    re.DOTALL,
)
_JWT_VALUE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
_EMAIL_ADDRESS = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_SSN_TEXT = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|"
    r"authorization)[A-Za-z0-9_.-]*)\s*[:=]\s*[^\s,;]+"
)
_URL_CREDENTIALS = re.compile(
    r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"
)


def _secret_environment_values() -> list[str]:
    values = []
    for name, value in os.environ.items():
        if not value or len(value) < 4:
            continue
        if name == "DATABASE_URL" or name.endswith(_SECRET_ENV_SUFFIXES):
            values.append(value)
    # Longest first so a URL containing a shorter secret is redacted whole.
    return sorted(set(values), key=len, reverse=True)


def sanitize_text_for_persistence(
    text: Optional[str], max_length: int = 2000
) -> Optional[str]:
    """Redact credential-like substrings before persisting free-form text.

    Used for stage failures/reasons and their details. This is best-effort
    defense in depth: callers should still avoid putting secrets in text.
    Returns a new string; None passes through.
    """
    if text is None:
        return None

    sanitized = str(text)
    for secret in _secret_environment_values():
        sanitized = sanitized.replace(secret, REDACTED_VALUE)

    sanitized = _BEARER_OR_BASIC.sub(
        lambda match: f"{match.group(1)} {REDACTED_VALUE}", sanitized
    )
    sanitized = _PRIVATE_KEY_BLOCK.sub(REDACTED_VALUE, sanitized)
    sanitized = _PRIVATE_KEY_OPEN.sub(REDACTED_VALUE, sanitized)
    sanitized = _JWT_VALUE.sub(REDACTED_VALUE, sanitized)
    sanitized = _URL_CREDENTIALS.sub(
        lambda match: f"{match.group(1)}{REDACTED_VALUE}@", sanitized
    )
    sanitized = _EMAIL_ADDRESS.sub(REDACTED_VALUE, sanitized)
    sanitized = _SSN_TEXT.sub(REDACTED_VALUE, sanitized)
    sanitized = _CREDENTIAL_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}={REDACTED_VALUE}", sanitized
    )

    if max_length > 0 and len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "... [truncated]"
    return sanitized
