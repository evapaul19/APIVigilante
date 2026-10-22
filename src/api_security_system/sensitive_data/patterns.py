"""Field-name and value-pattern rules for sensitive-data detection.

Both signals are required together where possible: a field called
`password` is only reported when its value looks like real credential
material rather than a mask or placeholder, and a value that merely
looks like an email address is only reported when the surrounding field
is actually an email/identity field. The rules intentionally avoid
guessing from names alone.
"""

import re
from typing import Optional

# Ordered: more specific categories win over generic ones.
_FIELD_RULES: list[tuple[str, re.Pattern]] = [
    (
        "private_key",
        re.compile(
            r"(?i)(^|[_-])(private[_-]?key|rsa[_-]?key|ec[_-]?key|"
            r"signing[_-]?key|ssh[_-]?key)($|[_-])"
        ),
    ),
    ("password", re.compile(
        r"(?i)(^|[_-])(pass(word|wd|phrase)?|pwd)($|[_-])"
    )),
    (
        "token",
        re.compile(
            r"(?i)(^|[_-])(auth|access|refresh|id|bearer|session)?[_-]?token"
            r"($|[_-])|(^|[_-])(jwt|api[_-]?key|apikey|client[_-]?secret|"
            r"secret[_-]?key)($|[_-])"
        ),
    ),
    ("generic_secret", re.compile(r"(?i)(^|[_-])secret($|[_-])")),
    (
        "pii_email",
        re.compile(
            r"(?i)^(e[_-]?mail|email|mail|user[_-]?email|"
            r"e[_-]?mail[_-]?address)$"
        ),
    ),
    (
        "pii_phone",
        re.compile(r"(?i)(^|[_-])(phone|mobile|msisdn|telephone)($|[_-])"),
    ),
    (
        "pii_ssn",
        re.compile(r"(?i)(^|[_-])(ssn|social[_-]?security)($|[_-])"),
    ),
    (
        "pii_payment",
        re.compile(
            r"(?i)(^|[_-])(credit[_-]?card|card[_-]?number|iban|"
            r"account[_-]?number|cvv|cvc|pin)($|[_-])"
        ),
    ),
    (
        "pii_dob",
        re.compile(r"(?i)(^|[_-])(date[_-]?of[_-]?birth|birthdate|dob)($|[_-])"),
    ),
    (
        "pii_address",
        re.compile(
            r"(?i)(^|[_-])(address|street|postal[_-]?code|zip[_-]?code)"
            r"[0-9]*($|[_-])"
        ),
    ),
]

PII_CATEGORIES = {
    "pii_email",
    "pii_phone",
    "pii_ssn",
    "pii_payment",
    "pii_dob",
    "pii_address",
}

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_JWT = re.compile(
    r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"
)
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"
)
_AWS_ACCESS_KEY = re.compile(r"^(?:AKIA|ASIA)[0-9A-Z]{16}$")
_COMMON_API_KEY = re.compile(
    r"^(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}$|^gh[pousr]_[A-Za-z0-9]{20,}$"
)
_SSN = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_PHONE = re.compile(r"^\+?[0-9][0-9 .()\-]{6,}$")
_HASH = re.compile(r"^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{20,}$")
_LONG_HEX = re.compile(r"^[0-9a-fA-F]{32,}$")
_OPAQUE_SECRET = re.compile(r"^[A-Za-z0-9._~+/=-]{8,}$")

_MASK = re.compile(r"(?i)(?:\*{3,}|x{4,}|\.{4,}|•{2,})")
_PLACEHOLDERS = {
    "",
    "n/a",
    "na",
    "none",
    "null",
    "undefined",
    "redacted",
    "hidden",
    "masked",
    "not set",
    "not_set",
    "******",
    "changeme",
    "change_me",
    "dummy",
    "example",
    "placeholder",
    "password",
    "sample",
    "test",
    "test_password",
    "testpassword",
    "todo",
    "your_password",
    "your-password",
}


def field_category(field_name: str) -> Optional[str]:
    """Return the first matching sensitive category for a field name."""
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(field_name))
    for category, pattern in _FIELD_RULES:
        if pattern.search(name):
            return category
    return None


def is_masked_or_placeholder(value) -> bool:
    """True when a value is clearly a mask/placeholder, not real data."""
    if value is None:
        return True
    if isinstance(value, bool):
        return True
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    lower = stripped.lower()
    if lower in _PLACEHOLDERS:
        return True
    if _MASK.search(stripped):
        return True
    if stripped.startswith("<") and stripped.endswith(">"):
        return True
    if stripped.startswith("[") and stripped.endswith("]") and "redact" in lower:
        return True
    return False


def _looks_like_opaque_secret(text: str) -> bool:
    """Reject short prose and common placeholders that happen to sit in
    a token-named field, while still accepting random token material."""
    if not _OPAQUE_SECRET.match(text):
        return False
    if text.lower() in _PLACEHOLDERS:
        return False
    if text.lower() in {
        "bearer",
        "basic",
        "digest",
        "authorization",
        "authentication",
    }:
        return False

    has_digit = any(char.isdigit() for char in text)
    has_symbol = any(not char.isalnum() for char in text)
    has_mixed_case = any(char.islower() for char in text) and any(
        char.isupper() for char in text
    )
    return has_digit or has_symbol or has_mixed_case


def value_kind(category: str, value) -> Optional[str]:
    """Classify a non-masked value for one category.

    Returns None when the value does not actually support the category -
    this is the guard against flagging fields based on name alone.
    """
    if value is None or isinstance(value, bool):
        return None
    text = str(value)
    stripped = text.strip()

    if category == "private_key":
        return "pem_private_key" if _PEM_PRIVATE_KEY.search(text) else "key_material"

    if category == "password":
        if _HASH.match(stripped) or stripped.startswith(
            ("$argon2", "$scrypt", "$pbkdf2")
        ):
            return "password_hash"
        if len(stripped) < 4:
            return None
        return "plaintext_password"

    if category in {"token", "generic_secret"}:
        if _JWT.match(stripped):
            return "jwt_token"
        if _AWS_ACCESS_KEY.match(stripped):
            return "api_key"
        if _COMMON_API_KEY.match(stripped):
            return "api_key"
        if _LONG_HEX.match(stripped):
            return "hex_secret"
        if _looks_like_opaque_secret(stripped):
            return "opaque_secret"
        return None

    if category == "pii_email":
        return "email" if _EMAIL.match(stripped) else None

    if category == "pii_phone":
        return "phone" if _PHONE.match(stripped) else None

    if category == "pii_ssn":
        return "ssn" if _SSN.match(stripped) else None

    if category == "pii_payment":
        digits = re.sub(r"[^0-9]", "", stripped)
        if _COMMON_API_KEY.match(stripped) or _JWT.match(stripped):
            return None
        return "payment_number" if 12 <= len(digits) <= 19 else None

    if category == "pii_dob":
        return "date" if re.match(r"^\d{4}-\d{2}-\d{2}$", stripped) else None

    if category == "pii_address":
        return "address" if len(stripped) >= 8 else None

    return None


def normalize_path(path: str) -> str:
    """Collapse list indexes so 100 rows produce one stable field path."""
    normalized = re.sub(r"\[\d+\]", "[*]", path)
    if normalized.startswith("$."):
        return normalized[2:]
    if normalized.startswith("$"):
        return normalized[1:]
    return normalized


def is_value_sensitive_standalone(value) -> bool:
    """Value-only checks used by the evidence sanitizer.

    Broader than detection: if a secret-looking value appears anywhere
    in a stored response body, redact it even when its field name is not
    in the sensitive-name list.
    """
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    return bool(
        _JWT.match(stripped)
        or _PEM_PRIVATE_KEY.search(stripped)
        or _AWS_ACCESS_KEY.match(stripped)
        or _COMMON_API_KEY.match(stripped)
        or _SSN.match(stripped)
        or _EMAIL.match(stripped)
    )


def masked_preview(value) -> str:
    """A short, non-reversible description of a redacted value."""
    if isinstance(value, str):
        return f"<redacted:{len(value)} chars>"
    return "<redacted>"
