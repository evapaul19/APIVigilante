"""Declarative authentication profiles for active checks.

Profiles let a caller supply identities for targets that do not use
VAmPI's register/login contract. Static bearer tokens, API keys, HTTP
Basic credentials, and a generic JSON login/token-extraction flow are
supported. Profile-level extra headers can carry required tenant,
API-version, or login-key values. Identities may also declare values to
substitute for path parameters (for example an account UUID) and a
subject marker used to attribute response data.

Secrets are kept in memory only. They are never persisted, included in
stage details, or written into evidence by this module.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any, Literal, Optional
from urllib.parse import unquote, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from api_security_system.auth.schemas import AuthenticationError
from api_security_system.db import TestIdentity, get_session
from api_security_system.db.redaction import REDACTED_VALUE, sanitize_text_for_persistence
from api_security_system.request_executor import ExecutionRequest

_IDENTITY_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_JSON_PATH = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$")
_FIELD_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_FORBIDDEN_HEADERS = {
    "connection",
    "content-length",
    "forwarded",
    "host",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
}


class AuthProfileError(ValueError):
    """Raised when a profile cannot produce a usable identity safely."""


def _validate_header_name(value: str) -> str:
    name = str(value or "").strip()
    if not name or not _HEADER_NAME.fullmatch(name):
        raise ValueError("Header name contains invalid characters.")
    if name.lower() in _FORBIDDEN_HEADERS:
        raise ValueError(f"Header '{name}' is not allowed in an auth profile.")
    return name


def _validate_header_value(value: str) -> str:
    text = str(value)
    if _CONTROL_CHARS.search(text):
        raise ValueError("Header values must not contain control characters.")
    return text


def _validate_headers(value: dict[str, SecretStr]) -> dict[str, SecretStr]:
    cleaned: dict[str, SecretStr] = {}
    for name, header_value in (value or {}).items():
        cleaned[_validate_header_name(name)] = SecretStr(
            _validate_header_value(_secret(header_value) or "")
        )
    return cleaned


def _secret_headers(headers: dict[str, SecretStr]) -> dict[str, str]:
    return {
        name: _secret(header_value) or ""
        for name, header_value in (headers or {}).items()
    }


def _merge_headers(*groups: dict[str, str]) -> dict[str, str]:
    """Merge header groups case-insensitively; later groups win."""
    merged: dict[str, str] = {}
    original_names: dict[str, str] = {}
    for group in groups:
        for name, value in (group or {}).items():
            lowered = str(name).lower()
            previous = original_names.get(lowered)
            if previous is not None:
                merged.pop(previous, None)
            merged[str(name)] = str(value)
            original_names[lowered] = str(name)
    return merged


def _validate_relative_path(value: str) -> str:
    path = str(value or "").strip()
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("Path must be an absolute path relative to the target origin.")
    parts = urlsplit(path)
    if parts.scheme or parts.netloc or parts.query or parts.fragment:
        raise ValueError("Path must not contain a scheme, query, or fragment.")
    if "\\" in path or _CONTROL_CHARS.search(path):
        raise ValueError("Path contains invalid characters.")
    decoded = unquote(path)
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise ValueError("Path must not contain dot-segments.")
    return path


def _validate_path_value(value: str) -> str:
    text = str(value or "").strip()
    if not text or text in {".", ".."}:
        raise ValueError("Path parameter values must be non-empty single segments.")
    if any(char in text for char in ("/", "\\", "?", "#")):
        raise ValueError("Path parameter values must not contain URL delimiters.")
    decoded = unquote(text)
    if decoded in {".", ".."}:
        raise ValueError("Path parameter values must not encode dot-segments.")
    if any(char in decoded for char in ("/", "\\", "?", "#")):
        raise ValueError("Path parameter values must not encode URL delimiters.")
    if _CONTROL_CHARS.search(text) or _CONTROL_CHARS.search(decoded):
        raise ValueError("Path parameter values must not contain control characters.")
    return text


def _secret(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    return str(value)


class AuthIdentity(BaseModel):
    """One caller-supplied identity for an auth profile."""

    model_config = ConfigDict(extra="forbid")

    label: str = Field(
        min_length=1,
        max_length=64,
        description="Unique, non-secret label used in local evidence records.",
    )
    username: Optional[str] = Field(default=None, max_length=200)
    password: Optional[SecretStr] = None
    token: Optional[SecretStr] = None
    api_key: Optional[SecretStr] = None
    subject: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Value that identifies this identity in response bodies.",
    )
    path_values: dict[str, str] = Field(
        default_factory=dict,
        description="Path parameter name to concrete value for this identity.",
    )
    headers: dict[str, SecretStr] = Field(
        default_factory=dict,
        description="Direct static headers; use for schemes not covered by helpers.",
    )
    admin: bool = False

    @field_validator("label")
    @classmethod
    def _validate_label(cls, value: str) -> str:
        text = str(value or "").strip()
        if not _IDENTITY_LABEL.fullmatch(text):
            raise ValueError(
                "Identity label must start with a letter or digit and contain "
                "only letters, digits, dots, underscores, or hyphens."
            )
        return text

    @field_validator("username", "subject")
    @classmethod
    def _validate_text(cls, value):
        if value is None:
            return None
        text = str(value).strip()
        if not text or len(text) > 200 or _CONTROL_CHARS.search(text):
            raise ValueError("Identity values must be non-empty, short, and control-free.")
        return text

    @field_validator("headers")
    @classmethod
    def _validate_identity_headers(
        cls, value: dict[str, SecretStr]
    ) -> dict[str, SecretStr]:
        return _validate_headers(value)

    @field_validator("path_values")
    @classmethod
    def _validate_path_values(cls, value: dict[str, str]) -> dict[str, str]:
        cleaned: dict[str, str] = {}
        for name, path_value in (value or {}).items():
            key = str(name or "").strip()
            if not _FIELD_NAME.fullmatch(key):
                raise ValueError("Path parameter names must be simple identifiers.")
            cleaned[key] = _validate_path_value(path_value)
        return cleaned

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(label={self.label!r}, "
            f"username={self.username!r}, subject={self.subject!r}, "
            f"password={REDACTED_VALUE!r}, token={REDACTED_VALUE!r}, "
            f"api_key={REDACTED_VALUE!r}, headers={REDACTED_VALUE!r}, "
            f"path_values={self.path_values!r}, admin={self.admin!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


class AuthProfile(BaseModel):
    """A small, declarative authentication contract for one assessment."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["static", "login", "none"] = Field(
        default="static",
        description="static headers/tokens, a generic JSON login, or anonymous only.",
    )
    scheme: Literal["bearer", "api_key", "basic", "custom"] = "custom"
    header_name: Optional[str] = Field(
        default=None,
        description="Header to use; defaults depend on the selected scheme.",
    )
    extra_headers: dict[str, SecretStr] = Field(
        default_factory=dict,
        description=(
            "Non-auth headers sent on login and authenticated requests, "
            "such as tenant or API-version headers."
        ),
    )
    token_prefix: str = Field(
        default="Bearer ",
        max_length=32,
        description="Prefix for bearer tokens, including any trailing space.",
    )
    login_path: Optional[str] = Field(
        default=None,
        description="Relative JSON login endpoint, e.g. /auth/login.",
    )
    login_method: Literal["POST"] = "POST"
    login_username_field: str = "username"
    login_password_field: str = "password"
    token_path: str = Field(
        default="auth_token",
        description="Dot-separated JSON path to the token in the login response.",
    )
    identities: list[AuthIdentity] = Field(default_factory=list)

    @field_validator("header_name")
    @classmethod
    def _validate_optional_header(cls, value):
        return _validate_header_name(value) if value else None

    @field_validator("extra_headers")
    @classmethod
    def _validate_extra_headers(
        cls, value: dict[str, SecretStr]
    ) -> dict[str, SecretStr]:
        return _validate_headers(value)

    @field_validator("login_path")
    @classmethod
    def _validate_optional_login_path(cls, value):
        return _validate_relative_path(value) if value else None

    @field_validator("token_prefix")
    @classmethod
    def _validate_token_prefix(cls, value: str) -> str:
        return _validate_header_value(value)

    @field_validator("login_username_field", "login_password_field")
    @classmethod
    def _validate_field_name(cls, value: str) -> str:
        text = str(value or "").strip()
        if not _FIELD_NAME.fullmatch(text):
            raise ValueError("Login field names must be simple identifiers.")
        return text

    @field_validator("token_path")
    @classmethod
    def _validate_token_path(cls, value: str) -> str:
        text = str(value or "").strip()
        if not _JSON_PATH.fullmatch(text):
            raise ValueError("Token path must be a dot-separated JSON field path.")
        return text

    @model_validator(mode="after")
    def _validate_profile(self):
        labels = [identity.label for identity in self.identities]
        if len(labels) != len(set(labels)):
            raise ValueError("Identity labels must be unique within a profile.")
        if self.type == "none" and self.identities:
            raise ValueError("A 'none' profile must not contain identities.")
        if self.type in {"static", "login"} and not self.identities:
            raise ValueError(f"A '{self.type}' profile requires at least one identity.")
        if self.type == "login":
            if not self.login_path:
                raise ValueError("A login profile requires login_path.")
            if self.scheme == "basic":
                raise ValueError("A login profile cannot use HTTP Basic extraction.")
        if self.type == "static" and not self.header_name and self.scheme == "custom":
            # Custom static identities may use only explicit headers; this
            # validator intentionally does not reject them.
            pass
        return self

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(type={self.type!r}, "
            f"scheme={self.scheme!r}, header_name={self.header_name!r}, "
            f"extra_headers=<{len(self.extra_headers)}>, "
            f"login_path={self.login_path!r}, identities=<{len(self.identities)}>)"
        )

    def __str__(self) -> str:
        return self.__repr__()


@dataclass(frozen=True)
class ProfileIdentity:
    """A resolved identity with usable headers and attribution markers."""

    identity_id: int
    label: str
    subject: str
    username: str
    headers: dict[str, str]
    path_values: dict[str, str]
    admin: bool = False

    def value_for(
        self, parameter: str, *, username_identifier: bool = False
    ) -> Optional[str]:
        if parameter in self.path_values:
            return self.path_values[parameter]
        if username_identifier:
            return self.username or self.subject or None
        return None

    def markers(self) -> set[str]:
        values = {self.subject, self.username, *self.path_values.values()}
        return {str(value).strip() for value in values if value is not None and str(value).strip()}

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(identity_id={self.identity_id!r}, "
            f"label={self.label!r}, subject={self.subject!r}, "
            f"username={self.username!r}, headers={REDACTED_VALUE!r}, "
            f"path_values={self.path_values!r}, admin={self.admin!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


def _extract_json_path(body: Any, path: str) -> Optional[str]:
    current = body
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    if isinstance(current, bool) or current is None:
        return None
    if isinstance(current, (str, int, float)):
        value = str(current).strip()
        return value or None
    return None


def _static_headers(profile: AuthProfile, identity: AuthIdentity) -> dict[str, str]:
    extra_headers = _secret_headers(profile.extra_headers)
    if identity.headers:
        return _merge_headers(extra_headers, _secret_headers(identity.headers))

    scheme = profile.scheme
    if scheme == "bearer":
        token = _secret(identity.token)
        if not token:
            raise AuthProfileError(
                f"Identity '{identity.label}' requires a bearer token."
            )
        header = profile.header_name or "Authorization"
        return _merge_headers(
            extra_headers, {header: f"{profile.token_prefix}{token}"}
        )

    if scheme == "api_key":
        api_key = _secret(identity.api_key) or _secret(identity.token)
        if not api_key:
            raise AuthProfileError(
                f"Identity '{identity.label}' requires an api_key or token."
            )
        return _merge_headers(
            extra_headers, {profile.header_name or "X-API-Key": api_key}
        )

    if scheme == "basic":
        password = _secret(identity.password)
        if not identity.username or not password:
            raise AuthProfileError(
                f"Identity '{identity.label}' requires username and password for Basic auth."
            )
        encoded = base64.b64encode(
            f"{identity.username}:{password}".encode("utf-8")
        ).decode("ascii")
        return _merge_headers(
            extra_headers, {"Authorization": f"Basic {encoded}"}
        )

    token = _secret(identity.token)
    api_key = _secret(identity.api_key)
    if token:
        return _merge_headers(
            extra_headers, {profile.header_name or "Authorization": token}
        )
    if api_key:
        return _merge_headers(
            extra_headers, {profile.header_name or "X-API-Key": api_key}
        )
    raise AuthProfileError(
        f"Identity '{identity.label}' has no headers, token, or api_key."
    )


def _login_headers(profile: AuthProfile, identity: AuthIdentity, executor) -> dict[str, str]:
    if executor is None:
        raise AuthProfileError("A login profile requires a request executor.")
    if not profile.login_path:
        raise AuthProfileError("A login profile requires login_path.")
    password = _secret(identity.password)
    if not identity.username or not password:
        raise AuthProfileError(
            f"Identity '{identity.label}' requires username and password."
        )

    extra_headers = _secret_headers(profile.extra_headers)
    response = executor.execute(
        ExecutionRequest(
            method=profile.login_method,
            path=profile.login_path,
            headers=extra_headers,
            json_body={
                profile.login_username_field: identity.username,
                profile.login_password_field: password,
            },
        )
    )
    if not (200 <= response.response_status < 300):
        raise AuthenticationError(
            f"Login failed for identity '{identity.label}' "
            f"(HTTP {response.response_status})."
        )

    token = _extract_json_path(response.response_body, profile.token_path)
    if not token:
        raise AuthenticationError(
            f"Login response for identity '{identity.label}' did not contain "
            f"the configured token path '{profile.token_path}'."
        )

    if profile.scheme == "bearer":
        auth_headers = {
            profile.header_name or "Authorization": f"{profile.token_prefix}{token}"
        }
    elif profile.scheme == "api_key":
        auth_headers = {profile.header_name or "X-API-Key": token}
    else:
        auth_headers = {profile.header_name or "Authorization": token}

    return _merge_headers(extra_headers, auth_headers)


def headers_for_identity(
    profile: AuthProfile,
    identity: AuthIdentity,
    executor=None,
) -> dict[str, str]:
    """Build request headers for one identity without persisting anything."""
    if profile.type == "login":
        return _login_headers(profile, identity, executor)
    return _static_headers(profile, identity)


def _persist_identity(scan_id: int, role_label: str, description: str) -> int:
    safe_description = sanitize_text_for_persistence(description, max_length=200)
    safe_role = re.sub(r"[^A-Za-z0-9_]", "_", role_label)[:64] or "profile_identity"
    with get_session() as session:
        row = TestIdentity(
            scan_id=scan_id,
            role_label=safe_role,
            description=safe_description or "profile_identity",
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return row.id


def resolve_profile_identities(
    profile: AuthProfile,
    executor,
    scan_id: int,
    role_prefix: str,
    limit: Optional[int] = None,
) -> list[ProfileIdentity]:
    """Resolve and persist non-secret identity records for a profile.

    Networking is performed only for ``login`` profiles. If any login or
    header construction fails, no identity records are persisted. ``limit``
    lets read-only checks resolve only the identities they need.
    """
    if profile.type == "none":
        return []

    selected = (
        profile.identities
        if limit is None
        else profile.identities[: max(0, limit)]
    )
    prepared: list[tuple[AuthIdentity, dict[str, str], str, str]] = []
    for identity in selected:
        headers = headers_for_identity(profile, identity, executor)
        subject = identity.subject or identity.username or identity.label
        username = identity.username or identity.subject or identity.label
        prepared.append((identity, headers, subject, username))

    resolved: list[ProfileIdentity] = []
    for identity, headers, subject, username in prepared:
        identity_id = _persist_identity(
            scan_id,
            f"{role_prefix}_{identity.label}",
            subject,
        )
        resolved.append(
            ProfileIdentity(
                identity_id=identity_id,
                label=identity.label,
                subject=subject,
                username=username,
                headers=headers,
                path_values=dict(identity.path_values),
                admin=identity.admin,
            )
        )
    return resolved
