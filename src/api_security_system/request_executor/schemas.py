"""Pydantic schemas and exception types for the RequestExecutor module."""

import math
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from .redaction import redact_headers

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
MAX_TIMEOUT_SECONDS = 120.0


class TargetOriginError(Exception):
    """Raised when a requested path would escape the configured target
    origin: an absolute URL, a protocol-relative path, an embedded
    query string/fragment, or traversal. Raised before any request
    is sent - RequestExecutor never attempts a request it has
    rejected as unsafe."""


class TransportError(Exception):
    """Raised when a request could not complete at all - connection
    refused, DNS failure, TLS error, or timeout. Distinct from a
    4xx/5xx HTTP response, which is returned as a normal
    ExecutionResult, not raised.

    Messages are built from method/path/error-type only, never from
    raw header values, so this is always safe to log directly."""


class ExecutionRequest(BaseModel):
    """A single HTTP request to send through RequestExecutor.

    `path` must be a concrete, already-substituted path relative to
    the target's origin (e.g. "/users/v1/alice") - RequestExecutor
    performs no path-parameter substitution or resource discovery;
    that belongs to the Resource Graph / whichever agent calls this.
    """

    method: str
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    json_body: Optional[dict] = None
    timeout_seconds: float = 10.0

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str) -> str:
        upper = v.upper()
        if upper not in ALLOWED_METHODS:
            raise ValueError(f"Unsupported HTTP method: {v!r}")
        return upper

    @field_validator("timeout_seconds")
    @classmethod
    def _validate_timeout(cls, v: float) -> float:
        if v is None:
            raise ValueError("timeout_seconds must not be None (that would mean unbounded).")
        if math.isinf(v) or math.isnan(v):
            raise ValueError("timeout_seconds must be finite.")
        if v <= 0:
            raise ValueError("timeout_seconds must be greater than 0.")
        if v > MAX_TIMEOUT_SECONDS:
            raise ValueError(f"timeout_seconds must not exceed {MAX_TIMEOUT_SECONDS}.")
        return v


class ExecutionResult(BaseModel):
    """Structured evidence from a single HTTP request/response.

    Full, unredacted data (including real auth header values) is
    accessible via normal attribute access, for authorized callers
    that persist evidence (e.g. into TestExecution). repr()/str() are
    overridden to redact sensitive headers and truncate bodies by
    default, so accidental logging, debugging, or exception context
    never leaks a credential or dumps a large/sensitive body.
    """

    request_method: str
    request_path: str
    request_headers: dict[str, str]
    request_body: Optional[dict] = None
    response_status: int
    response_headers: dict[str, str]
    response_body: Optional[dict] = None
    response_body_raw: Optional[str] = None
    latency_ms: int
    executed_at: datetime

    def __repr__(self) -> str:
        safe_request_headers = redact_headers(self.request_headers)
        safe_response_headers = redact_headers(self.response_headers)
        body_len = len(str(self.response_body)) if self.response_body else 0
        raw_len = len(self.response_body_raw) if self.response_body_raw else 0
        return (
            f"{self.__class__.__name__}("
            f"request_method={self.request_method!r}, "
            f"request_path={self.request_path!r}, "
            f"request_headers={safe_request_headers!r}, "
            f"response_status={self.response_status!r}, "
            f"response_headers={safe_response_headers!r}, "
            f"response_body=<{body_len} chars>, "
            f"response_body_raw=<{raw_len} chars>, "
            f"latency_ms={self.latency_ms!r}, "
            f"executed_at={self.executed_at!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()