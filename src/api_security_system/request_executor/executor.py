
"""Deterministic HTTP request execution against a configured target.

This is the sole chokepoint through which the system sends HTTP
requests to a target under test. No LLM calls, no reasoning, no
decisions about what to test or which identity to use - send exactly
what the caller asks for, scoped strictly to the target's origin, and
return exactly what came back as structured evidence.

Does not depend on the database - constructed with a plain base_url
string (e.g. target.base_url), consistent with Recon's parser.py and
classifier.py being free of DB dependencies.
"""

import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import httpx

from .schemas import (
    ExecutionRequest,
    ExecutionResult,
    TargetOriginError,
    TransportError,
)


def _build_target_url(base_url: str, path: str) -> str:
    """Join a target base URL and relative path without changing origin.

    Reject absolute URLs, protocol-relative paths, embedded query strings,
    fragments, and literal dot-segments before constructing the final URL.
    Query parameters must be supplied separately through query_params.
    """
    if not isinstance(path, str) or not path:
        raise TargetOriginError("Path must be a non-empty relative URL path.")

    # Validate the ORIGINAL path before adding or changing any characters.
    # Otherwise, prepending "/" could hide an absolute URL's scheme.
    if path.startswith("//") or path.startswith("\\\\"):
        raise TargetOriginError(
            f"Protocol-relative paths are not allowed: {path!r}"
        )

    parsed_original = urlsplit(path)

    if parsed_original.scheme or parsed_original.netloc:
        raise TargetOriginError(
            f"Path must be relative to the target origin, got: {path!r}"
        )

    if parsed_original.query:
        raise TargetOriginError(
            "Path must not include a query string; use query_params instead."
        )

    if parsed_original.fragment:
        raise TargetOriginError("Path must not include a fragment.")

    # Reject literal dot-segments instead of silently normalizing them.
    original_segments = parsed_original.path.split("/")
    if any(segment in {".", ".."} for segment in original_segments):
        raise TargetOriginError(
            f"Path traversal is not allowed: {path!r}"
        )

    # Reject backslashes and control characters to avoid ambiguous URL parsing.
    if "\\" in path or any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise TargetOriginError(
            "Path must not contain backslashes or control characters."
        )

    normalized_input = (
        parsed_original.path
        if parsed_original.path.startswith("/")
        else "/" + parsed_original.path
    )

    base_parts = urlsplit(base_url)

    if (
        base_parts.scheme.lower() not in {"http", "https"}
        or not base_parts.netloc
        or base_parts.username is not None
        or base_parts.password is not None
        or base_parts.query
        or base_parts.fragment
    ):
        raise TargetOriginError(
            f"Target base_url is not a valid HTTP(S) origin URL: {base_url!r}"
        )

    # Ensure the configured URL itself has a valid hostname and port.
    try:
        hostname = base_parts.hostname
        _ = base_parts.port
    except ValueError as exc:
        raise TargetOriginError(
            "Target base_url contains an invalid hostname or port."
        ) from exc

    if not hostname:
        raise TargetOriginError(
            f"Target base_url must include a hostname: {base_url!r}"
        )

    # Preserve a configured base path, if present, without normalizing
    # away or concealing traversal in the caller-supplied path.
    combined_path = base_parts.path.rstrip("/") + normalized_input

    final_url = urlunsplit(
        (
            base_parts.scheme,
            base_parts.netloc,
            combined_path,
            "",
            "",
        )
    )

    # Defense in depth: confirm that the final URL retains the target origin.
    final_parts = urlsplit(final_url)

    if (
        final_parts.scheme.lower(),
        final_parts.netloc.lower(),
    ) != (
        base_parts.scheme.lower(),
        base_parts.netloc.lower(),
    ):
        raise TargetOriginError(
            "Resolved URL escapes the configured target origin."
        )

    return final_url


class RequestExecutor:
    """Send HTTP requests to a single configured target origin.

    Callers supply request headers, including authentication headers.
    This class does not manage identities, sessions, or tokens and does
    not persist results to the database.
    """

    def __init__(
        self,
        base_url: str,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        # Validate the configured base URL at construction time.
        parsed_base = urlsplit(base_url)

        if (
            parsed_base.scheme.lower() not in {"http", "https"}
            or not parsed_base.netloc
            or parsed_base.username is not None
            or parsed_base.password is not None
            or parsed_base.query
            or parsed_base.fragment
        ):
            raise TargetOriginError(
                f"Target base_url is not a valid HTTP(S) URL: {base_url!r}"
            )

        try:
            hostname = parsed_base.hostname
            _ = parsed_base.port
        except ValueError as exc:
            raise TargetOriginError(
                "Target base_url contains an invalid hostname or port."
            ) from exc

        if not hostname:
            raise TargetOriginError(
                "Target base_url must include a hostname."
            )

        self._base_url = base_url.rstrip("/")

        # Redirects remain disabled so credentials cannot be forwarded
        # automatically to another destination.
        self._client = httpx.Client(
            transport=transport,
            follow_redirects=False,
        )

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        url = _build_target_url(self._base_url, request.path)

        start = time.monotonic()

        try:
            response = self._client.request(
                method=request.method,
                url=url,
                headers=request.headers,
                params=request.query_params or None,
                json=request.json_body,
                timeout=request.timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            raise TransportError(
                f"Request timed out after {request.timeout_seconds}s: "
                f"{request.method} {request.path}"
            ) from exc
        except httpx.RequestError as exc:
            # Do not include the exception message: it could contain
            # sensitive request details.
            raise TransportError(
                f"Transport failure for {request.method} "
                f"{request.path}: {type(exc).__name__}"
            ) from exc

        elapsed_ms = int((time.monotonic() - start) * 1000)

        response_body: Optional[dict] = None
        response_body_raw: Optional[str] = None

        if response.content:
            try:
                parsed_body = response.json()
                if isinstance(parsed_body, dict):
                    response_body = parsed_body
                else:
                    # Preserve valid JSON arrays, strings, numbers, and
                    # booleans rather than silently discarding them.
                    response_body_raw = response.text
            except ValueError:
                response_body_raw = response.text

        return ExecutionResult(
            request_method=request.method,
            request_path=request.path,
            request_headers=dict(request.headers),
            request_body=request.json_body,
            response_status=response.status_code,
            response_headers=dict(response.headers),
            response_body=response_body,
            response_body_raw=response_body_raw,
            latency_ms=elapsed_ms,
            executed_at=datetime.now(timezone.utc),
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "RequestExecutor":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
