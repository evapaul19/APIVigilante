"""OpenAPI specification acquisition: explicit URL or common discovery paths.

Only same-origin URLs are fetched (enforced in .security). Redirects are
never followed. Retrieved documents are size-limited and must look like
an OpenAPI/Swagger document before they are accepted.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence
from urllib.parse import parse_qsl, urlsplit

import yaml

from api_security_system.request_executor import (
    ExecutionRequest,
    RequestExecutor,
    TargetOriginError,
    TransportError,
)

from .security import (
    ResolvedTarget,
    TargetValidationError,
    resolve_target,
    validate_pinned_addresses,
    validate_resolved_target,
)

MAX_SPEC_BYTES = 5 * 1024 * 1024
SPEC_TIMEOUT_SECONDS = 15.0
DISCOVERY_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/swagger/v1/swagger.json",
    "/swagger/v1/swagger.yaml",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
)

_PROJECT_ROOT = Path(__file__).resolve().parents[3]


class SpecUnavailableError(RuntimeError):
    """Raised when no usable OpenAPI document can be obtained for a target."""


@dataclass
class FetchedSpec:
    document: dict
    source_url: str
    raw: bytes
    extension: str


def _origin(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def _safe_url(url: str) -> str:
    """Avoid echoing query strings or userinfo in error text."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<invalid-url>"
    hostname = parts.hostname or ""
    host = f"[{hostname}]" if ":" in hostname else hostname
    try:
        port_number = parts.port
    except ValueError:
        port_number = None
    port = f":{port_number}" if port_number is not None else ""
    return f"{parts.scheme}://{host}{port}{parts.path}"


def _fetch(url: str, resolved_addresses: Sequence[str]) -> bytes:
    """Fetch one URL using addresses already validated for its origin."""
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise SpecUnavailableError(
            f"Could not fetch {_safe_url(url)}: invalid URL."
        ) from exc
    base_url = f"{parts.scheme}://{parts.netloc}"
    path = parts.path or "/"
    query_params = dict(parse_qsl(parts.query, keep_blank_values=True))
    safe_url = _safe_url(url)

    executor = None
    try:
        executor = RequestExecutor(
            base_url=base_url,
            pinned_addresses=resolved_addresses,
        )
        result = executor.execute(
            ExecutionRequest(
                method="GET",
                path=path,
                query_params=query_params,
                timeout_seconds=SPEC_TIMEOUT_SECONDS,
            )
        )
    except (TargetOriginError, TransportError, ValueError) as exc:
        raise SpecUnavailableError(
            f"Could not fetch {safe_url}: {type(exc).__name__}"
        ) from exc
    finally:
        if executor is not None:
            executor.close()

    if 300 <= result.response_status < 400:
        raise SpecUnavailableError(
            f"{safe_url} returned a redirect ({result.response_status}); "
            "redirects are not followed."
        )
    if result.response_status != 200:
        raise SpecUnavailableError(
            f"{safe_url} returned HTTP {result.response_status}."
        )

    if result.response_body_raw is not None:
        raw = result.response_body_raw.encode("utf-8")
    elif result.response_body is not None:
        raw = json.dumps(
            result.response_body,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    else:
        raw = b""

    if len(raw) > MAX_SPEC_BYTES:
        raise SpecUnavailableError(
            f"{safe_url} is larger than the {MAX_SPEC_BYTES} byte limit."
        )
    if not raw:
        raise SpecUnavailableError(f"{safe_url} returned an empty body.")

    return raw


def _parse_spec(raw: bytes) -> tuple[dict, str]:
    text = raw.decode("utf-8", errors="replace")

    document = None
    extension = None
    try:
        document = json.loads(text)
        extension = ".json"
    except (ValueError, RecursionError):
        try:
            document = yaml.safe_load(text)
            extension = ".yaml"
        except (yaml.YAMLError, RecursionError) as exc:
            raise SpecUnavailableError(
                f"Response is neither valid JSON nor valid YAML: {exc}"
            ) from exc

    if not isinstance(document, dict):
        raise SpecUnavailableError("Response is not an OpenAPI object.")
    if "paths" not in document or not isinstance(document.get("paths"), dict):
        raise SpecUnavailableError("Document has no 'paths' object.")
    if "openapi" not in document and "swagger" not in document:
        raise SpecUnavailableError(
            "Document is missing an 'openapi' or 'swagger' version field."
        )

    return document, extension


def acquire_spec(
    base_origin: str,
    spec_url: str | None = None,
    resolved_addresses: Sequence[str] | None = None,
    resolved_target: ResolvedTarget | None = None,
) -> FetchedSpec:
    """Fetch an OpenAPI document, using an explicit URL or discovery order.

    Every candidate must share the target origin. Connections are pinned
    to addresses validated for the target, so a later DNS answer cannot
    redirect the request. Spec acquisition still goes through
    RequestExecutor, so redirects, query strings, response limits, and
    transport errors have the same protections as other target requests.

    ``resolved_target`` is the preferred internal integration seam: it is
    the validated result returned by ``resolve_target()`` and is checked
    against the requested target URL without another DNS lookup.
    ``resolved_addresses`` remains for internal/backward compatibility, but
    it is now validated against the complete target policy before any
    connection is attempted. Neither argument is accepted from the public
    HTTP API, and direct callers must not forward untrusted values.
    """
    if resolved_addresses is not None and resolved_target is not None:
        raise TargetValidationError(
            "Provide resolved_target or resolved_addresses, not both."
        )

    base = base_origin.rstrip("/")
    target_origin = _origin(base)

    if resolved_target is not None:
        addresses = validate_resolved_target(base, resolved_target)
    elif resolved_addresses is None:
        addresses = resolve_target(base).addresses
    else:
        addresses = validate_pinned_addresses(base, resolved_addresses)

    if spec_url:
        candidate = str(spec_url).strip()
        if candidate.startswith("/"):
            candidate = target_origin + candidate
        elif not candidate.lower().startswith(("http://", "https://")):
            candidate = base + "/" + candidate.lstrip("/")
        candidates = [candidate]
    else:
        candidates = [base + path for path in DISCOVERY_PATHS]

    attempts: list[str] = []
    for candidate in candidates:
        if _origin(candidate) != target_origin:
            attempts.append(
                f"{_safe_url(candidate)} is outside the target origin."
            )
            continue
        try:
            raw = _fetch(candidate, addresses)
            document, extension = _parse_spec(raw)
            return FetchedSpec(
                document=document,
                source_url=_safe_url(candidate),
                raw=raw,
                extension=extension,
            )
        except SpecUnavailableError as exc:
            attempts.append(str(exc))

    raise SpecUnavailableError(
        "No usable OpenAPI specification was found. Attempted: "
        + "; ".join(attempts)
    )


def save_spec(spec: FetchedSpec) -> str:
    """Persist the fetched document under targets/ and return a relative path."""
    targets_dir = _PROJECT_ROOT / "targets"
    targets_dir.mkdir(parents=True, exist_ok=True)

    filename = f"fetched-{uuid.uuid4().hex[:12]}{spec.extension}"
    destination = targets_dir / filename
    destination.write_bytes(spec.raw)
    return destination.relative_to(_PROJECT_ROOT).as_posix()
