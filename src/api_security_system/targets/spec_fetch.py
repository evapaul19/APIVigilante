"""OpenAPI specification acquisition: explicit URL or common discovery paths.

Only same-origin URLs are fetched (enforced in .security). Redirects are
never followed. Retrieved documents are size-limited and must look like
an OpenAPI/Swagger document before they are accepted.
"""

from __future__ import annotations

import json
import uuid
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

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
    origin_of,
    resolve_target,
    validate_pinned_addresses,
    validate_resolved_target,
)

MAX_SPEC_BYTES = 5 * 1024 * 1024
SPEC_TIMEOUT_SECONDS = 4.0
MAX_DISCOVERY_PAGES = 20
MAX_DISCOVERED_ENDPOINTS = 100
MAX_DISCOVERY_DEPTH = 2
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
    discovery_mode: bool = False
    limitations: list[str] = field(default_factory=list)


def _origin(url: str) -> str:
    try:
        return origin_of(url)
    except (TargetValidationError, ValueError):
        return ""


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


class _HTMLLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.is_html = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "html":
            self.is_html = True
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self.is_html = True
            self.links.append(href)


def _discovery_scope_path(base_url: str) -> str:
    return urlsplit(base_url).path.rstrip("/")


def _within_discovery_scope(path: str, base_path: str) -> bool:
    return (
        not base_path
        or path == base_path
        or path.startswith(base_path + "/")
    )


def _discover_html_endpoints(
    base_url: str,
    addresses: Sequence[str],
) -> tuple[dict[str, dict], list[str]]:
    """Inventory only same-origin GET links exposed by bounded HTML traversal."""
    base_origin = _origin(base_url)
    base_path = _discovery_scope_path(base_url)
    start_url = base_url.rstrip("/") + "/"
    queue = deque([(start_url, 0)])
    queued = {start_url}
    visited: set[str] = set()
    paths: dict[str, dict] = {}
    link_queue_truncated = False
    pages_failed = 0
    non_html_pages = 0
    limitations = [
        "No usable OpenAPI document was found; inventory is limited to "
        "same-origin HTML links reachable within the bounded crawl."
    ]

    while queue and len(visited) < MAX_DISCOVERY_PAGES:
        current_url, depth = queue.popleft()
        if current_url in visited:
            continue
        visited.add(current_url)
        try:
            raw = _fetch(current_url, addresses)
        except SpecUnavailableError:
            pages_failed += 1
            continue

        text = raw.decode("utf-8", errors="replace")
        parser = _HTMLLinkParser()
        try:
            parser.feed(text)
        except ValueError:
            pages_failed += 1
            continue

        if not parser.is_html:
            non_html_pages += 1
            continue

        current_parts = urlsplit(current_url)
        current_path = current_parts.path or "/"
        if _within_discovery_scope(current_path.rstrip("/"), base_path):
            path_item = paths.setdefault(current_path, {})
            path_item.setdefault(
                "get",
                {
                    "operationId": f"discovered_get_{len(paths) + 1:03d}",
                    "responses": {"200": {"description": "Observed HTML route"}},
                    "x-apivigilante-discovery-source": "html_page",
                },
            )

        if depth >= MAX_DISCOVERY_DEPTH:
            continue
        for href in parser.links:
            if len(paths) >= MAX_DISCOVERED_ENDPOINTS:
                break
            candidate = urljoin(current_url, href.strip())
            parts = urlsplit(candidate)
            if parts.scheme.lower() not in {"http", "https"}:
                continue
            if parts.username is not None or parts.password is not None:
                continue
            if _origin(candidate) != base_origin:
                continue
            path = parts.path or "/"
            if not _within_discovery_scope(path.rstrip("/"), base_path):
                continue
            normalized = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
            if normalized not in queued and normalized not in visited:
                if len(queued) >= MAX_DISCOVERY_PAGES:
                    link_queue_truncated = True
                    continue
                queued.add(normalized)
                queue.append((normalized, depth + 1))

    if queue:
        limitations.append(
            f"HTML traversal stopped at the {MAX_DISCOVERY_PAGES}-page limit."
        )
    if link_queue_truncated:
        limitations.append(
            f"HTML link queue stopped at the {MAX_DISCOVERY_PAGES}-page limit."
        )
    if pages_failed:
        limitations.append(
            f"{pages_failed} page request(s) failed."
        )
    if non_html_pages:
        limitations.append(
            f"{non_html_pages} successful response(s) did not contain HTML links."
        )
    if len(paths) >= MAX_DISCOVERED_ENDPOINTS:
        limitations.append(
            f"Endpoint inventory stopped at the {MAX_DISCOVERED_ENDPOINTS}-endpoint limit."
        )
    if not paths:
        limitations.append(
            "No HTML pages or same-origin links were available to inventory; "
            "API routes not linked from an HTML page remain undiscovered."
        )

    return paths, limitations


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

    if not spec_url:
        discovered_paths, limitations = _discover_html_endpoints(base, addresses)
        document = {
            "openapi": "3.0.3",
            "info": {
                "title": "Bounded HTML-link discovery",
                "version": "1.0.0",
            },
            "servers": [{"url": base}],
            "paths": discovered_paths,
            "x-apivigilante-discovery": {
                "strategy": "same-origin-html-links",
                "pages_visited_limit": MAX_DISCOVERY_PAGES,
                "endpoint_limit": MAX_DISCOVERED_ENDPOINTS,
            },
        }
        raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
        return FetchedSpec(
            document=document,
            source_url=_safe_url(base.rstrip("/") + "/"),
            raw=raw,
            extension=".json",
            discovery_mode=True,
            limitations=limitations,
        )

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
