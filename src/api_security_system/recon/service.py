"""Recon orchestration: parse spec, persist endpoints, classify risk.

Accepts an existing scan_id - does not create Target/Scan records.

OpenAPI spec paths stored as relative (e.g. "targets/fetched-*.yaml")
are resolved against the project root so they work from any CWD.
"""

from pydantic import BaseModel, Field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit
from sqlmodel import select

from api_security_system.db import Endpoint, Scan, Target, get_session
from api_security_system.llm import LLMClient

# Resolve OpenAPI spec paths relative to project root so they work
# from any CWD (the target stores a relative path like "targets/fetched-*.yaml")
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent  # .../api-security-system

from .classifier import ClassificationError, classify_endpoint
from .parser import parse_openapi_spec_with_coverage
from .schemas import ParsedEndpoint, ReconCoverage


class ScanNotFoundError(Exception):
    """Raised when run_recon is called with a scan_id that doesn't exist.
    Recon never creates Target/Scan records implicitly."""

    def __init__(self, scan_id: int) -> None:
        self.scan_id = scan_id
        super().__init__(f"Scan {scan_id} does not exist.")


class ClassificationFailure(BaseModel):
    operation_id: str | None
    path: str
    error: str


class ReconResult(BaseModel):
    scan_id: int
    endpoints_found: int
    endpoints_inserted: int
    endpoints_skipped_duplicate: int
    classifications_succeeded: int
    classifications_failed: int
    classification_failures: list[ClassificationFailure] = []
    coverage: ReconCoverage = Field(default_factory=ReconCoverage)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def _normalized_prefix(value: str) -> Optional[str]:
    text = str(value or "").strip()
    if not text or "{" in text or "}" in text:
        return None

    parts = urlsplit(text)
    path = parts.path if (parts.scheme or parts.netloc) else text
    path = "/" + path.strip("/") if path.strip("/") else ""
    return path or None


def _spec_path_prefix(
    coverage: ReconCoverage, base_url: str
) -> tuple[Optional[str], Optional[str]]:
    """Return (prefix to apply, limitation) for this target.

    The target base URL remains authoritative. A spec prefix is only
    applied when it can be combined unambiguously with the target's
    existing path. OpenAPI server URLs are used only when they are
    relative or share the target origin.
    """
    candidates: list[str] = []
    if coverage.base_path:
        prefix = _normalized_prefix(coverage.base_path)
        if prefix:
            candidates.append(prefix)
    else:
        target_origin = _origin(base_url)
        for server in coverage.servers:
            parts = urlsplit(server)
            if (parts.scheme or parts.netloc) and _origin(server) != target_origin:
                continue
            prefix = _normalized_prefix(server)
            if prefix:
                candidates.append(prefix)

    distinct = sorted(set(candidates))
    if not distinct:
        return None, None
    if len(distinct) > 1:
        return None, (
            "Multiple distinct spec path prefixes were found; the target "
            "base_url remains authoritative and no prefix was applied."
        )

    prefix = distinct[0]
    target_path = "/" + urlsplit(base_url).path.strip("/")
    if target_path == "/":
        return prefix, None
    if prefix == target_path:
        return None, None
    if prefix.startswith(target_path + "/"):
        return prefix[len(target_path):], None
    return None, (
        "Spec path prefix "
        f"{prefix!r} conflicts with the target base path {target_path!r}; "
        "the target base_url remains authoritative."
    )


def _join_path_prefix(prefix: str, path: str) -> str:
    if path.strip("/") == "":
        return prefix
    if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
        return path
    return prefix.rstrip("/") + "/" + path.lstrip("/")


def _apply_spec_path_prefix(
    endpoints: list[ParsedEndpoint],
    coverage: ReconCoverage,
    base_url: str,
) -> None:
    prefix, limitation = _spec_path_prefix(coverage, base_url)
    if limitation:
        coverage.limitations.append(limitation)
    if not prefix:
        return

    for endpoint in endpoints:
        endpoint.path = _join_path_prefix(prefix, endpoint.path)

    coverage.applied_path_prefix = prefix
    coverage.limitations.append(
        "Applied spec path prefix "
        f"{prefix!r} because the target base_url did not already include it."
    )


def run_recon(
    scan_id: int,
    llm_client: LLMClient | None = None,
    classify: bool = True,
) -> ReconResult:
    """Run Recon for an existing scan: parse spec, persist endpoints, classify risk.

    Set classify=False to persist the deterministic endpoint inventory
    without calling the LLM. Raises ScanNotFoundError if scan_id does not
    exist. Raises SpecParseError (from parser.py) if the target's OpenAPI
    spec cannot be parsed.

    Reruns against the same scan_id skip (path, method) pairs already
    persisted for that scan - existing rows are NOT refreshed even if
    the underlying spec file has changed since the last run. This is
    accepted MVP behavior.
    """
    if classify:
        llm_client = llm_client or LLMClient()

    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ScanNotFoundError(scan_id)

        target = session.get(Target, scan.target_id)
        # Resolve openapi_spec_path relative to project root so it works
        # from any CWD (the target stores a relative path like "targets/fetched-*.yaml")
        spec_path = Path(target.openapi_spec_path)
        if not spec_path.is_absolute():
            spec_path = _PROJECT_ROOT / spec_path
        parsed = parse_openapi_spec_with_coverage(str(spec_path))
        parsed_endpoints = parsed.endpoints
        coverage = parsed.coverage
        _apply_spec_path_prefix(parsed_endpoints, coverage, target.base_url)

        existing_rows = session.exec(
            select(Endpoint.path, Endpoint.method).where(Endpoint.scan_id == scan_id)
        ).all()
        existing_keys = {(path, method) for path, method in existing_rows}

        to_classify: list[tuple[int, ParsedEndpoint]] = []
        inserted_count = 0
        skipped_count = 0

        for parsed_endpoint in parsed_endpoints:
            key = (parsed_endpoint.path, parsed_endpoint.method)
            if key in existing_keys:
                skipped_count += 1
                continue

            db_endpoint = Endpoint(
                scan_id=scan_id,
                path=parsed_endpoint.path,
                method=parsed_endpoint.method,
                operation_id=parsed_endpoint.operation_id,
                resource_type=parsed_endpoint.resource_type,
                id_param_name=parsed_endpoint.id_param_name,
                risk_classification=None,
                raw_spec_fragment=parsed_endpoint.raw_spec_fragment,
            )
            session.add(db_endpoint)
            session.flush()  # assigns db_endpoint.id without committing yet
            to_classify.append((db_endpoint.id, parsed_endpoint))
            inserted_count += 1

        session.commit()

    coverage.operations_inserted = inserted_count
    coverage.operations_skipped_duplicate = skipped_count
    coverage.operations_persisted = inserted_count + skipped_count

    # Phase 2: classification. Endpoint rows above are already committed -
    # a failure here never loses the deterministic inventory, only
    # leaves risk_classification=None for that row.
    succeeded = 0
    failures: list[ClassificationFailure] = []

    if not classify:
        return ReconResult(
            scan_id=scan_id,
            endpoints_found=len(parsed_endpoints),
            endpoints_inserted=inserted_count,
            endpoints_skipped_duplicate=skipped_count,
            classifications_succeeded=0,
            classifications_failed=0,
            classification_failures=[],
            coverage=coverage,
        )

    with get_session() as session:
        for endpoint_id, parsed in to_classify:
            try:
                classification = classify_endpoint(parsed, llm_client)
            except ClassificationError as exc:
                failures.append(
                    ClassificationFailure(
                        operation_id=parsed.operation_id,
                        path=parsed.path,
                        error=str(exc.original),
                    )
                )
                continue

            db_endpoint = session.get(Endpoint, endpoint_id)
            db_endpoint.risk_classification = classification.risk_level.value
            session.add(db_endpoint)
            succeeded += 1

        session.commit()

    return ReconResult(
        scan_id=scan_id,
        endpoints_found=len(parsed_endpoints),
        endpoints_inserted=inserted_count,
        endpoints_skipped_duplicate=skipped_count,
        classifications_succeeded=succeeded,
        classifications_failed=len(failures),
        classification_failures=failures,
        coverage=coverage,
    )
