"""Recon orchestration: parse spec, persist endpoints, classify risk.

Accepts an existing scan_id - does not create Target/Scan records.

OpenAPI spec paths stored as relative (e.g. "targets/vampi-openapi.yml")
are resolved against the project root so they work from any CWD.
"""

from pydantic import BaseModel
from pathlib import Path
from sqlmodel import select

from api_security_system.db import Endpoint, Scan, Target, get_session
from api_security_system.llm import LLMClient

# Resolve OpenAPI spec paths relative to project root so they work
# from any CWD (the target stores a relative path like "targets/vampi-openapi.yml")
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent  # .../api-security-system

from .classifier import ClassificationError, classify_endpoint
from .parser import parse_openapi_spec
from .schemas import ParsedEndpoint


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


def run_recon(scan_id: int, llm_client: LLMClient | None = None) -> ReconResult:
    """Run Recon for an existing scan: parse spec, persist endpoints, classify risk.

    Raises ScanNotFoundError if scan_id does not exist.
    Raises SpecParseError (from parser.py) if the target's OpenAPI
    spec cannot be parsed.

    Reruns against the same scan_id skip (path, method) pairs already
    persisted for that scan - existing rows are NOT refreshed even if
    the underlying spec file has changed since the last run. This is
    accepted MVP behavior.
    """
    llm_client = llm_client or LLMClient()

    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ScanNotFoundError(scan_id)

        target = session.get(Target, scan.target_id)
        # Resolve openapi_spec_path relative to project root so it works
        # from any CWD (the target stores a relative path like "targets/vampi-openapi.yml")
        spec_path = Path(target.openapi_spec_path)
        if not spec_path.is_absolute():
            spec_path = _PROJECT_ROOT / spec_path
        parsed_endpoints = parse_openapi_spec(str(spec_path))

        existing_rows = session.exec(
            select(Endpoint.path, Endpoint.method).where(Endpoint.scan_id == scan_id)
        ).all()
        existing_keys = {(path, method) for path, method in existing_rows}

        to_classify: list[tuple[int, ParsedEndpoint]] = []
        inserted_count = 0
        skipped_count = 0

        for parsed in parsed_endpoints:
            key = (parsed.path, parsed.method)
            if key in existing_keys:
                skipped_count += 1
                continue

            db_endpoint = Endpoint(
                scan_id=scan_id,
                path=parsed.path,
                method=parsed.method,
                operation_id=parsed.operation_id,
                resource_type=parsed.resource_type,
                id_param_name=parsed.id_param_name,
                risk_classification=None,
                raw_spec_fragment=parsed.raw_spec_fragment,
            )
            session.add(db_endpoint)
            session.flush()  # assigns db_endpoint.id without committing yet
            to_classify.append((db_endpoint.id, parsed))
            inserted_count += 1

        session.commit()

    # Phase 2: classification. Endpoint rows above are already committed -
    # a failure here never loses the deterministic inventory, only
    # leaves risk_classification=None for that row.
    succeeded = 0
    failures: list[ClassificationFailure] = []

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
    )