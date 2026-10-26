
"""HTTP API for the API security assessment system."""

import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

from fastapi import BackgroundTasks, Request, Depends, FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlmodel import Session, select

from api_security_system.db import (
    AssessmentStage,
    Endpoint,
    Finding,
    FindingEvidence,
    Scan,
    ScanStatus,
    Target,
    TestExecution,
    TestIdentity,
    get_session,
)
from api_security_system.db.redaction import (
    redact_headers_for_persistence,
    sanitize_text_for_persistence,
)
from api_security_system.auth import AuthProfile
from api_security_system.recon.service import run_recon, ScanNotFoundError
from api_security_system.recon.parser import SpecParseError
from api_security_system.authz_bola.schemas import (
    BudgetExceededError,
    UnauthorizedTargetError,
)
from api_security_system.authz_bola.service import run_bola_check
from api_security_system.sensitive_data import sanitize_for_persistence
from api_security_system.reports import build_scan_report, humanize_finding
from api_security_system.targets import (
    DEFAULT_ASSESSMENT_REQUEST_BUDGET,
    AssessmentSchemaError,
    SpecUnavailableError,
    TargetValidationError,
    create_assessment,
    is_authorized_origin,
    provision_assessment,
    run_assessment,
)

logger = logging.getLogger(__name__)


def database_session():
    """Provide one database session for a request.

    A missing DATABASE_URL or an unavailable database must produce a clear
    503 instead of an unhandled dependency exception, so the frontend can
    distinguish a backend outage from an assessment error.
    """
    try:
        with get_session() as session:
            yield session
    except HTTPException:
        raise
    except (RuntimeError, SQLAlchemyError) as exc:
        logger.warning(
            "Database dependency unavailable: %s", type(exc).__name__
        )
        raise HTTPException(
            status_code=503,
            detail=(
                "Database unavailable. Verify PostgreSQL is running and "
                "DATABASE_URL points to the configured database."
            ),
        ) from exc


SessionDep = Annotated[Session, Depends(database_session)]


class ScanCreate(BaseModel):
    """Request body for creating a scan record."""

    target_id: int


class AssessmentCreate(BaseModel):
    """Options for the one-call URL-to-assessment flow.

    Active checks are opt-in. Without ``allow_identity_registration`` the
    assessment still discovers and persists endpoints but does not send
    registration, BOLA/BFLA, or sensitive-data requests. A target outside the
    operator allowlist also needs ``authorized_for_active_testing`` and the
    server-side ``APIVIGILANTE_ALLOW_USER_AUTHORIZED_TARGETS`` opt-in.
    """

    base_url: str = Field(
        min_length=1,
        description=(
            "User-supplied base URL of the API target. It must pass the "
            "project's SSRF policy. Active checks additionally require an "
            "operator-authorized origin, or the server-side user-authorized "
            "target opt-in plus per-assessment confirmation; other permitted "
            "targets are inventoried and report unsupported checks explicitly."
        ),
        examples=["https://api.example.com/v1"],
    )
    openapi_spec_url: str | None = Field(
        default=None,
        description=(
            "Optional explicit OpenAPI document URL, including a custom path. "
            "It must share the target origin; when omitted, common OpenAPI "
            "paths are tried before a bounded same-origin HTML-link inventory."
        ),
        examples=["https://api.example.com/v1/metadata/openapi.yaml"],
    )
    target_name: str | None = Field(
        default=None,
        description="Optional display name; defaults to the target origin.",
    )
    allow_identity_registration: bool = Field(
        default=False,
        description=(
            "Explicitly approve active testing. Required for identity "
            "registration, BOLA/BFLA, and sensitive-data requests."
        ),
    )
    authorized_for_active_testing: bool = Field(
        default=False,
        description=(
            "Per-assessment confirmation that the caller is authorized to "
            "send active requests to this target. Non-allowlisted origins "
            "also require APIVIGILANTE_ALLOW_USER_AUTHORIZED_TARGETS=1."
        ),
    )
    auth_profile: AuthProfile | None = Field(
        default=None,
        description=(
            "Optional identities and authentication scheme for targets that "
            "do not use the VAmPI register/login contract. Secrets are used "
            "in memory and are not persisted."
        ),
    )
    classify: bool = Field(
        default=True,
        description=(
            "Run optional LLM risk classification. Set false to persist the "
            "deterministic endpoint inventory without an LLM call."
        ),
    )
    request_budget: int = Field(
        default=DEFAULT_ASSESSMENT_REQUEST_BUDGET,
        ge=1,
        le=100,
        strict=True,
        description=(
            "Maximum target requests for BOLA/BFLA; sensitive-data checks use "
            "at most 20 from the same approved budget."
        ),
    )


class ScanResponse(BaseModel):
    """Public representation of a scan."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    status: ScanStatus
    started_at: datetime | None
    completed_at: datetime | None


class FindingResponse(BaseModel):
    """Public representation of a finding."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    endpoint_id: int
    finding_type: str
    severity: str
    description: str
    status: str
    confidence: float | None
    method: str | None = None
    path: str | None = None
    operation_id: str | None = None
    evidence_execution_ids: list[int] = Field(default_factory=list)
    title: str | None = None
    category_label: str | None = None
    what_happened: str | None = None
    why_it_matters: str | None = None
    impact: str | None = None
    remediation: str | None = None
    severity_reasoning: str | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize application resources when needed."""
    yield


app = FastAPI(
    title="APIVigilante API Security Assessment System",
    description=(
        "API assessment using an OpenAPI document or bounded same-origin "
        "HTML-link discovery, optional LLM classification, BOLA/BFLA checks, "
        "sensitive-data inspection, and persisted stage-aware reports. "
        "Active checks require explicit approval."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

_default_cors_origins = {
    "http://localhost:5173",
    "http://127.0.0.1:5173",
}
_configured_cors_origins = os.environ.get("APIVIGILANTE_CORS_ORIGINS")
_cors_origins = (
    sorted(_default_cors_origins)
    if _configured_cors_origins is None
    else [
        origin.strip()
        for origin in _configured_cors_origins.split(",")
        if origin.strip()
    ]
)
if "*" in _cors_origins:
    raise ValueError("APIVIGILANTE_CORS_ORIGINS must not contain '*'.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
):
    """Return validation locations/messages without echoing request secrets."""
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {
                    "type": error.get("type"),
                    "loc": list(error.get("loc", ())),
                    "msg": error.get("msg"),
                }
                for error in exc.errors()
            ]
        },
    )


@app.get("/health")
def health(session: SessionDep):
    """Report application and database health."""
    try:
        session.exec(text("SELECT 1"))
    except Exception as exc:
        logger.warning("Database health check failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=503,
            detail=(
                "Database unavailable. Verify PostgreSQL is running and "
                "DATABASE_URL points to the configured database."
            ),
        ) from exc

    return {"status": "ok", "database": "connected"}


def _assessment_http_error(exc: Exception) -> HTTPException:
    """Translate an assessment failure without echoing target or DB details."""
    if isinstance(exc, TargetValidationError):
        detail = sanitize_text_for_persistence(str(exc), max_length=1000) or (
            "The target URL is invalid or not allowed."
        )
        return HTTPException(status_code=400, detail=detail)
    if isinstance(exc, (SpecUnavailableError, SpecParseError)):
        detail = sanitize_text_for_persistence(str(exc), max_length=1000) or (
            "No usable OpenAPI specification was found."
        )
        return HTTPException(status_code=422, detail=detail)
    if isinstance(exc, AssessmentSchemaError):
        logger.warning(
            "Assessment could not initialize database state: %s",
            type(exc).__name__,
        )
        detail = sanitize_text_for_persistence(str(exc), max_length=1000) or (
            "The database schema is not ready; apply the pending migration."
        )
        return HTTPException(status_code=503, detail=detail)
    if isinstance(exc, SQLAlchemyError):
        logger.warning(
            "Assessment database operation failed: %s", type(exc).__name__
        )
        return HTTPException(
            status_code=503,
            detail=(
                "Database unavailable. Verify PostgreSQL is running and "
                "DATABASE_URL points to the configured database."
            ),
        )
    logger.error("Assessment request failed: %s", type(exc).__name__)
    return HTTPException(
        status_code=500,
        detail=f"Assessment failed ({type(exc).__name__}).",
    )


@app.post(
    "/assessments",
    response_model=dict,
    status_code=201,
    responses={
        400: {"description": "Invalid target URL or a spec URL from another origin."},
        422: {"description": "Invalid assessment options or an unusable OpenAPI spec."},
        503: {"description": "Database schema is not migrated or is unavailable."},
    },
)
def start_assessment(
    payload: AssessmentCreate,
    background_tasks: BackgroundTasks = None,
):
    """Create an assessment and run it without blocking the request.

    The target is validated and a scan row is created synchronously, so the
    caller receives a stable ``scan_id`` immediately. The slow stage pipeline
    (spec acquisition, discovery, checks, persistence) runs in the background
    and the frontend polls ``/scans/{scan_id}`` for the real status.

    Direct calls without FastAPI's background-task object still run
    synchronously, which keeps the function usable as a plain integration
    entry point and in tests.
    """
    stage_kwargs = {
        "allow_identity_registration": payload.allow_identity_registration,
        "classify": payload.classify,
        "request_budget": payload.request_budget,
        "auth_profile": payload.auth_profile,
        "authorized_for_active_testing": payload.authorized_for_active_testing,
    }

    if background_tasks is None:
        try:
            return create_assessment(
                base_url=payload.base_url,
                openapi_spec_url=payload.openapi_spec_url,
                target_name=payload.target_name,
                **stage_kwargs,
            )
        except Exception as exc:  # noqa: BLE001 - mapped to a safe HTTP error
            raise _assessment_http_error(exc) from exc

    try:
        provisioned = provision_assessment(
            base_url=payload.base_url,
            openapi_spec_url=payload.openapi_spec_url,
            target_name=payload.target_name,
        )
    except Exception as exc:  # noqa: BLE001 - mapped to a safe HTTP error
        raise _assessment_http_error(exc) from exc

    background_tasks.add_task(run_assessment, provisioned, **stage_kwargs)

    return {
        "scan_id": provisioned.scan_id,
        "target_id": provisioned.target_id,
        "target": {
            "id": provisioned.target_id,
            "name": provisioned.display_name,
            "base_url": provisioned.base_url,
        },
        "base_url": provisioned.base_url,
        "origin": provisioned.origin,
        "spec_source": provisioned.spec_url,
        "status": ScanStatus.PENDING.value,
        "findings_count": 0,
        "findings": [],
        "findings_persisted": 0,
        "stages": {},
        "message": (
            "Assessment created. Poll the scan status; the report becomes "
            "available when the scan reaches a terminal status."
        ),
    }


@app.post("/scans", response_model=ScanResponse, status_code=201)
def create_scan(payload: ScanCreate, session: SessionDep):
    """Create a pending scan for an existing target."""
    target = session.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = Scan(
        target_id=target.id,
        status=ScanStatus.PENDING,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    return scan


@app.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, session: SessionDep):
    """Retrieve a scan's current lifecycle state."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@app.get("/scans/{scan_id}/findings", response_model=list[FindingResponse])
def get_scan_findings(scan_id: int, session: SessionDep):
    """List findings persisted for a scan, with plain-language context."""
    if session.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = session.exec(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.id)
    ).all()
    endpoints = {
        endpoint.id: endpoint
        for endpoint in session.exec(
            select(Endpoint).where(Endpoint.scan_id == scan_id)
        ).all()
    }
    evidence_ids: dict[int, list[int]] = {}
    if findings:
        for link in session.exec(
            select(FindingEvidence).where(
                FindingEvidence.finding_id.in_(
                    [finding.id for finding in findings]
                )
            )
        ).all():
            evidence_ids.setdefault(link.finding_id, []).append(
                link.execution_id
            )

    def _enum_value(value):
        return getattr(value, "value", value)

    items: list[FindingResponse] = []
    for finding in findings:
        endpoint = endpoints.get(finding.endpoint_id)
        description = (
            sanitize_text_for_persistence(finding.description, max_length=2000)
            or ""
        )
        enriched = humanize_finding(
            finding_type=_enum_value(finding.finding_type),
            severity=_enum_value(finding.severity),
            status=_enum_value(finding.status),
            description=description,
            method=endpoint.method if endpoint else None,
            path=endpoint.path if endpoint else None,
        )
        items.append(
            FindingResponse(
                id=finding.id,
                scan_id=finding.scan_id,
                endpoint_id=finding.endpoint_id,
                finding_type=_enum_value(finding.finding_type),
                severity=_enum_value(finding.severity),
                description=description,
                status=_enum_value(finding.status),
                confidence=finding.confidence,
                method=endpoint.method if endpoint else None,
                path=endpoint.path if endpoint else None,
                operation_id=endpoint.operation_id if endpoint else None,
                evidence_execution_ids=sorted(
                    evidence_ids.get(finding.id, [])
                ),
                title=enriched["title"],
                category_label=enriched["category_label"],
                what_happened=enriched["what_happened"],
                why_it_matters=enriched["why_it_matters"],
                impact=enriched["impact"],
                remediation=enriched["remediation"],
                severity_reasoning=enriched["severity_reasoning"],
            )
        )

    return items


@app.get("/scans/{scan_id}/report", response_model=dict)
def get_scan_report(scan_id: int, session: SessionDep):
    """Return the persisted, human-readable report for a scan.

    The report is assembled from the findings, evidence, endpoint inventory,
    and assessment-stage rows already persisted by the assessment. It is not
    available while the assessment is still running, so a partial report is
    never mistaken for a final result.
    """
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(
            status_code=409,
            detail=(
                "The assessment is still running. The report is available "
                "after the scan reaches a terminal status."
            ),
        )

    try:
        report = build_scan_report(scan_id, session)
    except SQLAlchemyError as exc:
        logger.error("Report generation failed for scan %s: %s", scan_id, type(exc).__name__)
        raise HTTPException(
            status_code=503,
            detail=(
                "The report could not be generated because the database "
                "request failed. The persisted findings are unchanged; retry "
                "once the database is available."
            ),
        ) from exc

    if report is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return report


@app.post("/scans/{scan_id}/recon", response_model=dict)
def trigger_recon(scan_id: int, session: SessionDep):
    """Explicitly trigger reconnaissance for an existing scan.

    Parses the target's OpenAPI specification, persists the endpoint
    inventory, and runs LLM-based risk classification. The deterministic
    inventory is preserved if classification fails. This endpoint does not
    persist assessment-stage metadata or mark the scan completed; use
    ``POST /assessments`` for the stage-aware one-call flow.
    """
    from api_security_system.llm import LLMClient

    # Ensure scan exists
    if session.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    llm_client = LLMClient()
    try:
        result = run_recon(scan_id, llm_client=llm_client)
    except ScanNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found") from None
    except SpecParseError as exc:
        detail = sanitize_text_for_persistence(str(exc), max_length=1000) or (
            "The OpenAPI specification could not be parsed."
        )
        raise HTTPException(status_code=422, detail=detail) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=422,
            detail="The OpenAPI specification could not be read.",
        ) from exc

    # Update scan started/completed timestamps for the recon stage
    scan = session.get(Scan, scan_id)
    if scan.started_at is None:
        from datetime import datetime, timezone
        scan.started_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()

    return {
        "scan_id": scan_id,
        "endpoints_found": result.endpoints_found,
        "endpoints_inserted": result.endpoints_inserted,
        "endpoints_skipped_duplicate": result.endpoints_skipped_duplicate,
        "classifications_succeeded": result.classifications_succeeded,
        "classifications_failed": result.classifications_failed,
        "coverage": result.coverage.model_dump(),
        "stage": "recon_complete",
    }


@app.post("/scans/{scan_id}/bola-check", response_model=dict)
def trigger_bola_check(scan_id: int, session: SessionDep, request: Request):
    """Run BOLA and BFLA security checks against the scan's user endpoints.

    Requires allow_identity_registration=True to register disposable identities.
    Runs BOLA tests (update_email, update_password, delete_user) and then BFLA
    tests for operations documented as administrator-only.

    Returns endpoint results with outcomes (access_denied, confirmed, ambiguous,
    ruled_out, not_applicable) and any confirmed findings.
    """
    allow_identity_registration = request.query_params.get("allow_identity_registration", "false").lower() == "true"
    try:
        request_budget = int(
            request.query_params.get(
                "request_budget", str(DEFAULT_ASSESSMENT_REQUEST_BUDGET)
            )
        )
    except ValueError:
        raise HTTPException(status_code=422, detail="request_budget must be an integer.")
    if not (1 <= request_budget <= 100):
        raise HTTPException(
            status_code=422, detail="request_budget must be between 1 and 100."
        )

    try:
        result = run_bola_check(
            scan_id,
            allow_identity_registration=allow_identity_registration,
            request_budget=request_budget,
        )
        return {
            "scan_id": result.scan_id,
            "target_base_url": result.target_base_url,
            "requests_used": result.requests_used,
            "request_budget": result.request_budget,
            "endpoint_results": [
                {
                    "operation_id": er.operation_id,
                    "path": er.path,
                    "check_type": er.check_type,
                    "outcome": er.outcome,
                    "rationale": sanitize_text_for_persistence(
                        er.rationale, max_length=2000
                    ),
                    "finding_id": er.finding_id,
                }
                for er in result.endpoint_results
            ],
            "bfla_status": result.bfla_status,
            "bfla_reason": sanitize_text_for_persistence(
                result.bfla_reason, max_length=1000
            ),
            "bfla_results": [
                {
                    "operation_id": er.operation_id,
                    "path": er.path,
                    "check_type": er.check_type,
                    "outcome": er.outcome,
                    "rationale": sanitize_text_for_persistence(
                        er.rationale, max_length=2000
                    ),
                    "finding_id": er.finding_id,
                }
                for er in result.bfla_results
            ],
            "stopped_early": result.stopped_early,
            "stopped_reason": sanitize_text_for_persistence(
                result.stopped_reason, max_length=1000
            ),
        }
    except TargetValidationError as exc:
        detail = sanitize_text_for_persistence(str(exc), max_length=1000) or (
            "The scan target could not be validated."
        )
        raise HTTPException(status_code=400, detail=detail) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc
    except UnauthorizedTargetError as exc:
        detail = sanitize_text_for_persistence(str(exc), max_length=1000) or (
            "Authorization checks are not allowed for this target."
        )
        raise HTTPException(status_code=403, detail=detail) from exc
    except PermissionError as exc:
        detail = sanitize_text_for_persistence(str(exc), max_length=1000) or (
            "Explicit approval is required for active checks."
        )
        raise HTTPException(status_code=403, detail=detail) from exc
    except BudgetExceededError as exc:
        detail = sanitize_text_for_persistence(str(exc), max_length=1000) or (
            "The request budget was exhausted."
        )
        raise HTTPException(status_code=409, detail=detail) from exc
    except Exception as exc:
        # Do not echo exception text: transport/API errors may contain URLs,
        # headers, or response fragments. The exception type is enough to
        # diagnose the failure without leaking target data.
        raise HTTPException(
            status_code=500,
            detail=f"BOLA check failed ({type(exc).__name__}).",
        ) from exc
