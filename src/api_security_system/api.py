
"""HTTP API for the API security assessment system."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Request, Depends, FastAPI, HTTPException
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
from api_security_system.recon.service import run_recon, ScanNotFoundError
from api_security_system.recon.parser import SpecParseError
from api_security_system.authz_bola.schemas import (
    BudgetExceededError,
    UnauthorizedTargetError,
)
from api_security_system.authz_bola.service import run_bola_check
from api_security_system.sensitive_data import sanitize_for_persistence
from api_security_system.targets import (
    DEFAULT_ASSESSMENT_REQUEST_BUDGET,
    AssessmentSchemaError,
    SpecUnavailableError,
    TargetValidationError,
    create_assessment,
    is_authorized_origin,
)


def _sanitize_report_details(value):
    if isinstance(value, dict):
        return {key: _sanitize_report_details(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_report_details(item) for item in value]
    if isinstance(value, str):
        return sanitize_text_for_persistence(value, max_length=1000)
    return value


def database_session():
    """Provide one database session for a request."""
    with get_session() as session:
        yield session


SessionDep = Annotated[Session, Depends(database_session)]


class ScanCreate(BaseModel):
    """Request body for creating a scan record."""

    target_id: int


class AssessmentCreate(BaseModel):
    """Options for the one-call URL-to-assessment flow.

    Active checks are opt-in. Without ``allow_identity_registration`` the
    assessment still discovers and persists endpoints but does not send
    registration, BOLA/BFLA, or sensitive-data requests.
    """

    base_url: str = Field(
        min_length=1,
        description=(
            "Base URL of the authorized API target. Active checks require an "
            "explicitly allowlisted origin, such as http://localhost:5000 or "
            "the opt-in http://127.0.0.1:5001 test API."
        ),
        examples=["http://127.0.0.1:5001"],
    )
    openapi_spec_url: str | None = Field(
        default=None,
        description=(
            "Optional explicit OpenAPI document URL. It must share the "
            "target origin; when omitted, common discovery paths are tried."
        ),
        examples=["http://127.0.0.1:5001/openapi.json"],
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize application resources when needed."""
    yield


app = FastAPI(
    title="APIVigilante API Security Assessment System",
    description=(
        "OpenAPI-driven API assessment: discovery, optional LLM "
        "classification, BOLA/BFLA checks, sensitive-data inspection, and "
        "persisted stage-aware reports. Active checks require explicit approval."
    ),
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health(session: SessionDep):
    """Report application and database health."""
    try:
        session.exec(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        ) from exc

    return {"status": "ok", "database": "connected"}


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
def start_assessment(payload: AssessmentCreate):
    """Run a complete assessment from a user-supplied authorized URL.

    This is the main integration endpoint. It creates a target and scan,
    acquires the OpenAPI document (explicit URL or common discovery paths),
    persists the endpoint inventory, optionally runs LLM classification,
    builds the resource graph, and runs supported authorization and
    sensitive-data checks only when ``allow_identity_registration`` is true.

    Every stage outcome is returned explicitly, including skipped,
    unsupported, partial, and failed states. The response also links to the
    stage-aware report at ``/scans/{scan_id}/report``.
    """
    try:
        result = create_assessment(
            base_url=payload.base_url,
            openapi_spec_url=payload.openapi_spec_url,
            target_name=payload.target_name,
            allow_identity_registration=payload.allow_identity_registration,
            classify=payload.classify,
            request_budget=payload.request_budget,
        )
    except TargetValidationError as exc:
        detail = sanitize_text_for_persistence(str(exc), max_length=1000) or (
            "The target URL is invalid or not allowed."
        )
        raise HTTPException(status_code=400, detail=detail) from exc
    except SpecUnavailableError as exc:
        detail = sanitize_text_for_persistence(str(exc), max_length=1000) or (
            "No usable OpenAPI specification was found."
        )
        raise HTTPException(status_code=422, detail=detail) from exc
    except SpecParseError as exc:
        detail = sanitize_text_for_persistence(str(exc), max_length=1000) or (
            "The OpenAPI specification could not be parsed."
        )
        raise HTTPException(status_code=422, detail=detail) from exc
    except AssessmentSchemaError as exc:
        detail = sanitize_text_for_persistence(str(exc), max_length=1000) or (
            "The database schema is not ready; apply the pending migration."
        )
        raise HTTPException(status_code=503, detail=detail) from exc
    except Exception as exc:  # noqa: BLE001 - do not echo target/DB details
        raise HTTPException(
            status_code=500,
            detail=f"Assessment failed ({type(exc).__name__}).",
        ) from exc

    return result


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
    """List findings persisted for a scan."""
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

    return [
        FindingResponse(
            id=finding.id,
            scan_id=finding.scan_id,
            endpoint_id=finding.endpoint_id,
            finding_type=_enum_value(finding.finding_type),
            severity=_enum_value(finding.severity),
            description=(
                sanitize_text_for_persistence(finding.description, max_length=2000)
                or ""
            ),
            status=_enum_value(finding.status),
            confidence=finding.confidence,
            method=(
                endpoints[finding.endpoint_id].method
                if finding.endpoint_id in endpoints
                else None
            ),
            path=(
                endpoints[finding.endpoint_id].path
                if finding.endpoint_id in endpoints
                else None
            ),
            operation_id=(
                endpoints[finding.endpoint_id].operation_id
                if finding.endpoint_id in endpoints
                else None
            ),
            evidence_execution_ids=sorted(
                evidence_ids.get(finding.id, [])
            ),
        )
        for finding in findings
    ]


@app.get("/scans/{scan_id}/report", response_model=dict)
def get_scan_report(scan_id: int, session: SessionDep):
    """Generate a comprehensive report for a scan.

    Combines persisted assessment-stage outcomes with findings, sanitized
    evidence, endpoint inventory, and check results. Stage statuses come
    from the original assessment, so skipped, unsupported, partial, failed,
    and not-applicable checks are not confused with clean results.
    """
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    target = session.get(Target, scan.target_id)

    # Endpoint inventory and classification coverage
    endpoints = session.exec(
        select(Endpoint).where(Endpoint.scan_id == scan_id)
    ).all()
    total_endpoints = len(endpoints)
    endpoints_by_id = {endpoint.id: endpoint for endpoint in endpoints}
    classified_endpoints = sum(
        1 for e in endpoints if e.risk_classification is not None
    )
    classification_rate = (
        f"{classified_endpoints / total_endpoints * 100:.1f}%"
        if total_endpoints > 0
        else "0%"
    )

    # Persisted stage outcomes are the authoritative record of what the
    # original assessment attempted. Findings alone cannot distinguish a
    # clean result from a skipped, unsupported, or failed check.
    stage_rows = session.exec(
        select(AssessmentStage)
        .where(AssessmentStage.scan_id == scan_id)
        .order_by(AssessmentStage.sequence)
    ).all()
    persisted_stages: dict[str, dict] = {}
    for stage_row in stage_rows:
        entry = _sanitize_report_details(
            sanitize_for_persistence(dict(stage_row.details or {}))
        )
        entry["status"] = stage_row.status
        entry["reason"] = sanitize_text_for_persistence(
            stage_row.reason, max_length=1000
        )
        persisted_stages[stage_row.stage_name] = entry

    # Resource-graph summary: prefer the persisted stage outcome so a
    # failed or never-built graph is not silently reconstructed as success.
    resource_graph_summary = None
    resource_stage = persisted_stages.get("resource_graph")
    if resource_stage and resource_stage.get("status") == "built":
        resource_graph_summary = {
            "resources": resource_stage.get("resources", []),
            "endpoint_count": resource_stage.get("endpoint_count", 0),
            "edge_count": resource_stage.get("edge_count", 0),
            "identifies_count": resource_stage.get("identifies_count", 0),
            "may_relate_count": resource_stage.get("may_relate_count", 0),
        }
    elif resource_stage is None and endpoints:
        # Backward compatibility for scans recorded before stage persistence.
        from api_security_system.resource_graph.builder import (
            build_resource_graph_from_endpoints,
        )

        try:
            graph = build_resource_graph_from_endpoints(
                scan_id=scan_id,
                endpoints=list(endpoints),
            )
        except Exception:
            # Legacy endpoints may not contain enough information for graph
            # construction. Do not fabricate a successful summary.
            resource_graph_summary = None
        else:
            resource_graph_summary = {
                "resources": sorted(graph.resources.keys()),
                "endpoint_count": len(graph.endpoints),
                "edge_count": len(graph.edges),
                "identifies_count": sum(
                    1 for e in graph.edges if e.relation.name == "IDENTIFIES"
                ),
                "may_relate_count": sum(
                    1 for e in graph.edges if e.relation.name == "MAY_RELATE"
                ),
            }

    # Security-test execution evidence and findings
    findings = session.exec(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.id)
    ).all()

    def _enum_value(item):
        return getattr(item, "value", item)

    findings_by_severity: dict[str, int] = {}
    findings_by_status: dict[str, int] = {}
    findings_by_type: dict[str, int] = {}
    for f in findings:
        sev = _enum_value(f.severity) or "unknown"
        findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
        status = _enum_value(f.status) or "unknown"
        findings_by_status[status] = findings_by_status.get(status, 0) + 1
        ftype = _enum_value(f.finding_type) or "unknown"
        findings_by_type[ftype] = findings_by_type.get(ftype, 0) + 1

    executions = session.exec(
        select(TestExecution).where(TestExecution.scan_id == scan_id)
    ).all()
    identities = session.exec(
        select(TestIdentity).where(TestIdentity.scan_id == scan_id)
    ).all()

    # Consolidated finding details with sanitized, persisted evidence.
    executions_by_id = {execution.id: execution for execution in executions}
    evidence_ids_by_finding: dict[int, list[int]] = {}
    if findings:
        evidence_links = session.exec(
            select(FindingEvidence).where(
                FindingEvidence.finding_id.in_(
                    [finding.id for finding in findings]
                )
            )
        ).all()
        for link in evidence_links:
            evidence_ids_by_finding.setdefault(link.finding_id, []).append(
                link.execution_id
            )

    finding_details = []
    for finding in findings:
        endpoint = endpoints_by_id.get(finding.endpoint_id)
        evidence = []
        for execution_id in sorted(
            evidence_ids_by_finding.get(finding.id, [])
        ):
            execution = executions_by_id.get(execution_id)
            if execution is None:
                continue
            evidence.append(
                {
                    "execution_id": execution.id,
                    "response_status": execution.response_status,
                    "request_headers": sanitize_for_persistence(
                        redact_headers_for_persistence(
                            execution.request_headers or {}
                        )
                    ),
                    "request_body": sanitize_for_persistence(
                        execution.request_body
                    ),
                    "response_headers": sanitize_for_persistence(
                        redact_headers_for_persistence(
                            execution.response_headers or {}
                        )
                    ),
                    "response_body": sanitize_for_persistence(
                        execution.response_body
                    ),
                    "executed_at": (
                        str(execution.executed_at)
                        if execution.executed_at
                        else None
                    ),
                }
            )

        finding_details.append(
            {
                "id": finding.id,
                "finding_type": _enum_value(finding.finding_type),
                "severity": _enum_value(finding.severity),
                "status": _enum_value(finding.status),
                "confidence": finding.confidence,
                "description": sanitize_text_for_persistence(
                    finding.description, max_length=2000
                ),
                "endpoint": {
                    "id": finding.endpoint_id,
                    "method": endpoint.method if endpoint else None,
                    "path": endpoint.path if endpoint else None,
                    "operation_id": (
                        endpoint.operation_id if endpoint else None
                    ),
                },
                "evidence": evidence,
            }
        )

    scan_status = _enum_value(scan.status)
    authorization_supported = bool(
        target and is_authorized_origin(target.base_url)
    )

    # Sensitive-data inspections use their own identity label and must not
    # make BOLA/BFLA look like they ran.
    auth_identity_ids = {
        i.id
        for i in identities
        if str(i.role_label or "").startswith(("bola_", "bfla_"))
    }
    auth_executions = [e for e in executions if e.identity_id in auth_identity_ids]

    authorization_stage = persisted_stages.get("authorization_checks")
    if (
        authorization_stage
        and authorization_stage.get("supported_for_target") is not None
    ):
        authorization_supported = bool(
            authorization_stage.get("supported_for_target")
        )
    if authorization_stage:
        authorization_status = authorization_stage.get("status", "unknown")
        authorization_note = authorization_stage.get("reason")
    elif auth_executions:
        authorization_status = "performed"
        authorization_note = None
    elif authorization_supported:
        authorization_status = "not_run"
        authorization_note = "Identity registration was not approved."
    else:
        authorization_status = "not_supported"
        authorization_note = (
            "Only explicitly allowlisted origins support authorization checks. "
            "Other targets were inventoried only."
        )

    has_classified_endpoints = classified_endpoints > 0
    findings_populated = len(findings) > 0

    # BFLA outcomes are persisted as evidence and as the original stage
    # outcome; findings alone cannot distinguish not-run from not-applicable.
    bfla_identities = [
        i for i in identities if str(i.role_label or "").startswith("bfla_")
    ]
    bfla_findings = [
        f for f in findings if _enum_value(f.finding_type) == "bfla"
    ]
    bfla_outcome = (
        authorization_stage.get("bfla_status")
        if authorization_stage
        else None
    )
    bfla_reason = (
        authorization_stage.get("bfla_reason")
        if authorization_stage
        else None
    )
    bfla_has_confirmed = any(
        _enum_value(f.status) == "confirmed" for f in bfla_findings
    )
    bfla_has_candidate = any(
        _enum_value(f.status) == "candidate" for f in bfla_findings
    )
    if authorization_stage and bfla_outcome:
        if bfla_has_confirmed:
            bfla_status = "finding_confirmed"
        elif bfla_has_candidate:
            bfla_status = "candidate"
        elif bfla_outcome == "performed":
            bfla_status = "ran_no_finding"
        else:
            bfla_status = bfla_outcome
        bfla_note = bfla_reason
    elif authorization_stage and authorization_stage.get("status") == "failed":
        bfla_status = "failed"
        bfla_note = authorization_stage.get("reason")
    elif not authorization_supported:
        bfla_status = "not_supported"
        bfla_note = "BFLA checks are only enabled for the authorized origin."
    elif bfla_has_confirmed:
        bfla_status = "finding_confirmed"
        bfla_note = None
    elif bfla_has_candidate:
        bfla_status = "candidate"
        bfla_note = (
            "BFLA evidence was inconclusive; the finding is a candidate, "
            "not a confirmed privilege-boundary violation."
        )
    elif bfla_identities:
        bfla_status = "ran_no_finding"
        bfla_note = (
            "BFLA checks ran and produced no confirmed finding; recorded "
            "outcomes are in the BFLA execution evidence."
        )
    else:
        bfla_status = "not_run"
        bfla_note = (
            "No BFLA identities were recorded and no persisted BFLA outcome "
            "is available for this scan."
        )

    sensitive_identities = [
        i for i in identities if str(i.role_label or "").startswith("sensitive_data_")
    ]
    sensitive_findings = [
        f for f in findings if _enum_value(f.finding_type) == "sensitive_data"
    ]
    sensitive_confirmed = [
        f for f in sensitive_findings if _enum_value(f.status) == "confirmed"
    ]
    sensitive_candidates = [
        f for f in sensitive_findings if _enum_value(f.status) == "candidate"
    ]
    sensitive_stage = persisted_stages.get("sensitive_data_checks")
    sensitive_outcome = (
        sensitive_stage.get("status") if sensitive_stage else None
    )
    if sensitive_confirmed:
        sensitive_status = "finding_confirmed"
        sensitive_note = None
    elif sensitive_candidates:
        sensitive_status = "candidate"
        sensitive_note = (
            "Sensitive-looking data was observed, but the evidence does not "
            "establish that disclosure was inappropriate."
        )
    elif sensitive_stage and sensitive_outcome in {
        "failed",
        "not_run",
        "not_supported",
        "not_applicable",
        "unsupported",
        "stopped_early",
        "partial",
    }:
        sensitive_status = sensitive_outcome
        sensitive_note = sensitive_stage.get("reason")
    elif sensitive_stage and sensitive_outcome == "performed":
        sensitive_status = "ran_no_finding"
        sensitive_note = (
            "Responses were inspected and no confirmed or candidate "
            "sensitive-data exposure was recorded."
        )
    elif not authorization_supported:
        sensitive_status = "not_supported"
        sensitive_note = (
            "Sensitive-data checks are only enabled for the authorized origin."
        )
    elif sensitive_identities:
        sensitive_status = "ran_no_finding"
        sensitive_note = (
            "Responses were inspected and no confirmed or candidate "
            "sensitive-data exposure was recorded."
        )
    else:
        sensitive_status = "not_run"
        sensitive_note = (
            "Sensitive-data checks did not run, or no inspection identity "
            "was recorded."
        )

    incomplete_reasons: list[str] = []
    if scan_status != ScanStatus.COMPLETED.value:
        incomplete_reasons.append(f"Scan status is '{scan_status}', not 'completed'.")
    if total_endpoints == 0:
        incomplete_reasons.append(
            "No endpoints were discovered; the spec was not usable."
        )

    classification_stage = persisted_stages.get("classification")
    if classification_stage:
        classification_outcome = classification_stage.get("status")
        if classification_outcome in {"partial", "failed"}:
            incomplete_reasons.append(
                classification_stage.get("reason")
                or "Risk classification did not complete."
            )
    elif total_endpoints > 0 and classified_endpoints == 0:
        incomplete_reasons.append(
            "Risk classification did not complete (classification is optional "
            "for deterministic checks but the inventory is unclassified)."
        )

    if authorization_stage:
        if authorization_status in {
            "failed",
            "partial",
            "unsupported",
            "not_supported",
            "stopped_early",
            "not_run",
        }:
            incomplete_reasons.append(
                authorization_stage.get("reason")
                or "Authorization checks did not complete."
            )
        if authorization_stage.get("bfla_status") in {
            "unsupported",
            "stopped_early",
        }:
            incomplete_reasons.append(
                authorization_stage.get("bfla_reason")
                or "BFLA checks did not complete."
            )
    elif authorization_supported and not auth_executions:
        incomplete_reasons.append(
            "Authorization checks were not run (identity registration was not approved)."
        )
    elif not authorization_supported:
        incomplete_reasons.append(
            "Authorization and sensitive-data checks are not supported for "
            "this target; only inventory-level checks were performed."
        )

    if sensitive_stage and sensitive_outcome in {
        "failed",
        "not_run",
        "partial",
        "stopped_early",
        "unsupported",
        "not_supported",
    }:
        incomplete_reasons.append(
            sensitive_stage.get("reason")
            or "Sensitive-data checks did not complete."
        )
    elif (
        sensitive_stage is None
        and authorization_supported
        and not sensitive_identities
        and not sensitive_findings
    ):
        incomplete_reasons.append(
            "Sensitive-data checks were not recorded for this scan."
        )

    failed_stages = [
        stage_name
        for stage_name, entry in persisted_stages.items()
        if entry.get("status") == "failed"
    ]
    if failed_stages:
        incomplete_reasons.append(
            "Failed stage(s): " + ", ".join(failed_stages) + "."
        )

    recon_stage = persisted_stages.get("recon")
    recon_check_status = (
        recon_stage.get("status")
        if recon_stage
        else ("completed" if total_endpoints > 0 else "no_endpoints")
    )
    inventory_coverage = recon_stage.get("coverage") if recon_stage else None

    if classification_stage:
        classification_check_status = classification_stage.get("status", "unknown")
        classification_requested = classification_stage.get("requested")
        classification_reason = classification_stage.get("reason")
    else:
        classification_check_status = (
            "completed"
            if total_endpoints > 0 and classified_endpoints == total_endpoints
            else "partial"
            if classified_endpoints > 0
            else "not_completed"
        )
        classification_requested = None
        classification_reason = None

    resource_check_status = (
        resource_stage.get("status")
        if resource_stage
        else ("built" if resource_graph_summary else "not_built")
    )

    bola_findings = [
        f for f in findings if _enum_value(f.finding_type) == "bola"
    ]
    bola_confirmed = [
        f for f in bola_findings if _enum_value(f.status) == "confirmed"
    ]
    bola_candidates = [
        f for f in bola_findings if _enum_value(f.status) == "candidate"
    ]
    bfla_confirmed = [
        f for f in bfla_findings if _enum_value(f.status) == "confirmed"
    ]
    bfla_candidates = [
        f for f in bfla_findings if _enum_value(f.status) == "candidate"
    ]
    bola_results = (
        authorization_stage.get("results", []) if authorization_stage else []
    )
    bfla_results = (
        authorization_stage.get("bfla_results", [])
        if authorization_stage
        else []
    )
    if authorization_stage:
        bola_status = authorization_stage.get("bola_status")
        if not bola_status:
            authorization_outcome = authorization_stage.get("status")
            if authorization_outcome in {"not_supported", "not_run", "failed"}:
                bola_status = authorization_outcome
            else:
                bola_status = "performed" if bola_results else "not_applicable"
    else:
        bola_status = (
            "performed" if (auth_executions or bola_findings) else "not_run"
        )

    persistence_stage = persisted_stages.get("persistence")
    report_stage = persisted_stages.get("report")

    checks = {
        "recon": {
            "status": recon_check_status,
            "endpoints": total_endpoints,
            "coverage": inventory_coverage,
            "reason": recon_stage.get("reason") if recon_stage else None,
        },
        "classification": {
            "status": classification_check_status,
            "requested": classification_requested,
            "classified": classified_endpoints,
            "total": total_endpoints,
            "reason": classification_reason,
        },
        "resource_graph": {
            "status": resource_check_status,
            "resources": (
                resource_graph_summary["resources"]
                if resource_graph_summary
                else []
            ),
            "edges": (
                resource_graph_summary["edge_count"]
                if resource_graph_summary
                else 0
            ),
            "endpoint_count": (
                resource_graph_summary["endpoint_count"]
                if resource_graph_summary
                else 0
            ),
            "reason": resource_stage.get("reason") if resource_stage else None,
        },
        "authorization_tests": {
            "status": authorization_status,
            "supported_for_target": authorization_supported,
            "evidence_records": len(auth_executions),
            "identities": len(auth_identity_ids),
            "bola_status": bola_status,
            "bfla_status": bfla_status,
            "bfla_outcome": bfla_outcome,
            "requests_used": (
                authorization_stage.get("requests_used")
                if authorization_stage
                else None
            ),
            "request_budget": (
                authorization_stage.get("request_budget")
                if authorization_stage
                else None
            ),
            "stopped_early": (
                authorization_stage.get("stopped_early")
                if authorization_stage
                else None
            ),
            "reason": authorization_note,
            "note": authorization_note,
        },
        "bola": {
            "status": bola_status,
            "confirmed_findings": len(bola_confirmed),
            "candidate_findings": len(bola_candidates),
            "results": bola_results,
            "note": (
                None
                if bola_status == "performed"
                else "BOLA is only checked against eligible object-level "
                "endpoints on explicitly allowlisted origins."
            ),
        },
        "bfla": {
            "status": bfla_status,
            "outcome": bfla_outcome,
            "confirmed_findings": len(bfla_confirmed),
            "candidate_findings": len(bfla_candidates),
            "identities": len(bfla_identities),
            "results": bfla_results,
            "reason": bfla_reason,
            "note": bfla_note,
        },
        "sensitive_data": {
            "status": sensitive_status,
            "outcome": sensitive_outcome,
            "confirmed_findings": len(sensitive_confirmed),
            "candidate_findings": len(sensitive_candidates),
            "identities": len(sensitive_identities),
            "requests_used": (
                sensitive_stage.get("requests_used")
                if sensitive_stage
                else None
            ),
            "request_budget": (
                sensitive_stage.get("request_budget")
                if sensitive_stage
                else None
            ),
            "results": (
                sensitive_stage.get("results", []) if sensitive_stage else []
            ),
            "reason": sensitive_stage.get("reason") if sensitive_stage else None,
            "note": sensitive_note,
        },
        "persistence": {
            "status": (
                persistence_stage.get("status")
                if persistence_stage
                else "not_recorded"
            ),
            "findings_persisted": (
                persistence_stage.get("findings_persisted")
                if persistence_stage
                else len(findings)
            ),
        },
        "report": {
            "status": (
                report_stage.get("status") if report_stage else "available"
            ),
        },
    }

    zero_or_incomplete = {
        "zero_findings": not findings_populated,
        "no_classified_endpoints": not has_classified_endpoints,
        "classification_rate": classification_rate,
    }

    assessment_complete = (
        scan_status == ScanStatus.COMPLETED.value
        and total_endpoints > 0
        and not incomplete_reasons
    )

    return {
        "scan_id": scan.id,
        "target_id": scan.target_id,
        "status": scan_status,
        "started_at": str(scan.started_at) if scan.started_at else None,
        "completed_at": str(scan.completed_at) if scan.completed_at else None,
        "total_endpoints": total_endpoints,
        "classified_endpoints": classified_endpoints,
        "classification_rate": classification_rate,
        "findings_count": len(findings),
        "findings_by_severity": findings_by_severity,
        "findings_by_status": findings_by_status,
        "findings_by_type": findings_by_type,
        "findings": finding_details,
        "resource_graph_summary": resource_graph_summary,
        "inventory_coverage": inventory_coverage,
        "findings_populated": findings_populated,
        "has_classified_endpoints": has_classified_endpoints,
        "zero_or_incomplete": zero_or_incomplete,
        "assessment": {
            "complete": assessment_complete,
            "status": scan_status,
            "stages_persisted": bool(persisted_stages),
            "stage_source": (
                "persisted" if persisted_stages else "legacy_fallback"
            ),
            "stages": persisted_stages,
            "failed_stages": failed_stages,
            "incomplete_reasons": incomplete_reasons,
            "checks": checks,
        },
    }


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
