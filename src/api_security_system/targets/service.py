"""One-call assessment orchestration: URL -> spec -> endpoints -> checks."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import inspect
from sqlmodel import select

from api_security_system.authz_bola.service import run_bola_check
from api_security_system.db import (
    AssessmentStage,
    Finding,
    Scan,
    ScanStatus,
    Target,
    get_engine,
    get_session,
)
from api_security_system.db.redaction import sanitize_text_for_persistence
from api_security_system.recon.service import ReconResult, run_recon
from api_security_system.resource_graph import build_resource_graph
from api_security_system.sensitive_data import (
    DEFAULT_SENSITIVE_REQUEST_BUDGET,
    run_sensitive_data_check,
)

from .security import (
    authorized_origins,
    is_authorized_origin,
    origin_of,
    resolve_target,
    validate_spec_url,
)
from .spec_fetch import SpecUnavailableError, acquire_spec, save_spec

# BOLA and BFLA share one request budget; both identity provisioning and
# control executions count. 40 covers two check families against VAmPI.
DEFAULT_ASSESSMENT_REQUEST_BUDGET = 40


class AssessmentSchemaError(RuntimeError):
    """Raised when the database schema is missing a required assessment table."""


def _require_assessment_stage_table() -> None:
    """Fail before side effects when the additive migration is not applied."""
    try:
        with get_engine().connect() as connection:
            if inspect(connection).has_table("assessment_stages"):
                return
    except Exception as exc:
        raise AssessmentSchemaError(
            "Could not inspect the database schema. Verify PostgreSQL is "
            "reachable, then run: alembic upgrade head"
        ) from exc

    raise AssessmentSchemaError(
        "The assessment_stages table is missing. Apply the additive database "
        "migration before running an assessment: alembic upgrade head"
    )


def _safe_reason(value):
    if value is None:
        return None
    return sanitize_text_for_persistence(str(value), max_length=1000)


def _update_scan(scan_id: int, status: ScanStatus, completed: bool = False) -> None:
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = status
        if completed:
            scan.completed_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()


def _sanitize_stage_details(value):
    """Recursively sanitize free-form stage detail strings."""
    if isinstance(value, dict):
        return {key: _sanitize_stage_details(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_stage_details(item) for item in value]
    if isinstance(value, str):
        return sanitize_text_for_persistence(value, max_length=1000)
    return value


def _persist_stage_outcomes(scan_id: int, stages: dict) -> None:
    """Upsert the explicit outcome of every assessment stage for a scan.

    Existing stage rows for the same scan are updated rather than deleted,
    so re-running an orchestration step does not discard earlier state.
    """
    now = datetime.now(timezone.utc)
    with get_session() as session:
        existing = {
            row.stage_name: row
            for row in session.exec(
                select(AssessmentStage).where(
                    AssessmentStage.scan_id == scan_id
                )
            ).all()
        }

        for sequence, (stage_name, outcome) in enumerate(stages.items(), start=1):
            payload = dict(outcome)
            status = str(payload.pop("status", "unknown"))[:64]
            reason = payload.pop("reason", None)
            details = _sanitize_stage_details(payload)

            row = existing.get(stage_name)
            if row is None:
                row = AssessmentStage(
                    scan_id=scan_id,
                    stage_name=stage_name,
                    sequence=sequence,
                    status=status,
                    details=details,
                    recorded_at=now,
                )
            row.sequence = sequence
            row.status = status
            row.reason = sanitize_text_for_persistence(reason, max_length=1000)
            row.details = details
            row.recorded_at = now
            session.add(row)

        session.commit()


def _classification_summary(recon: ReconResult, requested: bool) -> dict:
    """Describe the optional LLM classification stage explicitly.

    A stage that was requested but classified nothing must not look the
    same as one that was not requested.
    """
    failures = [
        _sanitize_stage_details(failure.model_dump())
        for failure in recon.classification_failures
    ]
    reason = None

    if not requested:
        status = "not_requested"
    elif recon.endpoints_found == 0:
        status = "skipped_no_endpoints"
        reason = "No endpoints were discovered, so there was nothing to classify."
    elif recon.classifications_failed and recon.classifications_succeeded:
        status = "partial"
        reason = (
            "Some endpoints could not be classified; their deterministic "
            "inventory is preserved with risk_classification=None."
        )
    elif recon.classifications_failed:
        status = "failed"
        reason = (
            "No endpoint could be classified; the deterministic inventory is "
            "preserved with risk_classification=None."
        )
    else:
        status = "completed"

    return {
        "status": status,
        "requested": requested,
        "succeeded": recon.classifications_succeeded,
        "failed": recon.classifications_failed,
        "failures": failures,
        "reason": reason,
    }


def _resource_graph_summary(scan_id: int) -> dict:
    """Build the resource graph as an explicit orchestration stage.

    Graph construction is deterministic and local, but a failure is
    reported rather than silently ignored; it does not prevent the
    authorization or sensitive-data stages from running.
    """
    try:
        graph = build_resource_graph(scan_id)
    except Exception as exc:  # noqa: BLE001 - surfaced in the response
        return {
            "status": "failed",
            "reason": _safe_reason(
                f"Resource graph failed: {type(exc).__name__}: {exc}"
            ),
            "resources": [],
            "endpoint_count": 0,
            "edge_count": 0,
            "identifies_count": 0,
            "may_relate_count": 0,
        }

    if not graph.endpoints:
        return {
            "status": "not_built",
            "reason": "No endpoints were discovered, so no graph was built.",
            "resources": [],
            "endpoint_count": 0,
            "edge_count": 0,
            "identifies_count": 0,
            "may_relate_count": 0,
        }

    return {
        "status": "built",
        "reason": None,
        "resources": sorted(graph.resources.keys()),
        "endpoint_count": len(graph.endpoints),
        "edge_count": len(graph.edges),
        "identifies_count": sum(
            1 for edge in graph.edges if edge.relation.name == "IDENTIFIES"
        ),
        "may_relate_count": sum(
            1 for edge in graph.edges if edge.relation.name == "MAY_RELATE"
        ),
    }


def _authorization_summary(
    scan_id: int,
    origin: str,
    allow_identity_registration: bool,
    budget: int,
    resolved_target=None,
):
    if not is_authorized_origin(origin):
        return {
            "status": "not_supported",
            "supported_for_target": False,
            "reason": (
                "Authorization checks are only enabled for explicitly "
                f"allowlisted origins {sorted(authorized_origins())}. "
                "This target's endpoints were still discovered and persisted."
            ),
        }
    if not allow_identity_registration:
        return {
            "status": "not_run",
            "supported_for_target": True,
            "reason": (
                "Identity registration was not approved. Re-run with "
                "allow_identity_registration=true to execute BOLA and BFLA checks."
            ),
        }

    try:
        result = run_bola_check(
            scan_id=scan_id,
            allow_identity_registration=True,
            request_budget=budget,
            resolved_target=resolved_target,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced in the response
        return {
            "status": "failed",
            "supported_for_target": True,
            "reason": _safe_reason(
                f"Authorization checks failed: {type(exc).__name__}: {exc}"
            ),
        }

    bola_ran = any(
        item.outcome.value != "not_applicable"
        for item in result.endpoint_results
    )
    bfla_ran = result.bfla_status == "performed"

    if result.stopped_early:
        status = "partial"
    elif bola_ran or bfla_ran:
        status = "performed"
    elif result.bfla_status == "unsupported":
        status = "unsupported"
    else:
        status = "not_applicable"

    if result.stopped_early:
        reason = result.stopped_reason or (
            "Authorization checks stopped before completing the request budget."
        )
    elif status == "unsupported":
        reason = result.bfla_reason or (
            "No verified higher-privileged identity was available for BFLA."
        )
    elif status == "not_applicable":
        skipped_reasons = [
            item.rationale
            for item in result.endpoint_results
            if item.outcome.value == "not_applicable" and item.rationale
        ]
        reason = (
            skipped_reasons[0]
            if skipped_reasons
            else (
                "No eligible BOLA or BFLA candidate was found for this "
                "target; no authorization check ran."
            )
        )
    else:
        reason = None

    if result.stopped_early and not result.endpoint_results:
        bola_status = "stopped_early"
    elif bola_ran:
        bola_status = "performed"
    elif result.endpoint_results:
        bola_status = "not_applicable"
    else:
        bola_status = "not_applicable"

    return {
        "status": status,
        "supported_for_target": True,
        "reason": _safe_reason(reason),
        "bola_status": bola_status,
        "requests_used": result.requests_used,
        "request_budget": result.request_budget,
        "stopped_early": result.stopped_early,
        "stopped_reason": _safe_reason(result.stopped_reason),
        "results": [
            {
                "operation_id": item.operation_id,
                "path": item.path,
                "outcome": item.outcome.value,
                "finding_id": item.finding_id,
            }
            for item in result.endpoint_results
        ],
        "confirmed_findings": sum(
            1 for item in result.endpoint_results if item.outcome.value == "confirmed"
        ),
        "bfla_status": result.bfla_status,
        "bfla_reason": _safe_reason(result.bfla_reason),
        "bfla_results": [
            {
                "operation_id": item.operation_id,
                "path": item.path,
                "outcome": item.outcome.value,
                "finding_id": item.finding_id,
            }
            for item in result.bfla_results
        ],
        "bfla_confirmed_findings": sum(
            1 for item in result.bfla_results if item.outcome.value == "confirmed"
        ),
    }


def _sensitive_summary(
    scan_id: int,
    origin: str,
    allow_identity_registration: bool,
    budget: int,
    resolved_target=None,
):
    if not is_authorized_origin(origin):
        return {
            "status": "not_supported",
            "supported_for_target": False,
            "reason": (
                "Sensitive-data checks are only enabled for explicitly "
                f"allowlisted origins {sorted(authorized_origins())}."
            ),
        }
    if not allow_identity_registration:
        return {
            "status": "not_run",
            "supported_for_target": True,
            "reason": (
                "Active testing was not approved. Re-run with "
                "allow_identity_registration=true to inspect response bodies."
            ),
        }

    try:
        result = run_sensitive_data_check(
            scan_id=scan_id,
            allow_identity_registration=True,
            request_budget=min(budget, DEFAULT_SENSITIVE_REQUEST_BUDGET),
            resolved_target=resolved_target,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced in the response
        return {
            "status": "failed",
            "supported_for_target": True,
            "reason": _safe_reason(
                f"Sensitive-data checks failed: {type(exc).__name__}: {exc}"
            ),
        }

    return {
        "status": result.status,
        "supported_for_target": True,
        "requests_used": result.requests_used,
        "request_budget": result.request_budget,
        "reason": _safe_reason(result.reason),
        "confirmed_findings": result.confirmed_findings,
        "candidate_findings": result.candidate_findings,
        "results": [
            {
                "endpoint_id": item.endpoint_id,
                "method": item.method,
                "path": item.path,
                "operation_id": item.operation_id,
                "outcome": item.outcome.value,
                "auth_mode": item.auth_mode,
                "fields": item.fields,
                "categories": item.categories,
                "finding_id": item.finding_id,
                "execution_id": item.execution_id,
            }
            for item in result.results
        ],
    }


def create_assessment(
    base_url: str,
    openapi_spec_url: str | None = None,
    target_name: str | None = None,
    allow_identity_registration: bool = False,
    classify: bool = True,
    request_budget: int = DEFAULT_ASSESSMENT_REQUEST_BUDGET,
) -> dict:
    """Create a Target + Scan and run the assessment stages in order.

    Stage order: target validation -> spec discovery -> recon (endpoint
    inventory) -> optional LLM classification -> resource graph ->
    BOLA/BFLA -> sensitive data. Each stage outcome is returned explicitly;
    non-foundational stage failures are reported without discarding earlier
    results. Persistence and report availability are reported last.

    Raises TargetValidationError for unsafe URLs and SpecUnavailableError
    when no usable OpenAPI document can be obtained. In both cases no
    Target or Scan is created. A Recon/spec-parse failure marks the created
    scan as failed and is re-raised.
    """
    if (
        isinstance(request_budget, bool)
        or not isinstance(request_budget, int)
        or request_budget < 0
    ):
        raise ValueError("request budget must be a non-negative integer.")

    resolved_target = resolve_target(base_url)
    base = resolved_target.base_url
    origin = origin_of(base)
    spec_url = validate_spec_url(base, openapi_spec_url)

    _require_assessment_stage_table()

    spec = acquire_spec(
        base,
        spec_url,
        resolved_target=resolved_target,
    )
    spec_path = save_spec(spec)

    with get_session() as session:
        target = Target(
            name=target_name or origin,
            base_url=base,
            openapi_spec_path=spec_path,
        )
        session.add(target)
        session.commit()
        session.refresh(target)

        scan = Scan(
            target_id=target.id,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id
        target_id = target.id

    try:
        recon = run_recon(scan_id, classify=classify)
    except Exception as exc:  # noqa: BLE001 - scan is marked failed and persisted
        failed_reason = (
            f"Reconnaissance failed: {type(exc).__name__}: {exc}"
        )
        try:
            _persist_stage_outcomes(
                scan_id,
                {
                    "target_validation": {
                        "status": "passed",
                        "base_url": base,
                        "origin": origin,
                    },
                    "spec_discovery": {
                        "status": "succeeded",
                        "source": spec.source_url,
                        "path": spec_path,
                    },
                    "recon": {
                        "status": "failed",
                        "reason": failed_reason,
                        "endpoints": 0,
                    },
                    "classification": {
                        "status": "not_run",
                        "reason": "Reconnaissance did not complete.",
                    },
                    "resource_graph": {
                        "status": "not_run",
                        "reason": "Reconnaissance did not complete.",
                    },
                    "authorization_checks": {
                        "status": "not_run",
                        "reason": "Reconnaissance did not complete.",
                    },
                    "sensitive_data_checks": {
                        "status": "not_run",
                        "reason": "Reconnaissance did not complete.",
                    },
                    "persistence": {
                        "status": "not_run",
                        "reason": "Assessment did not reach persistence.",
                    },
                    "report": {
                        "status": "available",
                        "path": f"/scans/{scan_id}/report",
                    },
                },
            )
        except Exception:  # noqa: BLE001 - preserve the primary recon error
            pass
        _update_scan(scan_id, ScanStatus.FAILED, completed=True)
        raise

    classification = _classification_summary(recon, classify)
    resource_graph = _resource_graph_summary(scan_id)

    authorization = _authorization_summary(
        scan_id,
        origin,
        allow_identity_registration,
        request_budget,
        resolved_target=resolved_target,
    )
    # Authorization and sensitive-data checks share the assessment's one
    # approved budget. Sensitive inspection gets only what remains, capped
    # at its own 20-request ceiling.
    authorization_requests = authorization.get("requests_used") or 0
    remaining_budget = max(0, request_budget - authorization_requests)
    sensitive_data = _sensitive_summary(
        scan_id,
        origin,
        allow_identity_registration,
        remaining_budget,
        resolved_target=resolved_target,
    )

    with get_session() as session:
        findings_persisted = len(
            session.exec(
                select(Finding.id).where(Finding.scan_id == scan_id)
            ).all()
        )

    recon_status = "completed" if recon.endpoints_found else "no_endpoints"

    stages = {
        "target_validation": {
            "status": "passed",
            "base_url": base,
            "origin": origin,
        },
        "spec_discovery": {
            "status": "succeeded",
            "source": spec.source_url,
            "path": spec_path,
            "format": recon.coverage.spec_format,
            "version": recon.coverage.spec_version,
        },
        "recon": {
            "status": recon_status,
            "endpoints": recon.endpoints_found,
            "endpoints_inserted": recon.endpoints_inserted,
            "endpoints_skipped_duplicate": recon.endpoints_skipped_duplicate,
            "coverage": recon.coverage.model_dump(),
        },
        "classification": {
            "status": classification["status"],
            "reason": classification["reason"],
            "requested": classification["requested"],
            "succeeded": classification["succeeded"],
            "failed": classification["failed"],
            "failures": classification["failures"],
        },
        "resource_graph": {
            "status": resource_graph["status"],
            "reason": resource_graph["reason"],
            "resources": resource_graph["resources"],
            "endpoint_count": resource_graph["endpoint_count"],
            "edge_count": resource_graph["edge_count"],
            "identifies_count": resource_graph["identifies_count"],
            "may_relate_count": resource_graph["may_relate_count"],
        },
        "authorization_checks": {
            "status": authorization["status"],
            "reason": authorization.get("reason"),
            "supported_for_target": authorization.get("supported_for_target"),
            "bola_status": authorization.get("bola_status"),
            "bfla_status": authorization.get("bfla_status"),
            "bfla_reason": authorization.get("bfla_reason"),
            "requests_used": authorization.get("requests_used"),
            "request_budget": authorization.get("request_budget"),
            "stopped_early": authorization.get("stopped_early"),
            "stopped_reason": authorization.get("stopped_reason"),
            "confirmed_findings": authorization.get("confirmed_findings"),
            "bfla_confirmed_findings": authorization.get(
                "bfla_confirmed_findings"
            ),
            "results": authorization.get("results", []),
            "bfla_results": authorization.get("bfla_results", []),
        },
        "sensitive_data_checks": {
            "status": sensitive_data["status"],
            "reason": sensitive_data.get("reason"),
            "supported_for_target": sensitive_data.get("supported_for_target"),
            "requests_used": sensitive_data.get("requests_used"),
            "request_budget": sensitive_data.get("request_budget"),
            "confirmed_findings": sensitive_data.get("confirmed_findings"),
            "candidate_findings": sensitive_data.get("candidate_findings"),
            "results": sensitive_data.get("results", []),
        },
        "persistence": {
            "status": "completed",
            "findings_persisted": findings_persisted,
        },
        "report": {
            "status": "available",
            "path": f"/scans/{scan_id}/report",
        },
    }

    _persist_stage_outcomes(scan_id, stages)
    _update_scan(scan_id, ScanStatus.COMPLETED, completed=True)

    return {
        "scan_id": scan_id,
        "target_id": target_id,
        "base_url": base,
        "origin": origin,
        "spec_source": spec.source_url,
        "spec_path": spec_path,
        "status": ScanStatus.COMPLETED.value,
        "recon": {
            "status": recon_status,
            "endpoints_found": recon.endpoints_found,
            "endpoints_inserted": recon.endpoints_inserted,
            "endpoints_skipped_duplicate": recon.endpoints_skipped_duplicate,
            "coverage": recon.coverage.model_dump(),
        },
        "classification": classification,
        "resource_graph": resource_graph,
        "authorization_tests": authorization,
        "sensitive_data_tests": sensitive_data,
        "findings_persisted": findings_persisted,
        "stages": stages,
    }
