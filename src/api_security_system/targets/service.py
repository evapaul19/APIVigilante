"""One-call assessment orchestration: URL -> spec -> endpoints -> checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy import inspect
from sqlmodel import select

from api_security_system.auth import AuthProfile
from api_security_system.authz_bola.service import run_bola_check
from api_security_system.db import (
    AssessmentStage,
    Endpoint,
    Finding,
    FindingEvidence,
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
    ResolvedTarget,
    authorized_origins,
    is_active_test_authorized,
    is_authorized_origin,
    origin_of,
    resolve_target,
    user_authorized_targets_enabled,
    validate_spec_url,
)
from .spec_fetch import SpecUnavailableError, acquire_spec, save_spec

logger = logging.getLogger(__name__)

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
        logger.warning("Assessment database readiness check failed: %s", type(exc).__name__)
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


def _enum_value(value):
    return getattr(value, "value", value)


def _scan_findings(scan_id: int) -> list[dict]:
    with get_session() as session:
        findings = session.exec(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.id)
        ).all()
        if not findings:
            return []

        endpoints = {
            endpoint.id: endpoint
            for endpoint in session.exec(
                select(Endpoint).where(Endpoint.scan_id == scan_id)
            ).all()
        }
        evidence_ids: dict[int, list[int]] = {}
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

        return [
            {
                "id": finding.id,
                "scan_id": finding.scan_id,
                "endpoint_id": finding.endpoint_id,
                "finding_type": _enum_value(finding.finding_type),
                "severity": _enum_value(finding.severity),
                "description": (
                    sanitize_text_for_persistence(
                        finding.description, max_length=2000
                    )
                    or ""
                ),
                "status": _enum_value(finding.status),
                "confidence": finding.confidence,
                "method": (
                    endpoints[finding.endpoint_id].method
                    if finding.endpoint_id in endpoints
                    else None
                ),
                "path": (
                    endpoints[finding.endpoint_id].path
                    if finding.endpoint_id in endpoints
                    else None
                ),
                "operation_id": (
                    endpoints[finding.endpoint_id].operation_id
                    if finding.endpoint_id in endpoints
                    else None
                ),
                "evidence_execution_ids": sorted(
                    evidence_ids.get(finding.id, [])
                ),
            }
            for finding in findings
        ]


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
    A stage-persistence failure must not erase the scan itself; it is logged
    and the caller decides the final lifecycle status.
    """
    now = datetime.now(timezone.utc)
    try:
        with get_session() as session:
            existing = {
                row.stage_name: row
                for row in session.exec(
                    select(AssessmentStage).where(
                        AssessmentStage.scan_id == scan_id
                    )
                ).all()
            }

            for sequence, (stage_name, outcome) in enumerate(
                stages.items(), start=1
            ):
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
                row.reason = sanitize_text_for_persistence(
                    reason, max_length=1000
                )
                row.details = details
                row.recorded_at = now
                session.add(row)

            session.commit()
    except Exception as exc:  # noqa: BLE001 - lifecycle must still finalize
        logger.error(
            "Could not persist assessment stages for scan %s: %s",
            scan_id,
            type(exc).__name__,
        )


@dataclass(frozen=True)
class ProvisionedAssessment:
    """A validated target and scan row, before any target I/O."""

    scan_id: int
    target_id: int
    base_url: str
    origin: str
    display_name: str
    spec_url: str | None
    resolved_target: ResolvedTarget


def provision_assessment(
    base_url: str,
    openapi_spec_url: str | None = None,
    target_name: str | None = None,
) -> ProvisionedAssessment:
    """Validate the target and create a pending scan.

    Only local validation and one database insert happen here, so the API can
    acknowledge a request quickly and run the slow stages in the background.
    """
    resolved_target = resolve_target(base_url)
    base = resolved_target.base_url
    origin = origin_of(base)
    display_name = target_name or origin
    spec_url = validate_spec_url(base, openapi_spec_url)

    _require_assessment_stage_table()

    with get_session() as session:
        target = Target(
            name=display_name,
            base_url=base,
            openapi_spec_path="",
        )
        session.add(target)
        session.commit()
        session.refresh(target)

        scan = Scan(
            target_id=target.id,
            status=ScanStatus.PENDING,
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        target_id = target.id
        scan_id = scan.id

    return ProvisionedAssessment(
        scan_id=scan_id,
        target_id=target_id,
        base_url=base,
        origin=origin,
        display_name=display_name,
        spec_url=spec_url,
        resolved_target=resolved_target,
    )


def _failure_result(
    provisioned: ProvisionedAssessment,
    message: str,
    stages: dict | None = None,
) -> dict:
    """Persist an explicit failed outcome and return the public result shape."""
    _persist_stage_outcomes(
        provisioned.scan_id,
        stages
        or {
            "target_validation": {
                "status": "passed",
                "base_url": provisioned.base_url,
                "origin": provisioned.origin,
            },
            "lifecycle": {
                "status": "failed",
                "reason": message,
            },
        },
    )
    _update_scan(provisioned.scan_id, ScanStatus.FAILED, completed=True)
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
        "spec_source": None,
        "status": ScanStatus.FAILED.value,
        "findings_count": 0,
        "findings": [],
        "findings_persisted": 0,
        "stages": stages or {},
    }



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


_IDENTITY_CONTRACT_PATHS = frozenset(
    {
        ("POST", "/users/v1/register"),
        ("POST", "/users/v1/login"),
    }
)


def _endpoint_path_relative_to_base(path: str, base_path: str) -> str:
    normalized = "/" + str(path or "").strip("/")
    if base_path == "/":
        return normalized
    prefix = base_path.rstrip("/")
    if normalized == prefix or normalized.startswith(prefix + "/"):
        relative = normalized[len(prefix):]
        return relative or "/"
    return normalized


def _identity_contract_supported(scan_id: int, base_url: str) -> bool:
    """Return whether the spec exposes the supported identity contract.

    Active checks must not guess registration/login paths for a target with
    a different authentication mechanism. The supported contract is the
    VAmPI-compatible register/login pair used by ``AuthModule``.
    """
    base_path = "/" + urlsplit(base_url).path.strip("/")
    try:
        with get_session() as session:
            rows = session.exec(
                select(Endpoint.method, Endpoint.path).where(
                    Endpoint.scan_id == scan_id
                )
            ).all()
    except Exception:  # noqa: BLE001 - report unsupported rather than guess
        return False

    available = {
        (
            str(method or "").upper(),
            _endpoint_path_relative_to_base(path, base_path),
        )
        for method, path in rows
    }
    return _IDENTITY_CONTRACT_PATHS <= available


def _authorization_summary(
    scan_id: int,
    origin: str,
    allow_identity_registration: bool,
    budget: int,
    resolved_target=None,
    identity_contract_supported: bool = True,
    auth_profile: AuthProfile | None = None,
    authorized_for_active_testing: bool = False,
):
    active_authorized = is_authorized_origin(origin) or is_active_test_authorized(
        origin,
        authorized_for_active_testing=authorized_for_active_testing,
    )
    profile_supported = auth_profile is not None
    if not active_authorized:
        if user_authorized_targets_enabled() and not authorized_for_active_testing:
            reason = (
                "Active testing requires authorized_for_active_testing=true "
                "for this assessment, or an explicitly allowlisted origin "
                f"{sorted(authorized_origins())}."
            )
        else:
            reason = (
                "Authorization checks are only enabled for explicitly "
                f"allowlisted origins {sorted(authorized_origins())}, or for "
                "user-authorized targets when the operator enables "
                "APIVIGILANTE_ALLOW_USER_AUTHORIZED_TARGETS. This target's "
                "endpoints were still discovered and persisted."
            )
        return {
            "status": "not_supported",
            "supported_for_target": False,
            "identity_contract_supported": identity_contract_supported,
            "auth_profile_supported": profile_supported,
            "reason": reason,
        }
    if profile_supported:
        if auth_profile.type == "none":
            return {
                "status": "not_applicable",
                "supported_for_target": True,
                "identity_contract_supported": False,
                "auth_profile_supported": True,
                "auth_profile_type": auth_profile.type,
                "auth_scheme": auth_profile.scheme,
                "reason": (
                    "The auth profile is anonymous; no authenticated BOLA "
                    "check is possible. Sensitive-data inspection may still run."
                ),
            }
        if not allow_identity_registration:
            return {
                "status": "not_run",
                "supported_for_target": True,
                "identity_contract_supported": False,
                "auth_profile_supported": True,
                "auth_profile_type": auth_profile.type,
                "auth_scheme": auth_profile.scheme,
                "reason": (
                    "Active testing was not approved. Re-run with "
                    "allow_identity_registration=true to execute profile-based "
                    "read-only BOLA checks."
                ),
            }
        if len(auth_profile.identities) < 2:
            return {
                "status": "not_applicable",
                "supported_for_target": True,
                "identity_contract_supported": False,
                "auth_profile_supported": True,
                "auth_profile_type": auth_profile.type,
                "auth_scheme": auth_profile.scheme,
                "reason": (
                    "Read-only BOLA requires at least two identities in the "
                    "auth profile (attacker and victim)."
                ),
            }
    elif not identity_contract_supported:
        return {
            "status": "unsupported",
            "supported_for_target": False,
            "identity_contract_supported": False,
            "auth_profile_supported": False,
            "reason": (
                "This target does not expose the supported identity contract "
                "(POST /users/v1/register and POST /users/v1/login) and no "
                "auth_profile was supplied. Authorization checks were skipped "
                "rather than guessing a different authentication mechanism."
            ),
        }
    if not allow_identity_registration:
        return {
            "status": "not_run",
            "supported_for_target": True,
            "identity_contract_supported": identity_contract_supported,
            "auth_profile_supported": profile_supported,
            "auth_profile_type": auth_profile.type if auth_profile else None,
            "auth_scheme": auth_profile.scheme if auth_profile else None,
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
            auth_profile=auth_profile,
            authorized_for_active_testing=authorized_for_active_testing,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced in the response
        return {
            "status": "failed",
            "supported_for_target": True,
            "identity_contract_supported": identity_contract_supported,
            "auth_profile_supported": profile_supported,
            "auth_profile_type": auth_profile.type if auth_profile else None,
            "auth_scheme": auth_profile.scheme if auth_profile else None,
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
    elif result.bfla_status == "unsupported" and not profile_supported:
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
                result.bfla_reason
                if result.bfla_status == "not_applicable"
                and result.bfla_reason
                and not result.endpoint_results
                else (
                    "No eligible BOLA or BFLA candidate was found for this "
                    "target; no authorization check ran."
                )
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
        "identity_contract_supported": identity_contract_supported,
        "auth_profile_supported": profile_supported,
        "auth_profile_type": auth_profile.type if auth_profile else None,
        "auth_scheme": auth_profile.scheme if auth_profile else None,
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
    identity_contract_supported: bool = True,
    auth_profile: AuthProfile | None = None,
    authorized_for_active_testing: bool = False,
):
    active_authorized = is_authorized_origin(origin) or is_active_test_authorized(
        origin,
        authorized_for_active_testing=authorized_for_active_testing,
    )
    profile_supported = auth_profile is not None
    if not active_authorized:
        if user_authorized_targets_enabled() and not authorized_for_active_testing:
            reason = (
                "Active testing requires authorized_for_active_testing=true "
                "for this assessment, or an explicitly allowlisted origin "
                f"{sorted(authorized_origins())}."
            )
        else:
            reason = (
                "Sensitive-data checks are only enabled for explicitly "
                f"allowlisted origins {sorted(authorized_origins())}, or for "
                "user-authorized targets when the operator enables "
                "APIVIGILANTE_ALLOW_USER_AUTHORIZED_TARGETS."
            )
        return {
            "status": "not_supported",
            "supported_for_target": False,
            "identity_contract_supported": identity_contract_supported,
            "auth_profile_supported": profile_supported,
            "reason": reason,
        }
    if not allow_identity_registration:
        return {
            "status": "not_run",
            "supported_for_target": True,
            "identity_contract_supported": identity_contract_supported,
            "auth_profile_supported": profile_supported,
            "auth_profile_type": auth_profile.type if auth_profile else None,
            "auth_scheme": auth_profile.scheme if auth_profile else None,
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
            provision_identity_enabled=(
                identity_contract_supported and auth_profile is None
            ),
            auth_profile=auth_profile,
            authorized_for_active_testing=authorized_for_active_testing,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced in the response
        return {
            "status": "failed",
            "supported_for_target": True,
            "identity_contract_supported": identity_contract_supported,
            "auth_profile_supported": profile_supported,
            "auth_profile_type": auth_profile.type if auth_profile else None,
            "auth_scheme": auth_profile.scheme if auth_profile else None,
            "reason": _safe_reason(
                f"Sensitive-data checks failed: {type(exc).__name__}: {exc}"
            ),
        }

    return {
        "status": result.status,
        "supported_for_target": True,
        "identity_contract_supported": identity_contract_supported,
        "auth_profile_supported": profile_supported,
        "auth_profile_type": auth_profile.type if auth_profile else None,
        "auth_scheme": auth_profile.scheme if auth_profile else None,
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


def _validate_request_budget(request_budget: int) -> None:
    if (
        isinstance(request_budget, bool)
        or not isinstance(request_budget, int)
        or request_budget < 0
    ):
        raise ValueError("request budget must be a non-negative integer.")


def create_assessment(
    base_url: str,
    openapi_spec_url: str | None = None,
    target_name: str | None = None,
    allow_identity_registration: bool = False,
    classify: bool = True,
    request_budget: int = DEFAULT_ASSESSMENT_REQUEST_BUDGET,
    auth_profile: AuthProfile | None = None,
    authorized_for_active_testing: bool = False,
) -> dict:
    """Validate a target, create the scan, and run every stage synchronously.

    This is the deterministic entry point used by tests and by callers that
    need the completed result. The HTTP API uses ``provision_assessment`` plus
    ``run_assessment`` so slow target I/O does not block the request.
    """
    _validate_request_budget(request_budget)
    provisioned = provision_assessment(
        base_url=base_url,
        openapi_spec_url=openapi_spec_url,
        target_name=target_name,
    )
    return run_assessment(
        provisioned,
        allow_identity_registration=allow_identity_registration,
        classify=classify,
        request_budget=request_budget,
        auth_profile=auth_profile,
        authorized_for_active_testing=authorized_for_active_testing,
    )


def _begin_scan(scan_id: int) -> None:
    """Move a provisioned scan into the running state.

    Reading the row first keeps this idempotent and avoids an extra status
    write when a caller re-runs an already-running scan.
    """
    try:
        with get_session() as session:
            scan = session.get(Scan, scan_id)
            if scan is None or scan.status == ScanStatus.RUNNING:
                return
            scan.status = ScanStatus.RUNNING
            if scan.started_at is None:
                scan.started_at = datetime.now(timezone.utc)
            session.add(scan)
            session.commit()
    except Exception as exc:  # noqa: BLE001 - the guarded body handles it
        logger.error(
            "Could not mark scan %s as running: %s",
            scan_id,
            type(exc).__name__,
        )


def run_assessment(
    provisioned: ProvisionedAssessment,
    *,
    allow_identity_registration: bool = False,
    classify: bool = True,
    request_budget: int = DEFAULT_ASSESSMENT_REQUEST_BUDGET,
    auth_profile: AuthProfile | None = None,
    authorized_for_active_testing: bool = False,
) -> dict:
    """Run all assessment stages for an already-provisioned scan.

    The scan is transitioned to ``running`` first. Any unexpected error is
    converted into a persisted failed outcome, so a scan can never remain
    ``running`` because a stage or persistence helper raised.
    """
    _validate_request_budget(request_budget)
    _begin_scan(provisioned.scan_id)
    try:
        return _execute_assessment(
            provisioned,
            allow_identity_registration=allow_identity_registration,
            classify=classify,
            request_budget=request_budget,
            auth_profile=auth_profile,
            authorized_for_active_testing=authorized_for_active_testing,
        )
    except Exception as exc:  # noqa: BLE001 - persisted, never left running
        logger.error(
            "Assessment %s failed unexpectedly: %s",
            provisioned.scan_id,
            type(exc).__name__,
        )
        message = _safe_reason(
            f"The assessment stopped unexpectedly ({type(exc).__name__}). "
            "Any results persisted before the failure are retained."
        )
        return _failure_result(provisioned, message or "Assessment failed.")


def _execute_assessment(
    provisioned: ProvisionedAssessment,
    *,
    allow_identity_registration: bool,
    classify: bool,
    request_budget: int,
    auth_profile: AuthProfile | None,
    authorized_for_active_testing: bool,
) -> dict:
    """Run the stage pipeline for a provisioned scan.

    Stage order: spec discovery -> recon (endpoint inventory) -> optional LLM
    classification -> resource graph -> BOLA/BFLA -> sensitive data. Each
    stage outcome is returned explicitly; non-foundational stage failures are
    reported without discarding earlier results.
    """
    base = provisioned.base_url
    origin = provisioned.origin
    target_display_name = provisioned.display_name
    spec_url = provisioned.spec_url
    resolved_target = provisioned.resolved_target
    scan_id = provisioned.scan_id
    target_id = provisioned.target_id

    try:
        spec = acquire_spec(
            base,
            spec_url,
            resolved_target=resolved_target,
        )
    except SpecUnavailableError as exc:
        failed_reason = _safe_reason(str(exc)) or "No usable specification or discoverable routes were found."
        stages = {
            "target_validation": {
                "status": "passed",
                "base_url": base,
                "origin": origin,
            },
            "spec_discovery": {
                "status": "failed",
                "source": "openapi",
                "reason": failed_reason,
            },
            "recon": {
                "status": "not_run",
                "endpoints": 0,
                "reason": "Specification acquisition did not produce an inventory.",
            },
            "classification": {
                "status": "not_run",
                "reason": "No endpoints were available to classify.",
            },
            "resource_graph": {
                "status": "not_run",
                "reason": "No endpoints were available to build a resource graph.",
            },
            "authorization_checks": {
                "status": "not_run",
                "reason": "No endpoints were available for authorization checks.",
            },
            "sensitive_data_checks": {
                "status": "not_run",
                "reason": "No endpoints were available for sensitive-data checks.",
            },
            "persistence": {
                "status": "completed",
                "findings_persisted": 0,
            },
            "report": {
                "status": "available",
                "path": f"/scans/{scan_id}/report",
            },
        }
        _persist_stage_outcomes(scan_id, stages)
        _update_scan(scan_id, ScanStatus.FAILED, completed=True)
        return {
            "scan_id": scan_id,
            "target_id": target_id,
            "target": {
                "id": target_id,
                "name": target_display_name,
                "base_url": base,
            },
            "base_url": base,
            "origin": origin,
            "spec_source": None,
            "status": ScanStatus.FAILED.value,
            "findings_count": 0,
            "findings": [],
            "findings_persisted": 0,
            "stages": stages,
        }

    spec_path = save_spec(spec)
    with get_session() as session:
        persisted_target = session.get(Target, target_id)
        if persisted_target is None:
            raise AssessmentSchemaError(
                "The assessment target disappeared before its specification could be saved."
            )
        persisted_target.openapi_spec_path = spec_path
        session.add(persisted_target)
        session.commit()

    try:
        recon = run_recon(scan_id, classify=classify)
    except Exception as exc:  # noqa: BLE001 - scan is marked failed and persisted
        failed_reason = _safe_reason(
            f"Reconnaissance failed: {type(exc).__name__}: {exc}"
        ) or "Reconnaissance failed."
        stages = {
            "target_validation": {
                "status": "passed",
                "base_url": base,
                "origin": origin,
            },
            "spec_discovery": {
                "status": "discovery_only" if spec.discovery_mode else "succeeded",
                "source_type": (
                    "bounded_html_discovery" if spec.discovery_mode else "openapi"
                ),
                "source": spec.source_url,
                "path": spec_path,
                "limitations": spec.limitations,
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
                "status": "completed",
                "findings_persisted": 0,
            },
            "report": {
                "status": "available",
                "path": f"/scans/{scan_id}/report",
            },
        }
        try:
            _persist_stage_outcomes(scan_id, stages)
        except Exception:  # noqa: BLE001 - preserve the primary recon error
            pass
        _update_scan(scan_id, ScanStatus.FAILED, completed=True)
        return {
            "scan_id": scan_id,
            "target_id": target_id,
            "target": {
                "id": target_id,
                "name": target_display_name,
                "base_url": base,
            },
            "base_url": base,
            "origin": origin,
            "spec_source": spec.source_url,
            "status": ScanStatus.FAILED.value,
            "findings_count": 0,
            "findings": [],
            "findings_persisted": 0,
            "recon": {"status": "failed", "endpoints_found": 0},
            "stages": stages,
        }

    classification = _classification_summary(recon, classify)
    resource_graph = _resource_graph_summary(scan_id)
    identity_contract_supported = _identity_contract_supported(scan_id, base)

    authorization = _authorization_summary(
        scan_id,
        origin,
        allow_identity_registration,
        request_budget,
        resolved_target=resolved_target,
        identity_contract_supported=identity_contract_supported,
        auth_profile=auth_profile,
        authorized_for_active_testing=authorized_for_active_testing,
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
        identity_contract_supported=identity_contract_supported,
        auth_profile=auth_profile,
        authorized_for_active_testing=authorized_for_active_testing,
    )

    findings = _scan_findings(scan_id)
    findings_persisted = len(findings)

    recon_status = "completed" if recon.endpoints_found else "no_endpoints"
    if spec.discovery_mode:
        recon.coverage.limitations.extend(
            limitation
            for limitation in spec.limitations
            if limitation not in recon.coverage.limitations
        )

    stages = {
        "target_validation": {
            "status": "passed",
            "base_url": base,
            "origin": origin,
        },
        "spec_discovery": {
            "status": "discovery_only" if spec.discovery_mode else "succeeded",
            "source_type": (
                "bounded_html_discovery" if spec.discovery_mode else "openapi"
            ),
            "source": spec.source_url,
            "path": spec_path,
            "limitations": spec.limitations,
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
            "identity_contract_supported": authorization.get(
                "identity_contract_supported"
            ),
            "auth_profile_supported": authorization.get(
                "auth_profile_supported"
            ),
            "auth_profile_type": authorization.get("auth_profile_type"),
            "auth_scheme": authorization.get("auth_scheme"),
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
            "identity_contract_supported": sensitive_data.get(
                "identity_contract_supported"
            ),
            "auth_profile_supported": sensitive_data.get(
                "auth_profile_supported"
            ),
            "auth_profile_type": sensitive_data.get("auth_profile_type"),
            "auth_scheme": sensitive_data.get("auth_scheme"),
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

    # A scan that produced an inventory is COMPLETED only when no security
    # stage failed. PARTIAL makes a degraded assessment distinguishable from
    # a clean one instead of reporting a misleading success.
    degraded_stages = [
        name
        for name in (
            "recon",
            "resource_graph",
            "authorization_checks",
            "sensitive_data_checks",
        )
        if stages.get(name, {}).get("status") == "failed"
    ]
    if recon.endpoints_found == 0:
        final_status = ScanStatus.FAILED
    elif degraded_stages:
        final_status = ScanStatus.PARTIAL
    else:
        final_status = ScanStatus.COMPLETED
    _update_scan(scan_id, final_status, completed=True)

    return {
        "scan_id": scan_id,
        "target_id": target_id,
        "target": {
            "id": target_id,
            "name": target_display_name,
            "base_url": base,
        },
        "base_url": base,
        "origin": origin,
        "spec_source": spec.source_url,
        "spec_path": spec_path,
        "status": final_status.value,
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
        "findings_count": findings_persisted,
        "findings": findings,
        "findings_persisted": findings_persisted,
        "stages": stages,
    }
