"""Assessment report construction.

This module is the single source of truth for the report payload. Both the
report endpoint and the assessment lifecycle use it, so the report always
reflects the findings persisted for the scan.

The builder is deterministic: it reads persisted rows only, performs no
target I/O, and never invents findings. Plain-language fields are derived
from the finding category, status, and the evidence already recorded.
"""

from __future__ import annotations

from sqlmodel import select

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
)
from api_security_system.db.redaction import (
    redact_headers_for_persistence,
    sanitize_text_for_persistence,
)
from api_security_system.sensitive_data import sanitize_for_persistence
from api_security_system.targets.security import is_authorized_origin


CATEGORY_INFO = {
    "bola": {
        "label": "Broken object-level authorization",
        "why": (
            "An authenticated caller may be able to read or change another "
            "user's data by changing an object identifier in the request."
        ),
        "fix": (
            "Enforce object ownership and tenant checks on every request that "
            "uses an identifier. Authorize against the authenticated subject "
            "server-side rather than trusting identifiers supplied by the "
            "caller, and add regression tests for cross-user access."
        ),
    },
    "bfla": {
        "label": "Broken function-level authorization",
        "why": (
            "A less-privileged caller may be able to reach an administrative "
            "or otherwise privileged operation."
        ),
        "fix": (
            "Check the caller's role and permissions server-side for every "
            "privileged operation. Deny by default and cover each role "
            "boundary with tests."
        ),
    },
    "sensitive_data": {
        "label": "Sensitive data exposure",
        "why": (
            "Responses may disclose personal data, credentials, or tokens to "
            "a wider audience than intended."
        ),
        "fix": (
            "Return only the fields the caller needs, remove secrets and "
            "unnecessary personal data from responses, and enforce "
            "authorization before serializing the object."
        ),
    },
}

_SEVERITY_REASONING = {
    "critical": (
        "Rated critical because the observed behavior could lead directly to "
        "broad compromise with little attacker effort."
    ),
    "high": (
        "Rated high because the observed behavior crosses a meaningful "
        "security boundary and could expose or modify protected data."
    ),
    "medium": (
        "Rated medium because the behavior is security-relevant but the "
        "available evidence is indirect or requires additional conditions."
    ),
    "low": (
        "Rated low because the observed behavior has limited security impact "
        "or requires significant preconditions."
    ),
    "info": (
        "Rated informational because the observation is useful context but "
        "does not by itself demonstrate a vulnerability."
    ),
}


def _sanitize_report_details(value):
    if isinstance(value, dict):
        return {key: _sanitize_report_details(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_report_details(item) for item in value]
    if isinstance(value, str):
        return sanitize_text_for_persistence(value, max_length=1000)
    return value


def _humanize_report_finding(item: dict) -> dict:
    """Add plain-language context without changing the persisted evidence."""
    finding_type = str(item.get("finding_type") or "")
    severity = str(item.get("severity") or "unknown")
    status = str(item.get("status") or "unknown")
    endpoint = item.get("endpoint") or {}
    method = str(endpoint.get("method") or "").upper()
    path = endpoint.get("path") or ""
    location = " ".join(part for part in (method, path) if part) or "the target"

    info = CATEGORY_INFO.get(
        finding_type,
        {
            "label": (finding_type or "Security issue").replace("_", " ").title(),
            "why": "The recorded test observed behavior that warrants review.",
            "fix": "Review the affected endpoint and enforce the intended security control.",
        },
    )

    if status == "confirmed":
        title = f"{info['label']} on {location}"
    elif status == "candidate":
        title = f"Possible {info['label'].lower()} on {location} (unconfirmed)"
    else:
        title = f"{info['label']} on {location} ({status})"

    if status == "confirmed":
        impact = (
            "The test produced evidence that this behavior is reachable. "
            "If the endpoint is exposed to real users, this issue should be "
            "treated as a confirmed weakness until it is fixed and retested."
        )
    elif status == "candidate":
        impact = (
            "The available evidence suggests a weakness but does not prove "
            "it. Treat it as a lead for manual review, not as a confirmed "
            "vulnerability."
        )
    else:
        impact = (
            "This record is retained for traceability. Its status does not "
            "establish that the target is vulnerable."
        )

    return {
        **item,
        "title": title,
        "category_label": info["label"],
        "what_happened": item.get("description") or "",
        "why_it_matters": info["why"],
        "impact": impact,
        "remediation": info["fix"],
        "severity_reasoning": _SEVERITY_REASONING.get(
            severity,
            "No severity rationale was recorded for this finding.",
        ),
    }


def _build_report_summary(report: dict) -> dict:
    status = str(report.get("status") or "unknown")
    endpoints = int(report.get("total_endpoints") or 0)
    findings_count = int(report.get("findings_count") or 0)
    by_status = report.get("findings_by_status") or {}
    confirmed = int(by_status.get("confirmed") or 0)
    candidates = int(by_status.get("candidate") or 0)
    incomplete = list((report.get("assessment") or {}).get("incomplete_reasons") or [])

    if status == "failed":
        headline = "Assessment failed"
        verdict = (
            "The assessment did not complete successfully. Any findings "
            "recorded below are real observations, but they do not represent "
            "complete coverage of the target."
        )
    elif status == "partial":
        headline = "Assessment completed with limitations"
        verdict = (
            "The assessment finished and produced results, but one or more "
            "checks failed or could not be completed. Review the limitations "
            "before drawing conclusions about the target."
        )
    elif status in {"running", "pending"}:
        headline = "Assessment in progress"
        verdict = "The assessment has not finished. Results are not final."
    elif findings_count == 0:
        headline = "No confirmed vulnerabilities"
        verdict = (
            "The checks that ran did not confirm a vulnerability. This is not "
            "proof that the target is secure: coverage depends on the "
            "endpoints discovered and the checks that were permitted to run."
        )
    else:
        headline = f"{confirmed} confirmed and {candidates} candidate finding(s)"
        verdict = (
            "The findings below come from tests that actually ran against the "
            "target. Candidate findings need manual review before they are "
            "treated as vulnerabilities."
        )

    if endpoints == 0:
        coverage = "No API endpoints were discovered, so no endpoint-level security testing was possible."
    else:
        coverage = (
            f"{endpoints} endpoint(s) were inventoried. Discovery is bounded: "
            "endpoints that are neither documented nor linked may not appear."
        )

    return {
        "headline": headline,
        "verdict": verdict,
        "coverage": coverage,
        "confirmed_findings": confirmed,
        "candidate_findings": candidates,
        "limitations": incomplete,
    }


def humanize_finding(
    *,
    finding_type: str,
    severity: str,
    status: str,
    description: str,
    method: str | None,
    path: str | None,
) -> dict:
    """Return the same plain-language fields used by the report.

    The findings endpoint and the report must describe a finding the same
    way; both call this function so the two surfaces cannot drift apart.
    """
    return _humanize_report_finding(
        {
            "finding_type": finding_type,
            "severity": severity,
            "status": status,
            "description": description,
            "endpoint": {"method": method, "path": path},
        }
    )


def build_scan_report(scan_id: int, session) -> dict | None:
    """Build the persisted, human-readable report for one scan.

    Returns ``None`` when the scan does not exist. Raises database errors to
    the caller so a storage failure is never presented as an empty report.
    """
    scan = session.get(Scan, scan_id)
    if scan is None:
        return None


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
    spec_stage = persisted_stages.get("spec_discovery")
    if spec_stage and spec_stage.get("source_type") == "bounded_html_discovery":
        incomplete_reasons.append(
            "The endpoint inventory came from bounded same-origin HTML-link "
            "discovery, not an OpenAPI contract, and may omit unlinked API routes."
        )
    elif spec_stage and spec_stage.get("status") == "failed":
        incomplete_reasons.append(
            spec_stage.get("reason")
            or "Specification acquisition and supported discovery did not complete."
        )
    if total_endpoints == 0:
        incomplete_reasons.append(
            "No endpoints were discovered; there is no evidence of complete API coverage."
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
            "Authorization checks are not supported for this target; its "
            "endpoints were inventoried without authenticated authorization "
            "testing."
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
        bola_outcome = authorization_stage.get("bola_status")
        if not bola_outcome:
            authorization_outcome = authorization_stage.get("status")
            if authorization_outcome in {"not_supported", "not_run", "failed"}:
                bola_outcome = authorization_outcome
            else:
                bola_outcome = "performed" if bola_results else "not_applicable"
        if bola_confirmed:
            bola_status = "finding_confirmed"
        elif bola_candidates:
            bola_status = "candidate"
        elif bola_outcome == "performed":
            bola_status = "ran_no_finding"
        else:
            bola_status = bola_outcome
    else:
        bola_outcome = None
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
            "identity_contract_supported": (
                authorization_stage.get("identity_contract_supported")
                if authorization_stage
                else None
            ),
            "auth_profile_supported": (
                authorization_stage.get("auth_profile_supported")
                if authorization_stage
                else None
            ),
            "auth_profile_type": (
                authorization_stage.get("auth_profile_type")
                if authorization_stage
                else None
            ),
            "auth_scheme": (
                authorization_stage.get("auth_scheme")
                if authorization_stage
                else None
            ),
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
            "outcome": bola_outcome,
            "confirmed_findings": len(bola_confirmed),
            "candidate_findings": len(bola_candidates),
            "results": bola_results,
            "note": (
                "BOLA ran and produced no confirmed or candidate finding."
                if bola_status == "ran_no_finding"
                else "BOLA is only checked against eligible object-level "
                "endpoints on authorized origins."
                if bola_status not in {"finding_confirmed", "candidate"}
                else None
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
            "identity_contract_supported": (
                sensitive_stage.get("identity_contract_supported")
                if sensitive_stage
                else None
            ),
            "auth_profile_supported": (
                sensitive_stage.get("auth_profile_supported")
                if sensitive_stage
                else None
            ),
            "auth_profile_type": (
                sensitive_stage.get("auth_profile_type")
                if sensitive_stage
                else None
            ),
            "auth_scheme": (
                sensitive_stage.get("auth_scheme")
                if sensitive_stage
                else None
            ),
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

    report = {
        "scan_id": scan.id,
        "target_id": scan.target_id,
        "target": (
            {
                "id": target.id,
                "name": target.name,
                "base_url": target.base_url,
            }
            if target is not None
            else None
        ),
        "spec_source": (
            persisted_stages.get("spec_discovery", {}).get("source")
            if persisted_stages
            else None
        ),
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

    report["findings"] = [
        _humanize_report_finding(item) for item in report["findings"]
    ]
    report["summary"] = _build_report_summary(report)
    return report

