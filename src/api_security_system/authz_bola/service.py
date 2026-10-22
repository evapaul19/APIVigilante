"""Orchestration for authorization checks. BOLA tests object-level access
with an attacker and single-purpose disposable victims; BFLA tests whether
a non-administrator can execute operations documented as administrator-only,
using an administrator control to establish the privilege boundary. Every
target request - registration, login, baseline, attempt, verification, and
control - counts against one shared request budget with no bypass path.
Origin-locked to the explicitly authorized local VAmPI instance, and closed
by default: requires allow_identity_registration=True.
"""

import re
from typing import TYPE_CHECKING, Optional

import os

if TYPE_CHECKING:
    from api_security_system.targets.security import ResolvedTarget

import httpx
from sqlmodel import select

from api_security_system.db import (
    Finding,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
    FindingType,
    Scan,
    Target,
    TestExecution,
    TestIdentity,
    get_session,
)
from api_security_system.auth import AuthContext, AuthenticationError, AuthModule, Credentials
from api_security_system.auth.auth_module import LOGIN_PATH
from api_security_system.db.redaction import (
    redact_body_for_persistence,
    redact_headers_for_persistence,
    sanitize_text_for_persistence,
)
from api_security_system.llm import LLMClient
from api_security_system.request_executor import ExecutionRequest, ExecutionResult, RequestExecutor, TransportError
from api_security_system.safe_gets import get_get_side_effect_reason

from .candidate_selector import (
    identifier_is_username,
    is_read_candidate,
    select_bfla_candidates,
    select_bola_candidates,
)
from .classifier import generate_ambiguous_rationale
from .identity_provisioner import provision_identity
from .schemas import AttemptOutcome, BolaCandidate, BolaCheckResult, BudgetExceededError, EndpointTestResult, UnauthorizedTargetError
from .verification import (
    is_denied_response,
    login_succeeded,
    verify_cross_identity_read,
    verify_deletion,
    verify_email_change,
    verify_password_change_from_logins,
)

DEFAULT_REQUEST_BUDGET = 20

EMAIL_OP = "api_views.users.update_email"
PASSWORD_OP = "api_views.users.update_password"
DELETE_OP = "api_views.users.delete_user"

_EXPECTED_METHODS = {
    EMAIL_OP: {"PUT", "PATCH", "POST"},
    PASSWORD_OP: {"PUT", "PATCH", "POST"},
    DELETE_OP: {"DELETE"},
}
_PATH_TEMPLATE_PARAMETER = re.compile(r"\{([^{}]+)\}")


class RequestBudget:
    def __init__(self, max_requests: int = DEFAULT_REQUEST_BUDGET) -> None:
        if (
            isinstance(max_requests, bool)
            or not isinstance(max_requests, int)
            or max_requests < 0
        ):
            raise ValueError("request budget must be a non-negative integer.")
        self.max_requests = max_requests
        self.used = 0

    def consume(self) -> None:
        if self.used >= self.max_requests:
            raise BudgetExceededError(f"Request budget of {self.max_requests} exhausted.")
        self.used += 1


class _BudgetedExecutor:
    """Wraps RequestExecutor so every call counts against the shared
    budget - including calls made indirectly through AuthModule, which
    only depends on execute()/close() and never sees the raw
    executor. No request path in this module can bypass it."""

    def __init__(self, executor: RequestExecutor, budget: RequestBudget) -> None:
        self._executor = executor
        self._budget = budget

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        self._budget.consume()
        return self._executor.execute(request)

    def close(self) -> None:
        self._executor.close()


def _persist_execution(scan_id: int, endpoint_id: int, identity_id: Optional[int], result: ExecutionResult) -> int:
    """Persists a redacted copy of the evidence. result itself (and any
    reference to it held elsewhere, e.g. in verification.py's already-
    completed outcome checks) is never mutated - redaction only
    affects what is written to Postgres."""
    with get_session() as session:
        row = TestExecution(
            scan_id=scan_id,
            endpoint_id=endpoint_id,
            identity_id=identity_id,
            request_headers=redact_headers_for_persistence(result.request_headers),
            request_body=redact_body_for_persistence(result.request_body),
            response_status=result.response_status,
            response_headers=redact_headers_for_persistence(result.response_headers),
            response_body=redact_body_for_persistence(result.response_body),
            latency_ms=result.latency_ms,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return row.id

def _login_succeeded(result: ExecutionResult) -> bool:
    """Compatibility wrapper around the shared deterministic classifier."""
    return login_succeeded(result)


def _attempt_login_capture(executor, username: str, password: str) -> ExecutionResult:
    """Direct login call via the budgeted RequestExecutor, reusing the
    same verified LOGIN_PATH AuthModule uses - bypasses AuthModule
    only because AuthModule.login() does not expose the raw
    ExecutionResult needed as persisted evidence here."""
    return executor.execute(
        ExecutionRequest(method="POST", path=LOGIN_PATH, json_body={"username": username, "password": password})
    )


def _build_result(
    scan_id: int, candidate: BolaCandidate, outcome: AttemptOutcome,
    execution_ids: list[int], llm_client: LLMClient,
) -> EndpointTestResult:
    finding_id = None
    rationale = None

    if outcome == AttemptOutcome.CONFIRMED:
        finding_id = _create_finding(
            scan_id, candidate, FindingStatus.CONFIRMED, FindingSeverity.HIGH,
            f"Cross-identity BOLA confirmed on {candidate.method} {candidate.path}: "
            f"deterministic post-condition verification established unauthorized "
            f"access/modification of another identity's resource.",
            execution_ids,
        )
    elif outcome == AttemptOutcome.AMBIGUOUS:
        evidence_summary = (
            f"Endpoint: {candidate.method} {candidate.path}\n"
            f"Outcome: ambiguous - response did not clearly match a denied, "
            f"confirmed, or ruled-out pattern.\nExecution IDs: {execution_ids}"
        )
        rationale = generate_ambiguous_rationale(evidence_summary, llm_client)
        finding_id = _create_finding(
            scan_id, candidate, FindingStatus.CANDIDATE, FindingSeverity.MEDIUM,
            f"Ambiguous cross-identity test result on {candidate.method} {candidate.path}. "
            f"LLM rationale (not a confirmation): {rationale}",
            execution_ids,
        )
    # ACCESS_DENIED and RULED_OUT: no Finding row. The outcome and the
    # preserved TestExecution evidence are the record - per design,
    # a successful-but-unverified response is never mislabeled as a
    # false_positive/INFO finding; it is simply not a finding at all.

    return EndpointTestResult(
        operation_id=candidate.operation_id,
        path=candidate.path,
        outcome=outcome,
        attempt_execution_id=execution_ids[0] if execution_ids else None,
        verification_execution_ids=execution_ids[1:],
        finding_id=finding_id,
        rationale=rationale,
    )


def _enum_value(value):
    return getattr(value, "value", value)


def _create_finding(
    scan_id,
    candidate,
    status,
    severity,
    description,
    execution_ids,
    finding_type=FindingType.BOLA,
) -> int:
    """Create or reuse the finding for this scan/endpoint/type.

    A repeated assessment step must not create a second finding for the
    same endpoint and check family. Existing evidence links are also
    reused, and a prior candidate is upgraded if deterministic
    verification now confirms it. A prior confirmation is never
    downgraded by a later ambiguous result.
    """
    description = (
        sanitize_text_for_persistence(description, max_length=2000) or ""
    )

    with get_session() as session:
        finding = session.exec(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.endpoint_id == candidate.endpoint_id,
                Finding.finding_type == _enum_value(finding_type),
            )
        ).first()

        requested_status = _enum_value(status)
        if finding is None:
            finding = Finding(
                scan_id=scan_id,
                endpoint_id=candidate.endpoint_id,
                finding_type=finding_type,
                severity=severity,
                description=description,
                status=status,
            )
            session.add(finding)
            session.commit()
            session.refresh(finding)
        elif (
            requested_status == FindingStatus.CONFIRMED.value
            and _enum_value(finding.status) != FindingStatus.CONFIRMED.value
        ):
            finding.status = status
            finding.severity = severity
            finding.description = description
            session.add(finding)
            session.commit()

        existing_evidence = {
            link.execution_id
            for link in session.exec(
                select(FindingEvidence).where(
                    FindingEvidence.finding_id == finding.id
                )
            ).all()
        }
        for execution_id in execution_ids:
            if execution_id not in existing_evidence:
                session.add(
                    FindingEvidence(
                        finding_id=finding.id,
                        execution_id=execution_id,
                    )
                )
                existing_evidence.add(execution_id)
        session.commit()
        return finding.id


def _run_email_test(auth, executor, scan_id, candidate, attacker_id, attacker_ctx, llm_client) -> EndpointTestResult:
    victim, victim_ctx, _ = provision_identity(auth, scan_id, "bola_victim_email")
    new_email = f"attacker_set_{victim.description}@example.invalid"
    path = candidate.path.replace(f"{{{candidate.id_param_name}}}", victim.description)

    attempt = executor.execute(
        ExecutionRequest(method=candidate.method, path=path,
                          headers={"Authorization": attacker_ctx.auth_header_value},
                          json_body={"email": new_email})
    )
    execution_ids = [_persist_execution(scan_id, candidate.endpoint_id, attacker_id, attempt)]

    if is_denied_response(attempt):
        return _build_result(scan_id, candidate, AttemptOutcome.ACCESS_DENIED, execution_ids, llm_client)
    if not (200 <= attempt.response_status < 300):
        return _build_result(scan_id, candidate, AttemptOutcome.AMBIGUOUS, execution_ids, llm_client)

    verify = executor.execute(
        ExecutionRequest(method="GET", path="/me", headers={"Authorization": victim_ctx.auth_header_value})
    )
    execution_ids.append(_persist_execution(scan_id, candidate.endpoint_id, victim.id, verify))

    outcome = verify_email_change(new_email, verify)
    return _build_result(scan_id, candidate, outcome, execution_ids, llm_client)


def _run_password_test(auth, executor, scan_id, candidate, attacker_id, attacker_ctx, llm_client) -> EndpointTestResult:
    victim, victim_ctx, victim_password = provision_identity(auth, scan_id, "bola_victim_password")
    new_password = f"Attacker_Set_{victim.description}!"
    path = candidate.path.replace(f"{{{candidate.id_param_name}}}", victim.description)

    attempt = executor.execute(
        ExecutionRequest(method=candidate.method, path=path,
                          headers={"Authorization": attacker_ctx.auth_header_value},
                          json_body={"password": new_password})
    )
    execution_ids = [_persist_execution(scan_id, candidate.endpoint_id, attacker_id, attempt)]

    if is_denied_response(attempt):
        return _build_result(scan_id, candidate, AttemptOutcome.ACCESS_DENIED, execution_ids, llm_client)
    if not (200 <= attempt.response_status < 300):
        return _build_result(scan_id, candidate, AttemptOutcome.AMBIGUOUS, execution_ids, llm_client)

    login_new = _attempt_login_capture(executor, victim.description, new_password)
    execution_ids.append(_persist_execution(scan_id, candidate.endpoint_id, victim.id, login_new))

    login_original = None
    if not _login_succeeded(login_new):
        login_original = _attempt_login_capture(executor, victim.description, victim_password)
        execution_ids.append(_persist_execution(scan_id, candidate.endpoint_id, victim.id, login_original))

    outcome = verify_password_change_from_logins(login_new, login_original)
    return _build_result(scan_id, candidate, outcome, execution_ids, llm_client)


def _run_delete_test(auth, executor, scan_id, candidate, attacker_id, attacker_ctx, llm_client) -> EndpointTestResult:
    victim, victim_ctx, victim_password = provision_identity(auth, scan_id, "bola_victim_delete")
    path = candidate.path.replace(f"{{{candidate.id_param_name}}}", victim.description)

    attempt = executor.execute(
        ExecutionRequest(method=candidate.method, path=path,
                          headers={"Authorization": attacker_ctx.auth_header_value})
    )
    execution_ids = [_persist_execution(scan_id, candidate.endpoint_id, attacker_id, attempt)]

    if is_denied_response(attempt):
        return _build_result(scan_id, candidate, AttemptOutcome.ACCESS_DENIED, execution_ids, llm_client)
    if not (200 <= attempt.response_status < 300):
        return _build_result(scan_id, candidate, AttemptOutcome.AMBIGUOUS, execution_ids, llm_client)

    relogin = _attempt_login_capture(executor, victim.description, victim_password)
    execution_ids.append(_persist_execution(scan_id, candidate.endpoint_id, victim.id, relogin))

    outcome = verify_deletion(relogin)
    return _build_result(scan_id, candidate, outcome, execution_ids, llm_client)


def _normalized_identifier_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _extract_document_identifier(body, id_param_name: str) -> Optional[str]:
    """Return the unique scalar value matching ``id_param_name`` in an
    authenticated identity document (normally GET /me).

    Key matching is normalized for case/underscores, with only id/uuid
    suffix aliases for user-resource paths. This keeps the check
    conservative: a value is used as an ownership identifier only when
    the identity's own response names it unambiguously. Multiple
    conflicting values are treated as insufficient evidence.
    """
    target = _normalized_identifier_name(id_param_name)
    if not target:
        return None

    # The resource graph only selects user resources. A path parameter such
    # as user_id/user_uuid can therefore use the matching id/uuid field from
    # that identity's own /me document. Conflicting values still fail closed.
    targets = {target}
    if target != "id" and target.endswith("id"):
        targets.add("id")
    if target != "uuid" and target.endswith("uuid"):
        targets.add("uuid")

    found: set[str] = set()

    def visit(value, depth: int) -> None:
        if depth > 8:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if (
                    _normalized_identifier_name(key) in targets
                    and isinstance(item, (str, int, float))
                    and not isinstance(item, bool)
                    and str(item).strip()
                ):
                    found.add(str(item).strip())
                elif isinstance(item, (dict, list)):
                    visit(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                visit(item, depth + 1)

    visit(body, 0)
    return next(iter(found)) if len(found) == 1 else None


def _resolve_identity_identifier(
    executor,
    scan_id: int,
    candidate: BolaCandidate,
    identity_id: int,
    context: AuthContext,
    id_param_name: str,
    cache: dict[tuple[str, str], tuple[Optional[str], Optional[str]]],
) -> tuple[Optional[str], Optional[str]]:
    """Resolve a non-username object identifier from the identity's own
    authenticated document.

    A username is directly usable. For numeric/UUID parameters we read
    GET /me and accept a single unambiguous id/uuid scalar. If the target
    does not expose one, the candidate is skipped rather than guessed. This
    keeps cross-identity requests tied to ownership evidence rather than
    to an assumed ID.
    """
    if identifier_is_username(id_param_name):
        return context.username, None

    key = (context.username, _normalized_identifier_name(id_param_name))
    if key in cache:
        return cache[key]

    response = executor.execute(
        ExecutionRequest(
            method="GET",
            path="/me",
            headers={"Authorization": context.auth_header_value},
        )
    )

    _persist_execution(scan_id, candidate.endpoint_id, identity_id, response)

    if not (200 <= response.response_status < 300):
        result = (
            None,
            (
                "The identity's own document could not be read "
                f"(GET /me returned HTTP {response.response_status}); "
                "the non-username identifier was not substituted."
            ),
        )
    else:
        value = _extract_document_identifier(
            response.response_body, id_param_name
        )
        if value is None:
            result = (
                None,
                (
                    "GET /me did not expose a unique id/uuid field for "
                    f"'{id_param_name}', so ownership of a numeric/UUID "
                    "identifier could not be established."
                ),
            )
        else:
            result = (value, None)

    cache[key] = result
    return result


def _run_read_test(
    executor,
    scan_id,
    candidate,
    attacker_id,
    attacker_ctx,
    llm_client,
    victim,
    own_identifier: Optional[str] = None,
    cross_identifier: Optional[str] = None,
) -> EndpointTestResult:
    """Read-only BOLA: an authenticated attacker reads its own object,
    then the same object type for a different identity's identifier.

    Confirmation is delegated to verify_cross_identity_read, which
    requires deterministic ownership evidence in both responses; a
    successful 2xx cross read alone is never sufficient.

    The victim identity is provisioned once per run by the caller and
    reused across read candidates; this function never provisions or
    deletes identities.
    """
    attacker_identifier = own_identifier or attacker_ctx.username
    victim_identifier = cross_identifier or victim.description
    own_path = candidate.path.replace(
        f"{{{candidate.id_param_name}}}", attacker_identifier
    )
    cross_path = candidate.path.replace(
        f"{{{candidate.id_param_name}}}", victim_identifier
    )
    headers = {"Authorization": attacker_ctx.auth_header_value}

    own_response = executor.execute(
        ExecutionRequest(method=candidate.method, path=own_path, headers=headers)
    )
    execution_ids = [
        _persist_execution(scan_id, candidate.endpoint_id, attacker_id, own_response)
    ]

    cross_response = executor.execute(
        ExecutionRequest(method=candidate.method, path=cross_path, headers=headers)
    )
    execution_ids.append(
        _persist_execution(scan_id, candidate.endpoint_id, attacker_id, cross_response)
    )

    outcome = verify_cross_identity_read(
        own_response,
        cross_response,
        caller_markers={
            attacker_ctx.username,
            f"{attacker_ctx.username}@example.invalid",
            str(attacker_identifier),
        },
        target_markers={
            victim.description,
            f"{victim.description}@example.invalid",
            str(victim_identifier),
        },
    )
    return _build_result(scan_id, candidate, outcome, execution_ids, llm_client)


def _run_read_checks(
    scan_id: int,
    executor,
    auth,
    attacker_identity,
    attacker_ctx,
    candidates: list[BolaCandidate],
    llm_client: Optional[LLMClient],
) -> tuple[list[EndpointTestResult], bool, Optional[str]]:
    """Run every read-only BOLA candidate with one shared victim identity.

    The victim is provisioned lazily on the first candidate, so an
    already-exhausted budget never creates an unused identity, and it is
    reused for every subsequent candidate. Reads never mutate the target.

    Returns (results, stopped_early, stopped_reason).
    """
    results: list[EndpointTestResult] = []
    victim = None
    victim_ctx = None
    victim_error: Optional[str] = None
    stopped_early = False
    stopped_reason: Optional[str] = None
    identifier_cache: dict[
        tuple[str, str], tuple[Optional[str], Optional[str]]
    ] = {}

    for candidate in candidates:
        restriction = get_get_side_effect_reason(
            candidate.path,
            candidate.operation_id,
            {
                "summary": candidate.summary,
                "description": candidate.description,
            },
            candidate.method,
        )
        if restriction:
            results.append(
                EndpointTestResult(
                    operation_id=candidate.operation_id,
                    path=candidate.path,
                    outcome=AttemptOutcome.NOT_APPLICABLE,
                    rationale=restriction,
                )
            )
            continue

        if victim_error is not None:
            results.append(
                EndpointTestResult(
                    operation_id=candidate.operation_id,
                    path=candidate.path,
                    outcome=AttemptOutcome.NOT_APPLICABLE,
                    rationale=victim_error,
                )
            )
            continue

        if victim is None:
            try:
                victim, victim_ctx, _ = provision_identity(
                    auth, scan_id, "bola_read_victim"
                )
            except BudgetExceededError as exc:
                stopped_early = True
                stopped_reason = str(exc)
                results.append(
                    EndpointTestResult(
                        operation_id=candidate.operation_id,
                        path=candidate.path,
                        outcome=AttemptOutcome.AMBIGUOUS,
                        rationale=(
                            "Read-only BOLA test did not complete because the "
                            f"request budget was exhausted: {exc}"
                        ),
                    )
                )
                break
            except (AuthenticationError, TransportError) as exc:
                victim_error = (
                    "Read-only BOLA could not provision a victim identity: "
                    f"{exc}"
                )
                results.append(
                    EndpointTestResult(
                        operation_id=candidate.operation_id,
                        path=candidate.path,
                        outcome=AttemptOutcome.NOT_APPLICABLE,
                        rationale=victim_error,
                    )
                )
                continue

        try:
            if identifier_is_username(candidate.id_param_name):
                own_identifier, own_reason = attacker_ctx.username, None
                cross_identifier, cross_reason = victim.description, None
            else:
                own_identifier, own_reason = _resolve_identity_identifier(
                    executor,
                    scan_id,
                    candidate,
                    attacker_identity.id,
                    attacker_ctx,
                    candidate.id_param_name,
                    identifier_cache,
                )
                if own_identifier is None:
                    cross_identifier, cross_reason = None, None
                else:
                    cross_identifier, cross_reason = _resolve_identity_identifier(
                        executor,
                        scan_id,
                        candidate,
                        victim.id,
                        victim_ctx,
                        candidate.id_param_name,
                        identifier_cache,
                    )
        except BudgetExceededError as exc:
            stopped_early = True
            stopped_reason = str(exc)
            results.append(
                EndpointTestResult(
                    operation_id=candidate.operation_id,
                    path=candidate.path,
                    outcome=AttemptOutcome.AMBIGUOUS,
                    rationale=(
                        "Read-only BOLA test did not complete because the "
                        f"request budget was exhausted: {exc}"
                    ),
                )
            )
            break
        except (AuthenticationError, TransportError) as exc:
            results.append(
                EndpointTestResult(
                    operation_id=candidate.operation_id,
                    path=candidate.path,
                    outcome=AttemptOutcome.AMBIGUOUS,
                    rationale=(
                        "Read-only BOLA identifier resolution could not "
                        f"complete: {exc}"
                    ),
                )
            )
            continue

        if own_identifier is None or cross_identifier is None:
            results.append(
                EndpointTestResult(
                    operation_id=candidate.operation_id,
                    path=candidate.path,
                    outcome=AttemptOutcome.NOT_APPLICABLE,
                    rationale=own_reason or cross_reason or (
                        "A reliable object identifier could not be established "
                        "for both identities."
                    ),
                )
            )
            continue

        if str(own_identifier) == str(cross_identifier):
            results.append(
                EndpointTestResult(
                    operation_id=candidate.operation_id,
                    path=candidate.path,
                    outcome=AttemptOutcome.NOT_APPLICABLE,
                    rationale=(
                        "The two identities resolved to the same object "
                        "identifier; no cross-identity read can be tested."
                    ),
                )
            )
            continue

        try:
            results.append(
                _run_read_test(
                    executor,
                    scan_id,
                    candidate,
                    attacker_identity.id,
                    attacker_ctx,
                    llm_client,
                    victim,
                    own_identifier=own_identifier,
                    cross_identifier=cross_identifier,
                )
            )
        except BudgetExceededError as exc:
            stopped_early = True
            stopped_reason = str(exc)
            results.append(
                EndpointTestResult(
                    operation_id=candidate.operation_id,
                    path=candidate.path,
                    outcome=AttemptOutcome.AMBIGUOUS,
                    rationale=(
                        "Read-only BOLA test did not complete because the "
                        f"request budget was exhausted: {exc}"
                    ),
                )
            )
            break
        except (AuthenticationError, TransportError) as exc:
            results.append(
                EndpointTestResult(
                    operation_id=candidate.operation_id,
                    path=candidate.path,
                    outcome=AttemptOutcome.AMBIGUOUS,
                    rationale=f"Test could not complete: {exc}",
                )
            )

    return results, stopped_early, stopped_reason


_ADMIN_USERNAME_ENV = "VAMPI_ADMIN_USERNAME"
_ADMIN_PASSWORD_ENV = "VAMPI_ADMIN_PASSWORD"


def _record_identity(scan_id: int, role_label: str, username: str) -> TestIdentity:
    """Record the non-disposable administrator identity without its secret."""
    with get_session() as session:
        identity = TestIdentity(
            scan_id=scan_id, role_label=role_label, description=username
        )
        session.add(identity)
        session.commit()
        session.refresh(identity)
        return identity


def _me_admin_flag(executor, context) -> tuple[int, Optional[bool]]:
    """Read the authenticated identity's admin flag from GET /me."""
    response = executor.execute(
        ExecutionRequest(
            method="GET",
            path="/me",
            headers={"Authorization": context.auth_header_value},
        )
    )
    body = response.response_body
    data = body.get("data") if isinstance(body, dict) else None
    flag = data.get("admin") if isinstance(data, dict) else None
    return response.response_status, flag if isinstance(flag, bool) else None


def _bfla_not_applicable(candidate, reason: str) -> EndpointTestResult:
    return EndpointTestResult(
        operation_id=candidate.operation_id,
        path=candidate.path,
        outcome=AttemptOutcome.NOT_APPLICABLE,
        check_type="bfla",
        rationale=reason,
    )


def _run_bfla_delete(
    scan_id,
    candidate,
    executor,
    auth,
    low_identity,
    low_ctx,
    admin_identity,
    admin_ctx,
) -> EndpointTestResult:
    """Test an administrator-only DELETE as a non-administrator.

    A control execution establishes that an administrator can perform the
    operation and that it takes effect. Only then is a lower-privileged
    attempt meaningful.
    """
    id_param = candidate.id_param_name
    path_parameters = _PATH_TEMPLATE_PARAMETER.findall(candidate.path)
    if (
        not id_param
        or path_parameters != [id_param]
        or candidate.method.upper() != "DELETE"
    ):
        return _bfla_not_applicable(
            candidate,
            "BFLA runner cannot safely substitute this operation's path "
            "identifier or verify its method.",
        )

    def target_path(username: str) -> str:
        return candidate.path.replace(f"{{{id_param}}}", username)

    # Control: an administrator performs the operation on a disposable victim.
    control_identity, _, control_password = provision_identity(
        auth, scan_id, "bfla_control_victim"
    )
    control_username = control_identity.description

    control_attempt = executor.execute(
        ExecutionRequest(
            method=candidate.method,
            path=target_path(control_username),
            headers={"Authorization": admin_ctx.auth_header_value},
        )
    )
    control_execution_id = _persist_execution(
        scan_id, candidate.endpoint_id, admin_identity.id, control_attempt
    )

    if is_denied_response(control_attempt):
        return _bfla_not_applicable(
            candidate,
            "Administrator control was denied, so this operation cannot be "
            "established as administrator-only; no BFLA conclusion is possible.",
        )
    if not (200 <= control_attempt.response_status < 300):
        return _bfla_not_applicable(
            candidate,
            f"Administrator control returned HTTP {control_attempt.response_status}; "
            "the operation's privilege requirement could not be established.",
        )

    control_relogin = _attempt_login_capture(
        executor, control_username, control_password
    )
    control_relogin_id = _persist_execution(
        scan_id, candidate.endpoint_id, control_identity.id, control_relogin
    )
    control_effect = verify_deletion(control_relogin)
    if control_effect is AttemptOutcome.RULED_OUT:
        return _bfla_not_applicable(
            candidate,
            "Administrator control returned success but the victim could still "
            "log in; the operation's effect could not be verified.",
        )
    if control_effect is not AttemptOutcome.CONFIRMED:
        return _bfla_not_applicable(
            candidate,
            "Administrator control returned success, but the victim's relogin "
            "was inconclusive; the operation's effect could not be verified.",
        )

    control_note = (
        f"Administrator control succeeded (HTTP {control_attempt.response_status}; "
        "the control victim could no longer authenticate)."
    )

    # Test: a non-administrator attempts the same operation.
    test_identity, _, test_password = provision_identity(
        auth, scan_id, "bfla_test_victim"
    )
    test_username = test_identity.description

    low_attempt = executor.execute(
        ExecutionRequest(
            method=candidate.method,
            path=target_path(test_username),
            headers={"Authorization": low_ctx.auth_header_value},
        )
    )
    low_execution_id = _persist_execution(
        scan_id, candidate.endpoint_id, low_identity.id, low_attempt
    )

    if is_denied_response(low_attempt):
        return EndpointTestResult(
            operation_id=candidate.operation_id,
            path=candidate.path,
            outcome=AttemptOutcome.RULED_OUT,
            check_type="bfla",
            attempt_execution_id=low_execution_id,
            verification_execution_ids=[control_execution_id, control_relogin_id],
            rationale=(
                f"{control_note} The non-administrator identity was denied "
                f"(HTTP {low_attempt.response_status}); function-level "
                "authorization is enforced."
            ),
        )

    if not (200 <= low_attempt.response_status < 300):
        return EndpointTestResult(
            operation_id=candidate.operation_id,
            path=candidate.path,
            outcome=AttemptOutcome.AMBIGUOUS,
            check_type="bfla",
            attempt_execution_id=low_execution_id,
            verification_execution_ids=[control_execution_id, control_relogin_id],
            rationale=(
                f"{control_note} The non-administrator attempt returned unexpected "
                f"HTTP {low_attempt.response_status}; the result is inconclusive."
            ),
        )

    test_relogin = _attempt_login_capture(executor, test_username, test_password)
    test_relogin_id = _persist_execution(
        scan_id, candidate.endpoint_id, test_identity.id, test_relogin
    )
    test_effect = verify_deletion(test_relogin)

    if test_effect is AttemptOutcome.RULED_OUT:
        return EndpointTestResult(
            operation_id=candidate.operation_id,
            path=candidate.path,
            outcome=AttemptOutcome.AMBIGUOUS,
            check_type="bfla",
            attempt_execution_id=low_execution_id,
            verification_execution_ids=[
                control_execution_id,
                control_relogin_id,
                test_relogin_id,
            ],
            rationale=(
                f"{control_note} The non-administrator attempt returned 2xx, but "
                "the victim could still authenticate; the operation's effect was "
                "not established. Recorded as a candidate only."
            ),
        )

    if test_effect is not AttemptOutcome.CONFIRMED:
        return EndpointTestResult(
            operation_id=candidate.operation_id,
            path=candidate.path,
            outcome=AttemptOutcome.AMBIGUOUS,
            check_type="bfla",
            attempt_execution_id=low_execution_id,
            verification_execution_ids=[
                control_execution_id,
                control_relogin_id,
                test_relogin_id,
            ],
            rationale=(
                f"{control_note} The non-administrator attempt returned 2xx, but "
                "the victim's relogin was inconclusive; the operation's effect "
                "could not be verified. Recorded as a candidate only."
            ),
        )

    execution_ids = [control_execution_id, control_relogin_id, low_execution_id, test_relogin_id]
    description = (
        f"BFLA confirmed on {candidate.method} {candidate.path}: a "
        "non-administrator identity executed an operation documented as "
        f"administrator-only ('{candidate.signal}'). {control_note} The "
        f"non-administrator attempt returned HTTP {low_attempt.response_status} "
        "and the victim could no longer authenticate, establishing unauthorized "
        "function access with a verified effect."
    )
    finding_id = _create_finding(
        scan_id,
        candidate,
        FindingStatus.CONFIRMED,
        FindingSeverity.HIGH,
        description,
        execution_ids,
        finding_type=FindingType.BFLA,
    )

    return EndpointTestResult(
        operation_id=candidate.operation_id,
        path=candidate.path,
        outcome=AttemptOutcome.CONFIRMED,
        check_type="bfla",
        attempt_execution_id=low_execution_id,
        verification_execution_ids=[
            control_execution_id,
            control_relogin_id,
            test_relogin_id,
        ],
        finding_id=finding_id,
        rationale=description,
    )


def run_bfla_checks(
    scan_id: int,
    executor,
    auth,
    llm_client: Optional[LLMClient] = None,
) -> tuple[list[EndpointTestResult], str, Optional[str]]:
    """Run BFLA checks independently of the BOLA candidate graph.

    Returns (results, status, reason), where status is one of
    "performed", "not_applicable", "unsupported", or "stopped_early".
    """
    candidates = select_bfla_candidates(scan_id)
    if not candidates:
        return (
            [],
            "not_applicable",
            "No authenticated operation is documented as administrator-only.",
        )

    supported = [
        candidate
        for candidate in candidates
        if candidate.method.upper() == "DELETE" and candidate.id_param_name
    ]
    unsupported = [candidate for candidate in candidates if candidate not in supported]

    results = [
        _bfla_not_applicable(
            candidate,
            "BFLA runner currently supports administrator-only DELETE "
            "operations with a substitutable path identifier.",
        )
        for candidate in unsupported
    ]

    if not supported:
        return (
            results,
            "not_applicable",
            "No administrator-only operation matched a supported execution shape.",
        )

    admin_username = os.environ.get(_ADMIN_USERNAME_ENV, "").strip()
    admin_password = os.environ.get(_ADMIN_PASSWORD_ENV, "").strip()
    if not admin_username or not admin_password:
        reason = (
            "BFLA requires explicit administrator credentials. Set "
            f"{_ADMIN_USERNAME_ENV} and {_ADMIN_PASSWORD_ENV} in the "
            "environment to enable privileged-control testing."
        )
        results.extend(_bfla_not_applicable(c, reason) for c in supported)
        return results, "unsupported", reason

    try:
        admin_ctx = auth.login(
            Credentials(
                username=admin_username,
                password=admin_password,
                email=None,
            ),
            role_label="bfla_admin",
        )
    except (AuthenticationError, TransportError) as exc:
        reason = (
            "No higher-privileged identity is available: administrator login "
            f"failed ({type(exc).__name__}). Set {_ADMIN_USERNAME_ENV} and "
            f"{_ADMIN_PASSWORD_ENV} to enable BFLA testing."
        )
        results.extend(_bfla_not_applicable(c, reason) for c in supported)
        return results, "unsupported", reason

    admin_me_status, admin_flag = _me_admin_flag(executor, admin_ctx)
    if admin_me_status != 200 or admin_flag is not True:
        reason = (
            "The configured higher-privileged identity did not verify as an "
            "administrator (GET /me did not return data.admin=true); BFLA "
            "cannot distinguish privilege levels without it."
        )
        results.extend(_bfla_not_applicable(c, reason) for c in supported)
        return results, "unsupported", reason

    admin_identity = _record_identity(scan_id, "bfla_admin", admin_username)

    low_identity, low_ctx, _ = provision_identity(
        auth, scan_id, "bfla_low_privilege"
    )
    low_me_status, low_flag = _me_admin_flag(executor, low_ctx)
    if low_me_status != 200 or low_flag is not False:
        reason = (
            "Could not establish a non-administrator identity: the registered "
            "test user did not verify as data.admin=false."
        )
        results.extend(_bfla_not_applicable(c, reason) for c in supported)
        return results, "unsupported", reason

    for candidate in supported:
        try:
            results.append(
                _run_bfla_delete(
                    scan_id,
                    candidate,
                    executor,
                    auth,
                    low_identity,
                    low_ctx,
                    admin_identity,
                    admin_ctx,
                )
            )
        except BudgetExceededError as exc:
            results.append(
                EndpointTestResult(
                    operation_id=candidate.operation_id,
                    path=candidate.path,
                    outcome=AttemptOutcome.AMBIGUOUS,
                    check_type="bfla",
                    rationale=f"BFLA test did not complete: {exc}",
                )
            )
            return results, "stopped_early", str(exc)

    return results, "performed", None


_TEST_RUNNERS = {EMAIL_OP: _run_email_test, PASSWORD_OP: _run_password_test, DELETE_OP: _run_delete_test}

_TEST_ORDER = [EMAIL_OP, PASSWORD_OP, DELETE_OP]  # deletion always last


def run_bola_check(
    scan_id: int,
    allow_identity_registration: bool = False,
    llm_client: Optional[LLMClient] = None,
    request_budget: int = DEFAULT_REQUEST_BUDGET,
    executor_transport: Optional[httpx.BaseTransport] = None,
    resolved_target: Optional["ResolvedTarget"] = None,
) -> BolaCheckResult:
    if not allow_identity_registration:
        raise PermissionError(
            "BOLA testing requires registering disposable identities against the "
            "target. Pass allow_identity_registration=True to explicitly approve this."
        )

    budget = RequestBudget(max_requests=request_budget)

    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan {scan_id} does not exist.")
        target = session.get(Target, scan.target_id)
        base_url = target.base_url

    from api_security_system.targets.security import (
        authorized_origins,
        is_authorized_origin,
        resolve_target,
        validate_resolved_target,
    )

    if not is_authorized_origin(base_url):
        raise UnauthorizedTargetError(
            "BOLA testing is only authorized against the explicitly "
            f"allowlisted origins {sorted(authorized_origins())}, got {base_url!r}."
        )

    llm_client = llm_client or LLMClient()
    if executor_transport is None:
        # Reuse the assessment's validated addresses when available. The
        # manual route has no such result, so it must resolve once here.
        # Injected test transports remain unchanged.
        if resolved_target is None:
            pinned_addresses = resolve_target(base_url).addresses
        else:
            pinned_addresses = validate_resolved_target(
                base_url, resolved_target
            )
        raw_executor = RequestExecutor(
            base_url=base_url,
            pinned_addresses=pinned_addresses,
        )
    else:
        raw_executor = RequestExecutor(
            base_url=base_url,
            transport=executor_transport,
        )
    executor = _BudgetedExecutor(raw_executor, budget)
    auth = AuthModule(executor)

    result = BolaCheckResult(scan_id=scan_id, target_base_url=base_url, requests_used=0, request_budget=request_budget)

    try:
        # BOLA: object-level, Resource-Graph selected.
        bola_candidates = {
            c.operation_id: c
            for c in select_bola_candidates(scan_id, resource_type="user")
        }
        if bola_candidates:
            try:
                attacker_identity, attacker_ctx, _ = provision_identity(
                    auth, scan_id, "bola_attacker"
                )
            except (AuthenticationError, TransportError, BudgetExceededError) as exc:
                result.stopped_early = True
                result.stopped_reason = f"Attacker provisioning failed: {exc}"
            else:
                for operation_id in _TEST_ORDER:
                    candidate = bola_candidates.get(operation_id)
                    if candidate is None:
                        continue
                    runner = _TEST_RUNNERS.get(operation_id)
                    if runner is None:
                        continue

                    expected_methods = _EXPECTED_METHODS.get(operation_id, set())
                    path_parameters = _PATH_TEMPLATE_PARAMETER.findall(
                        candidate.path
                    )
                    if (
                        candidate.method.upper() not in expected_methods
                        or path_parameters != [candidate.id_param_name]
                    ):
                        result.endpoint_results.append(
                            EndpointTestResult(
                                operation_id=candidate.operation_id,
                                path=candidate.path,
                                outcome=AttemptOutcome.NOT_APPLICABLE,
                                rationale=(
                                    "BOLA runner cannot safely substitute this "
                                    "operation's method/path shape, so no request "
                                    "was sent."
                                ),
                            )
                        )
                        continue

                    try:
                        test_result = runner(
                            auth,
                            executor,
                            scan_id,
                            candidate,
                            attacker_identity.id,
                            attacker_ctx,
                            llm_client,
                        )
                        result.endpoint_results.append(test_result)
                    except BudgetExceededError as exc:
                        result.stopped_early = True
                        result.stopped_reason = str(exc)
                        result.endpoint_results.append(
                            EndpointTestResult(
                                operation_id=candidate.operation_id,
                                path=candidate.path,
                                outcome=AttemptOutcome.AMBIGUOUS,
                                rationale=(
                                    "BOLA test did not complete because the "
                                    f"request budget was exhausted: {exc}"
                                ),
                            )
                        )
                        break
                    except (AuthenticationError, TransportError) as exc:
                        result.endpoint_results.append(
                            EndpointTestResult(
                                operation_id=candidate.operation_id,
                                path=candidate.path,
                                outcome=AttemptOutcome.AMBIGUOUS,
                                rationale=f"Test could not complete: {exc}",
                            )
                        )

                # Read-only BOLA: authenticated GETs of another identity's
                # object. Runs after the write checks so the higher-severity
                # side-effecting tests always get first use of the budget.
                # One victim identity is shared across all read candidates.
                read_candidates = [
                    c for c in bola_candidates.values() if is_read_candidate(c)
                ]
                read_results, read_stopped, read_reason = _run_read_checks(
                    scan_id,
                    executor,
                    auth,
                    attacker_identity,
                    attacker_ctx,
                    read_candidates,
                    llm_client,
                )
                result.endpoint_results.extend(read_results)
                if read_stopped:
                    result.stopped_early = True
                    result.stopped_reason = read_reason

        # BFLA: function-level, selected independently of the BOLA graph.
        try:
            bfla_results, bfla_status, bfla_reason = run_bfla_checks(
                scan_id, executor, auth, llm_client
            )
            result.bfla_results = bfla_results
            result.bfla_status = bfla_status
            result.bfla_reason = bfla_reason
        except BudgetExceededError as exc:
            result.bfla_status = "stopped_early"
            result.bfla_reason = str(exc)
            result.stopped_early = True
            result.stopped_reason = str(exc)
        except (AuthenticationError, TransportError) as exc:
            result.bfla_status = "unsupported"
            result.bfla_reason = f"BFLA could not run: {exc}"

    finally:
        executor.close()
        result.requests_used = budget.used

    return result