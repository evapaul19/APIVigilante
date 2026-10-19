"""Orchestration for the AuthZ/BOLA MVP. Identity-isolated (one
attacker, three single-purpose disposable victims - email, password,
delete, run in that order, deletion always last). Every target
request - registration, login, baseline, attempt, and verification -
counts against one shared request budget with no exceptions and no
bypass path. Origin-locked to the explicitly authorized local VAmPI
instance. Closed by default: requires allow_identity_registration=True.
"""

from typing import Optional

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
    get_session,
)
from api_security_system.auth import AuthContext, AuthenticationError, AuthModule, Credentials
from api_security_system.auth.auth_module import LOGIN_PATH
from api_security_system.db.redaction import redact_body_for_persistence, redact_headers_for_persistence
from api_security_system.llm import LLMClient
from api_security_system.request_executor import ExecutionRequest, ExecutionResult, RequestExecutor, TransportError

from .candidate_selector import select_bola_candidates
from .classifier import generate_ambiguous_rationale
from .identity_provisioner import provision_identity
from .schemas import AttemptOutcome, BolaCandidate, BolaCheckResult, BudgetExceededError, EndpointTestResult, UnauthorizedTargetError
from .verification import is_denied_response, verify_deletion, verify_email_change, verify_password_change

AUTHORIZED_ORIGIN = "http://localhost:5000"
DEFAULT_REQUEST_BUDGET = 20

EMAIL_OP = "api_views.users.update_email"
PASSWORD_OP = "api_views.users.update_password"
DELETE_OP = "api_views.users.delete_user"


class RequestBudget:
    def __init__(self, max_requests: int = DEFAULT_REQUEST_BUDGET) -> None:
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
    body = result.response_body or {}
    return result.response_status == 200 and body.get("status") == "success" and bool(body.get("auth_token"))


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


def _create_finding(scan_id, candidate, status, severity, description, execution_ids) -> int:
    with get_session() as session:
        finding = Finding(
            scan_id=scan_id, endpoint_id=candidate.endpoint_id, finding_type=FindingType.BOLA,
            severity=severity, description=description, status=status,
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        for execution_id in execution_ids:
            session.add(FindingEvidence(finding_id=finding.id, execution_id=execution_id))
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
    login_new_ok = _login_succeeded(login_new)

    login_original_ok = None
    if not login_new_ok:
        login_original = _attempt_login_capture(executor, victim.description, victim_password)
        execution_ids.append(_persist_execution(scan_id, candidate.endpoint_id, victim.id, login_original))
        login_original_ok = _login_succeeded(login_original)

    outcome = verify_password_change(login_new_ok, login_original_ok)
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

    outcome = verify_deletion(_login_succeeded(relogin))
    return _build_result(scan_id, candidate, outcome, execution_ids, llm_client)


_TEST_RUNNERS = {EMAIL_OP: _run_email_test, PASSWORD_OP: _run_password_test, DELETE_OP: _run_delete_test}
_TEST_ORDER = [EMAIL_OP, PASSWORD_OP, DELETE_OP]  # deletion always last


def run_bola_check(
    scan_id: int,
    allow_identity_registration: bool = False,
    llm_client: Optional[LLMClient] = None,
    request_budget: int = DEFAULT_REQUEST_BUDGET,
    executor_transport: Optional[httpx.BaseTransport] = None,
) -> BolaCheckResult:
    if not allow_identity_registration:
        raise PermissionError(
            "BOLA testing requires registering disposable identities against the "
            "target. Pass allow_identity_registration=True to explicitly approve this."
        )

    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan {scan_id} does not exist.")
        target = session.get(Target, scan.target_id)
        base_url = target.base_url

    if base_url != AUTHORIZED_ORIGIN:
        raise UnauthorizedTargetError(
            f"BOLA testing is only authorized against {AUTHORIZED_ORIGIN!r}, got {base_url!r}."
        )

    llm_client = llm_client or LLMClient()
    budget = RequestBudget(max_requests=request_budget)
    raw_executor = RequestExecutor(base_url=base_url, transport=executor_transport)
    executor = _BudgetedExecutor(raw_executor, budget)
    auth = AuthModule(executor)

    result = BolaCheckResult(scan_id=scan_id, target_base_url=base_url, requests_used=0, request_budget=request_budget)

    try:
        candidates = {c.operation_id: c for c in select_bola_candidates(scan_id, resource_type="user")}
        if not candidates:
            return result

        try:
            attacker_identity, attacker_ctx, _ = provision_identity(auth, scan_id, "bola_attacker")
        except (AuthenticationError, TransportError, BudgetExceededError) as exc:
            result.stopped_early = True
            result.stopped_reason = f"Attacker provisioning failed: {exc}"
            return result

        for operation_id in _TEST_ORDER:
            candidate = candidates.get(operation_id)
            if candidate is None:
                continue
            runner = _TEST_RUNNERS[operation_id]
            try:
                test_result = runner(auth, executor, scan_id, candidate, attacker_identity.id, attacker_ctx, llm_client)
                result.endpoint_results.append(test_result)
            except BudgetExceededError as exc:
                result.stopped_early = True
                result.stopped_reason = str(exc)
                break
            except (AuthenticationError, TransportError) as exc:
                result.endpoint_results.append(
                    EndpointTestResult(
                        operation_id=candidate.operation_id, path=candidate.path,
                        outcome=AttemptOutcome.AMBIGUOUS, rationale=f"Test could not complete: {exc}",
                    )
                )
    finally:
        executor.close()
        result.requests_used = budget.used

    return result