"""Integration tests for run_bola_check. Real Postgres (skipped if
DATABASE_URL unset, same pattern as other DB-backed tests in this
suite), mocked HTTP transport via RequestExecutor's injectable
transport - no real network calls, no dependency on a live VAmPI
instance.
"""

import os
import pytest
from pathlib import Path

# Resolve repository root from this file's location so the real spec
# works regardless of CWD when pytest is invoked from elsewhere.
TEST_FILE = Path(__file__).resolve()
PROJECT_ROOT = TEST_FILE.parent.parent  # .../api-security-system

from sqlmodel import select

from api_security_system.authz_bola import (
    AttemptOutcome,
    UnauthorizedTargetError,
    run_bola_check,
)
from api_security_system.authz_bola.schemas import BudgetExceededError
from api_security_system.db import (
    Endpoint,
    Finding,
    FindingEvidence,
    Scan,
    Target,
    TestExecution,
    TestIdentity,
    get_session,
)
from api_security_system.db.redaction import REDACTED_VALUE
from api_security_system.llm import LLMResponse, Provider
from api_security_system.recon.parser import parse_openapi_spec

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set",
)

REAL_SPEC_PATH = str(PROJECT_ROOT / "targets/vampi-openapi.yml")
AUTHORIZED_ORIGIN = "http://localhost:5000"


class _FakeResult:
    def __init__(self, status, body, headers=None, request_body=None):
        self.response_status = status
        self.response_body = body
        self.response_headers = {}
        self.request_headers = headers or {}
        self.request_body = request_body
        self.latency_ms = 1


class _FakeExecutor:
    """Scripted executor: the admin control always succeeds, and the
    non-administrator attempt is configurable per test."""

    def __init__(self, low_attempt):
        self.low_attempt = low_attempt
        self.deleted = set()
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        headers = request.headers or {}
        if request.method == "DELETE":
            username = request.path.rsplit("/", 1)[-1]
            self.deleted.add(username)
            if headers.get("Authorization") == "admin":
                return _FakeResult(
                    200,
                    {"status": "success", "message": "User deleted."},
                    headers,
                )
            return self.low_attempt
        if request.method == "POST":
            username = (request.json_body or {}).get("username")
            if username in self.deleted:
                return _FakeResult(
                    200, {"status": "fail", "message": "Username does not exist"}, headers
                )
            return _FakeResult(200, {"status": "success", "auth_token": "token"}, headers)
        raise AssertionError(request)


def _bfla_candidate():
    from api_security_system.authz_bola.schemas import BflaCandidate

    return BflaCandidate(
        endpoint_id=1,
        method="DELETE",
        path="/users/v1/{username}",
        operation_id="api_views.users.delete_user",
        id_param_name="username",
        signal="Only Admins",
        rationale="Delete user (Only Admins)",
    )


def _install_bfla_stubs(monkeypatch, service):
    from types import SimpleNamespace

    created = []
    execution_ids = iter(range(500, 600))

    def fake_provision_identity(auth, scan_id, role_label):
        return (
            SimpleNamespace(id=1, description=f"{role_label}-user"),
            SimpleNamespace(auth_header_value="low"),
            "pw",
        )

    def fake_persist_execution(scan_id, endpoint_id, identity_id, result):
        return next(execution_ids)

    def fake_create_finding(scan_id, candidate, status, severity, description, evidence, finding_type=None):
        created.append(
            {
                "severity": severity,
                "finding_type": finding_type,
                "description": description,
                "evidence": evidence,
            }
        )
        return 999

    monkeypatch.setattr(service, "provision_identity", fake_provision_identity)
    monkeypatch.setattr(service, "_persist_execution", fake_persist_execution)
    monkeypatch.setattr(service, "_create_finding", fake_create_finding)
    return created


def _run_bfla_delete(service, low_attempt, monkeypatch):
    from types import SimpleNamespace

    created = _install_bfla_stubs(monkeypatch, service)
    result = service._run_bfla_delete(
        scan_id=1,
        candidate=_bfla_candidate(),
        executor=_FakeExecutor(low_attempt),
        auth=SimpleNamespace(),
        low_identity=SimpleNamespace(id=11),
        low_ctx=SimpleNamespace(auth_header_value="low"),
        admin_identity=SimpleNamespace(id=10),
        admin_ctx=SimpleNamespace(auth_header_value="admin"),
    )
    return result, created


def test_bfla_confirmed_when_non_admin_deletes_user(monkeypatch):
    from api_security_system.authz_bola import service
    from api_security_system.db import FindingSeverity, FindingType

    result, created = _run_bfla_delete(
        service,
        _FakeResult(200, {"status": "success", "message": "User deleted."}),
        monkeypatch,
    )

    assert result.outcome is AttemptOutcome.CONFIRMED
    assert result.check_type == "bfla"
    assert result.finding_id == 999
    assert len(created) == 1
    assert created[0]["finding_type"] is FindingType.BFLA
    assert created[0]["severity"] is FindingSeverity.HIGH
    assert "non-administrator" in created[0]["description"]
    # find evidence: control delete, control relogin, low attempt, test relogin
    assert len(created[0]["evidence"]) == 4


def test_bfla_ruled_out_when_non_admin_is_denied(monkeypatch):
    from api_security_system.authz_bola import service

    result, created = _run_bfla_delete(
        service,
        _FakeResult(
            401,
            {"status": "fail", "message": "Only Admins may delete users!"},
        ),
        monkeypatch,
    )

    assert result.outcome is AttemptOutcome.RULED_OUT
    assert result.check_type == "bfla"
    assert result.finding_id is None
    assert created == []


def test_bfla_unsupported_without_verified_admin(monkeypatch):
    from api_security_system.auth import AuthenticationError
    from api_security_system.authz_bola import service

    class _DeniedAuth:
        def login(self, *args, **kwargs):
            raise AuthenticationError("denied")

    monkeypatch.setattr(
        service, "select_bfla_candidates", lambda scan_id: [_bfla_candidate()]
    )
    monkeypatch.setenv("VAMPI_ADMIN_USERNAME", "configured-admin")
    monkeypatch.setenv("VAMPI_ADMIN_PASSWORD", "configured-password")

    results, status, reason = service.run_bfla_checks(
        scan_id=1, executor=None, auth=_DeniedAuth()
    )

    assert status == "unsupported"
    assert "administrator login failed" in reason
    assert len(results) == 1
    assert results[0].outcome is AttemptOutcome.NOT_APPLICABLE
    assert results[0].check_type == "bfla"


def _read_candidate(path="/users/v1/{username}", id_param_name="username"):
    from api_security_system.authz_bola.schemas import BolaCandidate

    return BolaCandidate(
        endpoint_id=42,
        method="GET",
        path=path,
        operation_id="api_views.users.get_by_username",
        id_param_name=id_param_name,
    )


def _victim_identity():
    from types import SimpleNamespace

    return SimpleNamespace(id=99, description="bola_read_victim-user")


class _ReadExecutor:
    """Scripted read executor: own-object and cross-object GETs return
    pre-built results, keyed off the substituted path identifier."""

    def __init__(self, own_result, cross_result):
        self.own_result = own_result
        self.cross_result = cross_result
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        if request.path.endswith("attacker-user"):
            return self.own_result
        if request.path.endswith("bola_read_victim-user"):
            return self.cross_result
        raise AssertionError(request)


def _run_read(service, own_result, cross_result, monkeypatch, llm_client=None):
    from types import SimpleNamespace

    created = _install_bfla_stubs(monkeypatch, service)
    executor = _ReadExecutor(own_result, cross_result)
    result = service._run_read_test(
        executor=executor,
        scan_id=1,
        candidate=_read_candidate(),
        attacker_id=7,
        attacker_ctx=SimpleNamespace(
            username="attacker-user", auth_header_value="token"
        ),
        llm_client=llm_client,
        victim=_victim_identity(),
    )
    return result, created, executor


_OWN_BODY = {"username": "attacker-user", "email": "attacker-user@example.invalid"}
_VICTIM_BODY = {
    "username": "bola_read_victim-user",
    "email": "bola_read_victim-user@example.invalid",
}


def test_read_bola_confirmed_when_attacker_reads_another_users_data(monkeypatch):
    from api_security_system.authz_bola import service
    from api_security_system.db import FindingSeverity

    result, created, executor = _run_read(
        service, _FakeResult(200, dict(_OWN_BODY)), _FakeResult(200, dict(_VICTIM_BODY)), monkeypatch
    )

    assert result.outcome is AttemptOutcome.CONFIRMED
    assert result.check_type == "bola"
    assert result.finding_id == 999
    assert len(created) == 1
    assert created[0]["severity"] is FindingSeverity.HIGH
    assert len(executor.requests) == 2
    assert "bola_read_victim-user" not in str(created[0]["description"])


def test_read_bola_no_finding_when_only_own_resource_is_returned(monkeypatch):
    from api_security_system.authz_bola import service

    result, created, _ = _run_read(
        service, _FakeResult(200, dict(_OWN_BODY)), _FakeResult(200, dict(_OWN_BODY)), monkeypatch
    )

    assert result.outcome is AttemptOutcome.RULED_OUT
    assert result.finding_id is None
    assert created == []


def test_read_bola_access_denied_on_403_creates_no_finding(monkeypatch):
    from api_security_system.authz_bola import service

    result, created, _ = _run_read(
        service, _FakeResult(200, dict(_OWN_BODY)), _FakeResult(403, {"detail": "Forbidden"}), monkeypatch
    )

    assert result.outcome is AttemptOutcome.ACCESS_DENIED
    assert result.finding_id is None
    assert created == []


def test_read_bola_ruled_out_on_404_creates_no_finding(monkeypatch):
    from api_security_system.authz_bola import service

    result, created, _ = _run_read(
        service, _FakeResult(200, dict(_OWN_BODY)), _FakeResult(404, {"detail": "Not found"}), monkeypatch
    )

    assert result.outcome is AttemptOutcome.RULED_OUT
    assert result.finding_id is None
    assert created == []


def test_read_bola_ruled_out_for_public_style_response(monkeypatch):
    from api_security_system.authz_bola import service

    result, created, _ = _run_read(
        service, _FakeResult(200, dict(_OWN_BODY)), _FakeResult(200, {"status": "success", "profile": "public"}), monkeypatch
    )

    assert result.outcome is AttemptOutcome.RULED_OUT
    assert created == []


def test_read_bola_ambiguous_on_malformed_cross_body(monkeypatch):
    from api_security_system.authz_bola import service
    from api_security_system.db import FindingSeverity

    result, created, _ = _run_read(
        service, _FakeResult(200, dict(_OWN_BODY)), _FakeResult(200, None), monkeypatch, llm_client=None
    )

    assert result.outcome is AttemptOutcome.AMBIGUOUS
    assert len(created) == 1
    assert created[0]["severity"] is FindingSeverity.MEDIUM


def test_read_bola_respects_request_budget(monkeypatch):
    from types import SimpleNamespace

    from api_security_system.authz_bola import service
    from api_security_system.authz_bola.schemas import BudgetExceededError

    _install_bfla_stubs(monkeypatch, service)
    budget = service.RequestBudget(max_requests=1)
    executor = service._BudgetedExecutor(
        _ReadExecutor(_FakeResult(200, dict(_OWN_BODY)), _FakeResult(200, dict(_VICTIM_BODY))),
        budget,
    )

    with pytest.raises(BudgetExceededError):
        service._run_read_test(
            executor=executor,
            scan_id=1,
            candidate=_read_candidate(),
            attacker_id=7,
            attacker_ctx=SimpleNamespace(
                username="attacker-user", auth_header_value="token"
            ),
            llm_client=None,
            victim=_victim_identity(),
        )
    assert budget.used == 1


def test_run_read_checks_provisions_one_shared_victim_and_uses_get_only(monkeypatch):
    from types import SimpleNamespace

    from api_security_system.authz_bola import service

    provision_calls = {"count": 0}

    def fake_provision(auth, scan_id, role_label):
        provision_calls["count"] += 1
        return _victim_identity(), SimpleNamespace(auth_header_value="victim"), "pw"

    _install_bfla_stubs(monkeypatch, service)
    monkeypatch.setattr(service, "provision_identity", fake_provision)

    executor = _ReadExecutor(
        _FakeResult(200, dict(_OWN_BODY)), _FakeResult(200, dict(_VICTIM_BODY))
    )
    candidates = [
        _read_candidate(),
        _read_candidate(path="/accounts/{username}"),
    ]
    results, stopped, reason = service._run_read_checks(
        scan_id=1,
        executor=executor,
        auth=SimpleNamespace(),
        attacker_identity=SimpleNamespace(id=7),
        attacker_ctx=SimpleNamespace(
            username="attacker-user", auth_header_value="token"
        ),
        candidates=candidates,
        llm_client=None,
    )

    assert provision_calls["count"] == 1
    assert stopped is False
    assert reason is None
    assert len(results) == 2
    assert all(item.outcome is AttemptOutcome.CONFIRMED for item in results)
    assert {request.method for request in executor.requests} == {"GET"}
    assert len(executor.requests) == 4


def test_run_read_checks_stops_early_when_budget_runs_out(monkeypatch):
    from types import SimpleNamespace

    from api_security_system.authz_bola import service

    def fake_provision(auth, scan_id, role_label):
        return _victim_identity(), SimpleNamespace(auth_header_value="victim"), "pw"

    _install_bfla_stubs(monkeypatch, service)
    monkeypatch.setattr(service, "provision_identity", fake_provision)

    budget = service.RequestBudget(max_requests=2)
    executor = service._BudgetedExecutor(
        _ReadExecutor(
            _FakeResult(200, dict(_OWN_BODY)), _FakeResult(200, dict(_VICTIM_BODY))
        ),
        budget,
    )
    candidates = [
        _read_candidate(),
        _read_candidate(path="/accounts/{username}"),
    ]
    results, stopped, reason = service._run_read_checks(
        scan_id=1,
        executor=executor,
        auth=SimpleNamespace(),
        attacker_identity=SimpleNamespace(id=7),
        attacker_ctx=SimpleNamespace(
            username="attacker-user", auth_header_value="token"
        ),
        candidates=candidates,
        llm_client=None,
    )

    assert stopped is True
    assert budget.used == 2
    assert results[0].outcome is AttemptOutcome.CONFIRMED
    assert results[-1].outcome is AttemptOutcome.AMBIGUOUS
    assert "budget" in (reason or "")