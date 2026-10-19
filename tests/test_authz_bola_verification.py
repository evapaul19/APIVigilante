"""Pure unit tests for deterministic post-condition verification. No
DB, no network - exercises endpoint-specific confirmation logic
directly, including false-positive avoidance (RULED_OUT, not
false_positive/INFO) and the rule that neither-password-works never
confirms."""

from datetime import datetime, timezone

from api_security_system.authz_bola.schemas import AttemptOutcome
from api_security_system.authz_bola.verification import (
    is_denied_response,
    verify_deletion,
    verify_email_change,
    verify_password_change,
)
from api_security_system.request_executor import ExecutionResult


def _result(status: int, body: dict | None) -> ExecutionResult:
    return ExecutionResult(
        request_method="GET", request_path="/x", request_headers={},
        response_status=status, response_headers={}, response_body=body,
        latency_ms=1, executed_at=datetime.now(timezone.utc),
    )


def test_is_denied_response_401():
    assert is_denied_response(_result(401, None)) is True


def test_is_denied_response_403():
    assert is_denied_response(_result(403, None)) is True


def test_is_denied_response_fail_status_body():
    assert is_denied_response(_result(200, {"status": "fail"})) is True


def test_is_denied_response_success_not_denied():
    assert is_denied_response(_result(200, {"status": "success"})) is False


def test_verify_email_change_confirmed_when_new_email_present():
    verify_me = _result(200, {"data": {"email": "attacker@evil.invalid"}, "status": "success"})
    assert verify_email_change("attacker@evil.invalid", verify_me) == AttemptOutcome.CONFIRMED


def test_verify_email_change_ruled_out_when_email_unchanged():
    verify_me = _result(200, {"data": {"email": "original@mail.com"}, "status": "success"})
    assert verify_email_change("attacker@evil.invalid", verify_me) == AttemptOutcome.RULED_OUT


def test_verify_password_change_confirmed_when_new_password_logs_in():
    assert verify_password_change(True, None) == AttemptOutcome.CONFIRMED


def test_verify_password_change_ruled_out_when_only_original_still_works():
    assert verify_password_change(False, True) == AttemptOutcome.RULED_OUT


def test_verify_password_change_ambiguous_when_neither_password_works():
    assert verify_password_change(False, False) == AttemptOutcome.AMBIGUOUS


def test_verify_deletion_confirmed_when_relogin_fails():
    assert verify_deletion(False) == AttemptOutcome.CONFIRMED


def test_verify_deletion_ruled_out_when_relogin_still_succeeds():
    assert verify_deletion(True) == AttemptOutcome.RULED_OUT