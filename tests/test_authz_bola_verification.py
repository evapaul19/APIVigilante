"""Pure unit tests for deterministic post-condition verification. No
DB, no network - exercises endpoint-specific confirmation logic
directly, including false-positive avoidance (RULED_OUT, not
false_positive/INFO) and the rule that neither-password-works never
confirms."""

from datetime import datetime, timezone

from api_security_system.authz_bola.candidate_selector import is_read_candidate
from api_security_system.authz_bola.schemas import AttemptOutcome, BolaCandidate
from api_security_system.authz_bola.verification import (
    is_denied_response,
    verify_cross_identity_read,
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


_CALLER_MARKERS = {"attacker", "attacker@example.invalid"}
_TARGET_MARKERS = {"victim", "victim@example.invalid"}


def _read(own_status, own_body, cross_status, cross_body):
    return verify_cross_identity_read(
        _result(own_status, own_body),
        _result(cross_status, cross_body),
        caller_markers=_CALLER_MARKERS,
        target_markers=_TARGET_MARKERS,
    )


def test_cross_identity_read_confirmed_on_other_users_protected_data():
    assert (
        _read(
            200,
            {"username": "attacker", "email": "attacker@example.invalid"},
            200,
            {"username": "victim", "email": "victim@example.invalid"},
        )
        is AttemptOutcome.CONFIRMED
    )


def test_cross_identity_read_ruled_out_when_own_resource_only():
    assert (
        _read(
            200,
            {"username": "attacker", "email": "attacker@example.invalid"},
            200,
            {"username": "attacker", "email": "attacker@example.invalid"},
        )
        is AttemptOutcome.RULED_OUT
    )


def test_cross_identity_read_access_denied_on_403():
    assert (
        _read(
            200,
            {"username": "attacker", "email": "attacker@example.invalid"},
            403,
            {"detail": "Forbidden"},
        )
        is AttemptOutcome.ACCESS_DENIED
    )


def test_cross_identity_read_ruled_out_on_404():
    assert (
        _read(
            200,
            {"username": "attacker", "email": "attacker@example.invalid"},
            404,
            {"detail": "Not found"},
        )
        is AttemptOutcome.RULED_OUT
    )


def test_cross_identity_read_ruled_out_for_path_independent_public_resource():
    public = {"profile": "public"}
    assert _read(200, {"username": "attacker"}, 200, public) is AttemptOutcome.RULED_OUT


def test_cross_identity_read_ruled_out_without_ownership_evidence():
    assert (
        _read(
            200,
            {"username": "attacker", "email": "attacker@example.invalid"},
            200,
            {"profile": "generic", "status": "success"},
        )
        is AttemptOutcome.RULED_OUT
    )


def test_cross_identity_read_ambiguous_on_malformed_cross_body():
    assert (
        _read(
            200,
            {"username": "attacker", "email": "attacker@example.invalid"},
            200,
            None,
        )
        is AttemptOutcome.AMBIGUOUS
    )


def test_cross_identity_read_ruled_out_when_own_baseline_denied():
    assert (
        _read(
            403,
            {"detail": "Forbidden"},
            200,
            {"username": "victim", "email": "victim@example.invalid"},
        )
        is AttemptOutcome.RULED_OUT
    )


def test_cross_identity_read_ruled_out_when_own_baseline_has_no_marker():
    assert (
        _read(
            200,
            {"status": "success"},
            200,
            {"username": "victim", "email": "victim@example.invalid"},
        )
        is AttemptOutcome.RULED_OUT
    )


def _candidate(method, path, id_param_name="username"):
    return BolaCandidate(
        endpoint_id=1,
        method=method,
        path=path,
        operation_id="op",
        id_param_name=id_param_name,
    )


def test_is_read_candidate_accepts_get_with_one_identifier():
    assert is_read_candidate(_candidate("GET", "/users/v1/{username}")) is True


def test_is_read_candidate_rejects_write_methods():
    assert is_read_candidate(_candidate("PUT", "/users/v1/{username}")) is False


def test_is_read_candidate_rejects_get_without_path_identifier():
    assert is_read_candidate(_candidate("GET", "/users/v1")) is False


def test_is_read_candidate_rejects_get_with_multiple_identifiers():
    candidate = _candidate("GET", "/a/{x}/b/{y}", id_param_name="x")
    assert is_read_candidate(candidate) is False