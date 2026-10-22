"""Deterministic, endpoint-specific post-condition checks. These
functions never send requests themselves - they classify outcomes
from already-captured evidence. A 2xx mutation response is never
treated as sufficient on its own; each endpoint's real-world effect
is independently checked.

Confirmation requires a successful, interpretable verification
response. A failed, malformed, or otherwise ambiguous verification is
never promoted to CONFIRMED.
"""

from typing import Optional

from api_security_system.request_executor import ExecutionResult

from .schemas import AttemptOutcome


def _body(result: ExecutionResult) -> dict:
    return result.response_body if isinstance(result.response_body, dict) else {}


def _status_is_success(result: ExecutionResult) -> bool:
    return 200 <= result.response_status < 300


def _status_is_definitive_rejection(result: ExecutionResult) -> bool:
    """True only when the target clearly rejected the credentials.

    A 5xx, timeout, redirect, or malformed 2xx response is not proof
    that an identity was deleted or that a password stopped working.
    """
    if result.response_status in (401, 403):
        return True
    body = _body(result)
    return result.response_status == 200 and body.get("status") == "fail"


def login_succeeded(result: ExecutionResult) -> bool:
    """The login endpoint returned a usable authenticated session."""
    body = _body(result)
    return (
        _status_is_success(result)
        and body.get("status") == "success"
        and bool(body.get("auth_token"))
    )


def login_definitively_rejected(result: ExecutionResult) -> bool:
    """The login endpoint clearly rejected the supplied credentials."""
    return _status_is_definitive_rejection(result)


def is_denied_response(result: ExecutionResult) -> bool:
    if result.response_status in (401, 403):
        return True
    body = _body(result)
    return (
        200 <= result.response_status < 500
        and not 300 <= result.response_status < 400
        and body.get("status") == "fail"
    )


def verify_email_change(new_email: str, verify_me: ExecutionResult) -> AttemptOutcome:
    """Called only when the attempt returned 2xx. Compares the victim's
    own GET /me response against the exact value the attacker set.

    The verification response must itself be a successful, structured
    response. A matching email in an error/inconclusive response does
    not prove the change took effect.
    """
    if not _status_is_success(verify_me):
        return AttemptOutcome.AMBIGUOUS

    body = _body(verify_me)
    if body.get("status") == "fail":
        return AttemptOutcome.AMBIGUOUS

    data = body.get("data")
    if not isinstance(data, dict):
        return AttemptOutcome.AMBIGUOUS

    if data.get("email") == new_email:
        return AttemptOutcome.CONFIRMED
    return AttemptOutcome.RULED_OUT


def verify_password_change(
    login_with_new_succeeded: bool,
    login_with_original_succeeded: Optional[bool],
) -> AttemptOutcome:
    """Called only when the attempt returned 2xx. A real password
    change is independently proven by successfully logging in with
    the attacker's chosen value via a different endpoint entirely."""
    if login_with_new_succeeded:
        return AttemptOutcome.CONFIRMED
    if login_with_original_succeeded:
        return AttemptOutcome.RULED_OUT
    # Neither the new nor the original password works: something
    # changed, but not to a value we can attribute with confidence.
    return AttemptOutcome.AMBIGUOUS


def verify_password_change_from_logins(
    login_new: ExecutionResult,
    login_original: Optional[ExecutionResult] = None,
) -> AttemptOutcome:
    """Classify a password-change verification using response evidence.

    Only a successful login with the attacker-chosen value confirms.
    This version distinguishes a definitive rejection from an
    inconclusive login failure, so a transient 5xx cannot confirm a
    change and cannot incorrectly rule one out either.
    """
    if login_succeeded(login_new):
        return AttemptOutcome.CONFIRMED

    if not login_definitively_rejected(login_new):
        return AttemptOutcome.AMBIGUOUS

    if login_original is None:
        return AttemptOutcome.AMBIGUOUS
    if login_succeeded(login_original):
        return AttemptOutcome.RULED_OUT
    return AttemptOutcome.AMBIGUOUS


def _contains_marker(body, markers: set[str]) -> bool:
    """True when any scalar leaf equals one of the given identity markers.

    Numeric and UUID identifiers are compared as their string form so an
    ``id: 42`` response can be tied to the identifier ``"42"`` resolved
    from that identity's own authenticated document.
    """
    if not markers:
        return False
    if isinstance(body, dict):
        return any(_contains_marker(value, markers) for value in body.values())
    if isinstance(body, list):
        return any(_contains_marker(item, markers) for item in body)
    if isinstance(body, bool) or body is None:
        return False
    if isinstance(body, (str, int, float)):
        return str(body).strip() in markers
    return False


def verify_cross_identity_read(
    own_response: ExecutionResult,
    cross_response: ExecutionResult,
    *,
    caller_markers: set[str],
    target_markers: set[str],
) -> AttemptOutcome:
    """Classify a read-only BOLA test that compares an authenticated
    caller's own-object read with a cross-object read.

    CONFIRMED requires all of: the caller's own read succeeded and
    carried the caller's ownership marker; the cross read returned 2xx
    with a structurally valid body; that body differs from the caller's
    own body; and it carries the target identity's marker without the
    caller's. A bare 2xx, a self-scoped response, an identical response
    (path ignored), or a marker-less body never confirms. 401/403 is a
    denial; 404 means the object was not exposed.
    """
    if is_denied_response(own_response) or own_response.response_status == 404:
        return AttemptOutcome.RULED_OUT
    if not _status_is_success(own_response):
        return AttemptOutcome.AMBIGUOUS

    own_body = own_response.response_body
    if not isinstance(own_body, (dict, list)):
        return AttemptOutcome.AMBIGUOUS
    if not _contains_marker(own_body, caller_markers):
        return AttemptOutcome.RULED_OUT

    if is_denied_response(cross_response):
        return AttemptOutcome.ACCESS_DENIED
    if cross_response.response_status == 404:
        return AttemptOutcome.RULED_OUT
    if not _status_is_success(cross_response):
        return AttemptOutcome.AMBIGUOUS

    cross_body = cross_response.response_body
    if not isinstance(cross_body, (dict, list)):
        return AttemptOutcome.AMBIGUOUS
    if cross_body == own_body:
        return AttemptOutcome.RULED_OUT

    target_present = _contains_marker(cross_body, target_markers)
    caller_present = _contains_marker(cross_body, caller_markers)
    if target_present and not caller_present:
        return AttemptOutcome.CONFIRMED
    if target_present and caller_present:
        return AttemptOutcome.AMBIGUOUS
    return AttemptOutcome.RULED_OUT


def verify_deletion(relogin_original) -> AttemptOutcome:
    """Deletion is proven by the victim's own known-good credentials no
    longer working.

    Accepts either a bool (legacy callers/tests) or the actual relogin
    ``ExecutionResult``. With a result, only a definitive authentication
    rejection confirms; a transport/HTTP/body ambiguity does not.
    """
    if isinstance(relogin_original, bool):
        return (
            AttemptOutcome.CONFIRMED
            if not relogin_original
            else AttemptOutcome.RULED_OUT
        )

    if login_succeeded(relogin_original):
        return AttemptOutcome.RULED_OUT
    if login_definitively_rejected(relogin_original):
        return AttemptOutcome.CONFIRMED
    return AttemptOutcome.AMBIGUOUS
