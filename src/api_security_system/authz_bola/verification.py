"""Deterministic, endpoint-specific post-condition checks. These
functions never send requests themselves - they classify outcomes
from already-captured evidence. A 2xx mutation response is never
treated as sufficient on its own; each endpoint's real-world effect
is independently checked.
"""

from typing import Optional

from api_security_system.request_executor import ExecutionResult

from .schemas import AttemptOutcome


def is_denied_response(result: ExecutionResult) -> bool:
    if result.response_status in (401, 403):
        return True
    body = result.response_body or {}
    return body.get("status") == "fail"


def verify_email_change(new_email: str, verify_me: ExecutionResult) -> AttemptOutcome:
    """Called only when the attempt returned 2xx. Compares the victim's
    own GET /me response against the exact value the attacker set."""
    data = (verify_me.response_body or {}).get("data", {})
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


def verify_deletion(relogin_original_succeeded: bool) -> AttemptOutcome:
    """Called only when the attempt returned 2xx. Deletion is proven by
    the victim's own original, known-good credentials no longer
    working."""
    if not relogin_original_succeeded:
        return AttemptOutcome.CONFIRMED
    return AttemptOutcome.RULED_OUT