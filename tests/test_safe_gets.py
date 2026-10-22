"""Focused tests for the shared GET side-effect classifier.

No database, no network.
"""

from api_security_system.safe_gets import get_get_side_effect_reason


def test_safe_get_has_no_restriction():
    assert get_get_side_effect_reason("/users/v1/{username}") is None
    assert get_get_side_effect_reason("/users/v1", "api_views.users.get_user") is None


def test_camel_case_operation_names_are_recognized():
    assert get_get_side_effect_reason("/safe", "resetUsers") is not None
    assert get_get_side_effect_reason("/safe", "createUser") is not None
    assert get_get_side_effect_reason("/safe", "deleteUser") is not None


def test_camel_case_paths_are_recognized():
    assert get_get_side_effect_reason("/admin/resetUsers") is not None
    assert get_get_side_effect_reason("/admin/deleteUser") is not None


def test_non_get_is_not_restricted_by_this_classifier():
    assert get_get_side_effect_reason("/admin/reset", "resetUsers", method="POST") is None
