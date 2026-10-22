"""Unit tests for sensitive-data response inspection. No database, no
network: the detector's pure inspection function is exercised directly."""

from api_security_system.sensitive_data.patterns import (
    field_category,
    is_masked_or_placeholder,
    normalize_path,
    value_kind,
)
from api_security_system.sensitive_data.schemas import SensitiveOutcome
from api_security_system.sensitive_data.service import (
    _sanitize_for_persistence,
    inspect_body,
)


def _inspect(body, **kwargs):
    return inspect_body(body, endpoint_path=kwargs.pop("endpoint_path", "/x"), **kwargs)


def test_anonymous_plaintext_passwords_are_confirmed():
    outcome, observations, subjects, rationale = _inspect(
        {"users": [{"username": "alice", "password": "hunter2"}]},
        endpoint_path="/users/v1/_debug",
    )
    assert outcome is SensitiveOutcome.CONFIRMED
    assert {o.path for o in observations} == {"users[*].password"}
    assert "hunter2" not in rationale
    assert subjects == {"alice"}


def test_masked_password_is_not_a_finding():
    outcome, _, _, rationale = _inspect(
        {"users": [{"username": "alice", "password": "********"}]}
    )
    assert outcome is SensitiveOutcome.RULED_OUT
    assert "masked" in rationale


def test_field_name_alone_does_not_flag():
    outcome, observations, _, _ = _inspect(
        {"email": "not-an-address", "password": "*****"}
    )
    assert outcome is SensitiveOutcome.RULED_OUT
    assert observations


def test_own_profile_email_is_ruled_out():
    outcome, _, _, rationale = _inspect(
        {"data": {"username": "probe", "email": "probe@example.invalid"}},
        endpoint_path="/me",
        authenticated=True,
        identity_username="probe",
    )
    assert outcome is SensitiveOutcome.RULED_OUT
    assert "own" in rationale


def test_anonymous_profile_email_is_a_candidate_not_ruled_out():
    # Regression: the path parameter is filled with the probe username so the
    # request is well-formed, but no credentials were sent, so the returned
    # profile cannot be attributed to the caller and must not be ruled out.
    outcome, _, subjects, rationale = _inspect(
        {"username": "probe", "email": "probe@example.invalid"},
        endpoint_path="/users/v1/{username}",
        authenticated=False,
        identity_username="probe",
    )
    assert outcome is SensitiveOutcome.CANDIDATE
    assert subjects == {"probe"}
    assert "anonymous caller" in rationale
    assert "own" not in rationale
    assert "probe@example.invalid" not in rationale


def test_anonymous_profile_email_for_another_username_is_a_candidate():
    outcome, _, _, rationale = _inspect(
        {"username": "alice", "email": "alice@example.invalid"},
        endpoint_path="/users/v1/{username}",
        authenticated=False,
        identity_username="probe",
    )
    assert outcome is SensitiveOutcome.CANDIDATE
    assert "identities other than the caller" in rationale


def test_authenticated_own_profile_by_username_is_ruled_out():
    outcome, _, _, rationale = _inspect(
        {"username": "probe", "email": "probe@example.invalid"},
        endpoint_path="/users/v1/{username}",
        authenticated=True,
        identity_username="probe",
    )
    assert outcome is SensitiveOutcome.RULED_OUT
    assert "own" in rationale


def test_anonymous_me_endpoint_email_is_a_candidate():
    outcome, _, _, rationale = _inspect(
        {"data": {"username": "probe", "email": "probe@example.invalid"}},
        endpoint_path="/me",
        authenticated=False,
        identity_username="probe",
    )
    assert outcome is SensitiveOutcome.CANDIDATE
    assert "anonymous caller" in rationale


def test_anonymous_profile_without_sensitive_data_is_ruled_out():
    outcome, _, _, _ = _inspect(
        {"username": "probe", "status": "active"},
        endpoint_path="/users/v1/{username}",
        authenticated=False,
        identity_username="probe",
    )
    assert outcome is SensitiveOutcome.RULED_OUT


def test_anonymous_profile_plaintext_password_is_confirmed():
    outcome, _, _, _ = _inspect(
        {"username": "probe", "password": "hunter2"},
        endpoint_path="/users/v1/{username}",
        authenticated=False,
        identity_username="probe",
    )
    assert outcome is SensitiveOutcome.CONFIRMED


def test_other_identities_emails_are_a_candidate():
    outcome, _, subjects, rationale = _inspect(
        {
            "users": [
                {"username": "alice", "email": "alice@example.invalid"},
                {"username": "bob", "email": "bob@example.invalid"},
            ]
        },
        authenticated=False,
        identity_username="probe",
    )
    assert outcome is SensitiveOutcome.CANDIDATE
    assert subjects == {"alice", "bob"}
    assert "alice@example.invalid" not in rationale


def test_token_from_issuance_operation_is_ruled_out():
    token = "aaaabbbb.ccccdddd.eeeeffff"
    outcome, _, _, rationale = _inspect(
        {"auth_token": token, "status": "success"},
        token_issuance=True,
    )
    assert outcome is SensitiveOutcome.RULED_OUT
    assert token not in rationale


def test_private_key_is_confirmed_even_with_generic_field_name():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA\n"
        "-----END RSA PRIVATE KEY-----"
    )
    outcome, observations, _, _ = _inspect({"key": pem})
    assert outcome is SensitiveOutcome.CONFIRMED
    assert observations[0].category == "private_key"
    assert observations[0].value_kind == "pem_private_key"


def test_password_for_other_identity_authenticated_is_confirmed():
    outcome, _, _, _ = _inspect(
        {
            "users": [
                {"username": "alice", "password": "hunter2"},
                {"username": "bob", "password": "hunter3"},
            ]
        },
        authenticated=True,
        identity_username="probe",
    )
    assert outcome is SensitiveOutcome.CONFIRMED


def test_sanitizer_redacts_secrets_and_personal_values():
    body = {
        "users": [
            {
                "username": "alice",
                "email": "alice@example.invalid",
                "password": "hunter2",
            }
        ],
        "auth_token": "aaaabbbb.ccccdddd.eeeeffff",
    }
    sanitized = _sanitize_for_persistence(body)
    rendered = str(sanitized)
    assert "hunter2" not in rendered
    assert "alice@example.invalid" not in rendered
    assert "aaaabbbb" not in rendered
    assert sanitized["users"][0]["username"] == "alice"


def test_pattern_helpers():
    assert field_category("userPassword") == "password"
    assert field_category("clientSecret") == "token"
    assert field_category("book_title") is None
    assert is_masked_or_placeholder("[REDACTED]")
    assert value_kind("pii_email", "a@b.co") == "email"
    assert normalize_path("$.users[3].password") == "users[*].password"
