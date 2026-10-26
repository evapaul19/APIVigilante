"""Unit tests for db/redaction.py. No database, no network."""

from api_security_system.db.redaction import (
    REDACTED_VALUE,
    redact_body_for_persistence,
    redact_headers_for_persistence,
)


def test_redact_headers_case_insensitive():
    headers = {"Authorization": "Bearer abc123", "X-Test": "keep-me"}
    redacted = redact_headers_for_persistence(headers)
    assert redacted["Authorization"] == REDACTED_VALUE
    assert redacted["X-Test"] == "keep-me"


def test_redact_headers_lowercase_authorization():
    headers = {"authorization": "Bearer abc123"}
    redacted = redact_headers_for_persistence(headers)
    assert redacted["authorization"] == REDACTED_VALUE


def test_redact_headers_redacts_custom_credential_headers():
    headers = {
        "X-Company-Key": "secret-key",
        "X-Auth-Token": "secret-token",
        "X-Request-Id": "keep-me",
    }
    redacted = redact_headers_for_persistence(headers)
    assert redacted["X-Company-Key"] == REDACTED_VALUE
    assert redacted["X-Auth-Token"] == REDACTED_VALUE
    assert redacted["X-Request-Id"] == "keep-me"


def test_redact_headers_does_not_mutate_input():
    headers = {"Authorization": "Bearer abc123"}
    redact_headers_for_persistence(headers)
    assert headers["Authorization"] == "Bearer abc123"


def test_redact_body_top_level_password():
    body = {"username": "alice", "password": "super-secret"}
    redacted = redact_body_for_persistence(body)
    assert redacted["password"] == REDACTED_VALUE
    assert redacted["username"] == "alice"


def test_redact_body_case_insensitive_field_name():
    body = {"Password": "super-secret"}
    redacted = redact_body_for_persistence(body)
    assert redacted["Password"] == REDACTED_VALUE


def test_redact_body_nested_dict():
    body = {"user": {"username": "alice", "password": "super-secret"}}
    redacted = redact_body_for_persistence(body)
    assert redacted["user"]["password"] == REDACTED_VALUE
    assert redacted["user"]["username"] == "alice"


def test_redact_body_list_of_dicts():
    body = {"users": [{"password": "secret1"}, {"password": "secret2"}]}
    redacted = redact_body_for_persistence(body)
    assert redacted["users"][0]["password"] == REDACTED_VALUE
    assert redacted["users"][1]["password"] == REDACTED_VALUE


def test_redact_body_none_passes_through():
    assert redact_body_for_persistence(None) is None


def test_redact_body_does_not_mutate_input():
    body = {"password": "super-secret"}
    redact_body_for_persistence(body)
    assert body["password"] == "super-secret"


def test_redact_body_auth_token_field():
    body = {"auth_token": "x.e30.y", "message": "ok"}
    redacted = redact_body_for_persistence(body)
    assert redacted["auth_token"] == REDACTED_VALUE
    assert redacted["message"] == "ok"