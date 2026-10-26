import pytest

from api_security_system.targets.security import (
    AUTHORIZED_ORIGINS,
    AUTHORIZED_ORIGINS_ENV,
    TEST_ONLY_AUTHORIZED_ORIGIN,
    TEST_ONLY_ORIGIN_ENV,
    TEST_ONLY_ORIGINS_ENV,
    USER_AUTHORIZED_TARGETS_ENV,
    TargetValidationError,
    authorized_origins,
    extra_authorized_origins,
    is_active_test_authorized,
    is_authorized_origin,
    origin_of,
    user_authorized_targets_enabled,
    validate_target_url,
)


@pytest.fixture(autouse=True)
def _clear_origin_config(monkeypatch):
    monkeypatch.delenv(AUTHORIZED_ORIGINS_ENV, raising=False)
    monkeypatch.delenv(TEST_ONLY_ORIGINS_ENV, raising=False)
    monkeypatch.delenv(TEST_ONLY_ORIGIN_ENV, raising=False)
    monkeypatch.delenv(USER_AUTHORIZED_TARGETS_ENV, raising=False)


def test_test_origin_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv(TEST_ONLY_ORIGIN_ENV, raising=False)

    assert authorized_origins() == AUTHORIZED_ORIGINS
    assert not is_authorized_origin(TEST_ONLY_AUTHORIZED_ORIGIN)
    with pytest.raises(TargetValidationError):
        validate_target_url(TEST_ONLY_AUTHORIZED_ORIGIN)


def test_exact_test_origin_is_enabled_by_explicit_flag(monkeypatch):
    monkeypatch.setenv(TEST_ONLY_ORIGIN_ENV, "1")

    assert authorized_origins() == AUTHORIZED_ORIGINS | {
        TEST_ONLY_AUTHORIZED_ORIGIN
    }
    assert is_authorized_origin(TEST_ONLY_AUTHORIZED_ORIGIN)
    assert is_authorized_origin(TEST_ONLY_AUTHORIZED_ORIGIN + "/api")
    assert (
        validate_target_url(TEST_ONLY_AUTHORIZED_ORIGIN)
        == TEST_ONLY_AUTHORIZED_ORIGIN
    )


@pytest.mark.parametrize("value", ["0", "false", "off", ""])
def test_non_truthy_flag_does_not_enable_test_origin(monkeypatch, value):
    monkeypatch.setenv(TEST_ONLY_ORIGIN_ENV, value)

    assert not is_authorized_origin(TEST_ONLY_AUTHORIZED_ORIGIN)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:5000",
        "http://127.0.0.1:5002",
        "http://localhost:5001",
        "https://127.0.0.1:5001",
    ],
)
def test_other_loopback_origins_remain_blocked_when_enabled(
    monkeypatch, url
):
    monkeypatch.setenv(TEST_ONLY_ORIGIN_ENV, "1")

    assert not is_authorized_origin(url)
    with pytest.raises(TargetValidationError):
        validate_target_url(url)


def test_additional_authorized_origins_are_configurable(monkeypatch):
    monkeypatch.setenv(
        AUTHORIZED_ORIGINS_ENV,
        "https://api.example.com, http://127.0.0.1:5010",
    )

    assert extra_authorized_origins() == {
        "https://api.example.com",
        "http://127.0.0.1:5010",
    }
    assert authorized_origins() == AUTHORIZED_ORIGINS | {
        "https://api.example.com",
        "http://127.0.0.1:5010",
    }
    assert is_authorized_origin("https://api.example.com/v1")
    assert is_authorized_origin("http://127.0.0.1:5010/openapi.json")


@pytest.mark.parametrize(
    "value",
    [
        "https://api.example.com/v1",
        "https://api.example.com?x=1",
        "not-a-url",
        "ftp://api.example.com",
    ],
)
def test_invalid_or_non_origin_allowlist_entries_fail_closed(
    monkeypatch, value
):
    monkeypatch.setenv(AUTHORIZED_ORIGINS_ENV, value)

    assert extra_authorized_origins() == frozenset()


def test_custom_test_origins_replace_the_bundled_default(monkeypatch):
    monkeypatch.setenv(TEST_ONLY_ORIGIN_ENV, "1")
    monkeypatch.setenv(
        TEST_ONLY_ORIGINS_ENV,
        "http://127.0.0.1:5010,http://localhost:5011",
    )

    assert is_authorized_origin("http://127.0.0.1:5010")
    assert is_authorized_origin("http://localhost:5011")
    assert not is_authorized_origin(TEST_ONLY_AUTHORIZED_ORIGIN)
    assert authorized_origins() == AUTHORIZED_ORIGINS | {
        "http://127.0.0.1:5010",
        "http://localhost:5011",
    }


def test_empty_test_origin_config_disables_test_origins(monkeypatch):
    monkeypatch.setenv(TEST_ONLY_ORIGIN_ENV, "1")
    monkeypatch.setenv(TEST_ONLY_ORIGINS_ENV, "")

    assert authorized_origins() == AUTHORIZED_ORIGINS
    assert not is_authorized_origin(TEST_ONLY_AUTHORIZED_ORIGIN)


def test_configured_custom_test_origin_with_port_is_authorized(monkeypatch):
    monkeypatch.setenv(TEST_ONLY_ORIGIN_ENV, "1")
    monkeypatch.setenv(TEST_ONLY_ORIGINS_ENV, "http://127.0.0.1:8888")

    assert is_authorized_origin("http://127.0.0.1:8888")
    assert is_authorized_origin("http://127.0.0.1:8888/api/v2")
    assert (
        validate_target_url("http://127.0.0.1:8888/api/v2")
        == "http://127.0.0.1:8888/api/v2"
    )


def test_unconfigured_custom_loopback_port_remains_rejected(monkeypatch):
    monkeypatch.delenv(TEST_ONLY_ORIGIN_ENV, raising=False)

    assert not is_authorized_origin("http://127.0.0.1:8888")
    with pytest.raises(TargetValidationError):
        validate_target_url("http://127.0.0.1:8888")


def test_origin_normalizes_default_ports_and_ipv6():
    assert origin_of("http://api.example.com:80/v1") == "http://api.example.com"
    assert origin_of("https://api.example.com:443/v1") == "https://api.example.com"
    assert origin_of("http://api.example.com:8080/v1") == (
        "http://api.example.com:8080"
    )
    assert origin_of("http://[::1]:80/v1") == "http://[::1]"
    assert origin_of("https://[::1]:8443/v1") == "https://[::1]:8443"


def test_user_authorized_targets_require_server_and_request_opt_in(monkeypatch):
    target = "https://api.example.com"

    assert not user_authorized_targets_enabled()
    assert not is_active_test_authorized(
        target, authorized_for_active_testing=True
    )

    monkeypatch.setenv(USER_AUTHORIZED_TARGETS_ENV, "1")
    assert user_authorized_targets_enabled()
    assert not is_active_test_authorized(
        target, authorized_for_active_testing=False
    )
    assert is_active_test_authorized(
        target, authorized_for_active_testing=True
    )


def test_allowlisted_origin_stays_authorized_without_user_opt_in(monkeypatch):
    monkeypatch.setenv(USER_AUTHORIZED_TARGETS_ENV, "1")
    assert is_active_test_authorized(
        "http://localhost:5000", authorized_for_active_testing=False
    )
