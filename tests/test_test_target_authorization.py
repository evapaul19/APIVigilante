import pytest

from api_security_system.targets.security import (
    AUTHORIZED_ORIGINS,
    TEST_ONLY_AUTHORIZED_ORIGIN,
    TEST_ONLY_ORIGIN_ENV,
    TargetValidationError,
    authorized_origins,
    is_authorized_origin,
    validate_target_url,
)


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
