"""Configured active-test origins cannot expand the SSRF address policy."""

import socket

import pytest

from api_security_system.targets import security
from api_security_system.targets.security import (
    AUTHORIZED_ORIGINS_ENV,
    TEST_ONLY_ORIGIN_ENV,
    TEST_ONLY_ORIGINS_ENV,
    TargetValidationError,
    resolve_target,
    validate_resolved_target,
)


PUBLIC_ADDRESS = "93.184.216.34"


def _patch_dns(monkeypatch, address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
    monkeypatch.setattr(
        security.socket,
        "getaddrinfo",
        lambda _host, port, *args, **kwargs: [
            (
                family,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (sockaddr[0], port, *sockaddr[2:]),
            )
        ],
    )


@pytest.fixture(autouse=True)
def _clear_target_configuration(monkeypatch):
    monkeypatch.delenv(AUTHORIZED_ORIGINS_ENV, raising=False)
    monkeypatch.delenv(TEST_ONLY_ORIGIN_ENV, raising=False)
    monkeypatch.delenv(TEST_ONLY_ORIGINS_ENV, raising=False)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "::1",
        "10.1.2.3",
        "192.168.1.20",
        "169.254.169.254",
        "fe80::1",
    ],
)
def test_operator_allowlist_does_not_allow_non_public_dns_answers(
    monkeypatch, address
):
    monkeypatch.setenv(AUTHORIZED_ORIGINS_ENV, "https://approved.example")
    _patch_dns(monkeypatch, address)

    with pytest.raises(TargetValidationError):
        resolve_target("https://approved.example")


def test_operator_allowlist_accepts_public_dns_answer(monkeypatch):
    monkeypatch.setenv(AUTHORIZED_ORIGINS_ENV, "https://approved.example")
    _patch_dns(monkeypatch, PUBLIC_ADDRESS)

    result = resolve_target("https://approved.example")

    assert result.addresses == (PUBLIC_ADDRESS,)


def test_local_test_origin_must_resolve_only_to_loopback(monkeypatch):
    monkeypatch.setenv(TEST_ONLY_ORIGIN_ENV, "1")
    monkeypatch.setenv(TEST_ONLY_ORIGINS_ENV, "http://127.0.0.1:5010")
    _patch_dns(monkeypatch, "10.1.2.3")

    with pytest.raises(TargetValidationError):
        resolve_target("http://127.0.0.1:5010")


def test_resolved_target_cannot_bypass_operator_origin_address_policy(
    monkeypatch,
):
    monkeypatch.setenv(AUTHORIZED_ORIGINS_ENV, "https://approved.example")
    resolved = security.ResolvedTarget(
        base_url="https://approved.example",
        scheme="https",
        hostname="approved.example",
        port=443,
        addresses=("169.254.169.254",),
    )

    with pytest.raises(TargetValidationError):
        validate_resolved_target("https://approved.example", resolved)
