"""DNS-rebinding regression tests using fake httpcore backends only."""

import socket

import httpcore
import httpx
import pytest

from api_security_system.request_executor import (
    MAX_RESPONSE_BYTES,
    ExecutionRequest,
    RequestExecutor,
    TargetOriginError,
    TransportError,
)
from api_security_system.request_executor import executor as executor_module
from api_security_system.request_executor.pinned import (
    PinnedAddressTransport,
    PinnedNetworkBackend,
)
from api_security_system.targets import security
from api_security_system.targets.security import (
    DEFAULT_AUTHORIZED_ORIGIN,
    TEST_ONLY_AUTHORIZED_ORIGIN,
    TEST_ONLY_ORIGIN_ENV,
    TEST_ONLY_ORIGINS_ENV,
    ResolvedTarget,
    TargetValidationError,
    resolve_target,
    validate_resolved_target,
    validate_target_url,
)
from api_security_system.targets import spec_fetch

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V4_ALT = "93.184.216.35"
PUBLIC_V6 = "2001:4860:4860::8888"
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 2\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"{}"
)


def _authorized_resolved_target(addresses=("127.0.0.1",)):
    return ResolvedTarget(
        base_url=DEFAULT_AUTHORIZED_ORIGIN,
        scheme="http",
        hostname="localhost",
        port=5000,
        addresses=tuple(addresses),
    )


def _public_resolved_target(addresses=(PUBLIC_V4,)):
    return ResolvedTarget(
        base_url="https://public.example",
        scheme="https",
        hostname="public.example",
        port=443,
        addresses=tuple(addresses),
    )


class RecordingStream(httpcore.MockStream):
    def __init__(self, buffer, connected_host):
        super().__init__(buffer)
        self.connected_host = connected_host
        self.sni_hostname = None
        self.written = bytearray()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.sni_hostname = server_hostname
        return self

    def write(self, buffer, timeout=None):
        self.written.extend(buffer)


class RecordingBackend(httpcore.SyncBackend):
    def __init__(self, response=HTTP_RESPONSE):
        self.response = response
        self.calls = []
        self.streams = []

    def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        self.calls.append((host, port))
        stream = RecordingStream([self.response], host)
        self.streams.append(stream)
        return stream

    def sleep(self, seconds):
        pass


class SelectiveBackend(RecordingBackend):
    def __init__(self, failing_host, response=HTTP_RESPONSE):
        super().__init__(response)
        self.failing_host = failing_host

    def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        if host == self.failing_host:
            self.calls.append((host, port))
            raise httpcore.ConnectError("simulated failure")
        return super().connect_tcp(
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


def _pinned_executor(monkeypatch, backend, base_url="https://public.example"):
    def build_transport(host, port, addresses):
        return PinnedAddressTransport(
            host,
            port,
            addresses,
            network_backend=backend,
        )

    monkeypatch.setattr(
        executor_module,
        "PinnedAddressTransport",
        build_transport,
    )
    return RequestExecutor(
        base_url=base_url,
        pinned_addresses=(PUBLIC_V4,),
    )


def _addr_info(address, port):
    if ":" in address:
        return (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (address, port, 0, 0),
        )
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (address, port),
    )


def _patch_resolution(monkeypatch, *addresses):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [_addr_info(address, port) for address in addresses]

    monkeypatch.setattr(security.socket, "getaddrinfo", fake_getaddrinfo)


def test_resolve_target_rejects_mixed_public_and_private(monkeypatch):
    _patch_resolution(monkeypatch, PUBLIC_V4, "127.0.0.1")

    with pytest.raises(TargetValidationError):
        resolve_target("https://public.example")


def test_resolve_target_accepts_public_ipv4_and_ipv6(monkeypatch):
    _patch_resolution(monkeypatch, PUBLIC_V4, PUBLIC_V6)

    resolved = resolve_target("https://public.example")

    assert resolved.addresses == (PUBLIC_V4, PUBLIC_V6)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "100.64.0.1",
        "100.127.255.255",
        "::ffff:100.64.0.1",
    ],
)
def test_resolve_target_rejects_unsafe_addresses(monkeypatch, address):
    _patch_resolution(monkeypatch, PUBLIC_V4, address)

    with pytest.raises(TargetValidationError):
        resolve_target("https://public.example")


@pytest.mark.parametrize(
    "address",
    ["100.64.0.1", "100.127.255.255", "::ffff:100.64.0.1"],
)
def test_validate_target_url_rejects_non_global_literals(address):
    host = f"[{address}]" if ":" in address else address
    with pytest.raises(TargetValidationError):
        validate_target_url(f"http://{host}/")


def test_validate_target_url_accepts_public_literal():
    assert validate_target_url(f"http://{PUBLIC_V4}/") == f"http://{PUBLIC_V4}"


def test_authorized_localhost_accepts_only_loopback_answers(monkeypatch):
    _patch_resolution(monkeypatch, "127.0.0.1", "::1", "::ffff:127.0.0.1")

    resolved = resolve_target(DEFAULT_AUTHORIZED_ORIGIN)

    assert resolved.addresses == ("127.0.0.1", "::1")


@pytest.mark.parametrize(
    "addresses",
    [
        ("127.0.0.1", PUBLIC_V4),
        (PUBLIC_V4,),
        ("192.168.1.10",),
    ],
)
def test_authorized_localhost_rejects_non_loopback_answers(
    monkeypatch, addresses
):
    _patch_resolution(monkeypatch, *addresses)

    with pytest.raises(TargetValidationError):
        resolve_target(DEFAULT_AUTHORIZED_ORIGIN)


def test_authorized_origin_resolves_only_when_connecting(monkeypatch):
    monkeypatch.setenv(TEST_ONLY_ORIGIN_ENV, "1")
    _patch_resolution(monkeypatch, "127.0.0.1")

    resolved = resolve_target(TEST_ONLY_AUTHORIZED_ORIGIN)

    assert resolved.addresses == ("127.0.0.1",)
    assert validate_target_url(TEST_ONLY_AUTHORIZED_ORIGIN) == (
        TEST_ONLY_AUTHORIZED_ORIGIN
    )


def test_configured_test_origin_with_custom_port_resolves(monkeypatch):
    monkeypatch.setenv(TEST_ONLY_ORIGIN_ENV, "1")
    monkeypatch.setenv(TEST_ONLY_ORIGINS_ENV, "http://127.0.0.1:8888")
    _patch_resolution(monkeypatch, "127.0.0.1")

    resolved = resolve_target("http://127.0.0.1:8888/api/v2")

    assert resolved.base_url == "http://127.0.0.1:8888/api/v2"
    assert resolved.addresses == ("127.0.0.1",)


def test_configured_ipv6_test_origin_resolves_loopback(monkeypatch):
    monkeypatch.setenv(TEST_ONLY_ORIGIN_ENV, "1")
    monkeypatch.setenv(TEST_ONLY_ORIGINS_ENV, "http://[::1]:8888")
    _patch_resolution(monkeypatch, "::1")

    resolved = resolve_target("http://[::1]:8888")

    assert resolved.base_url == "http://[::1]:8888"
    assert resolved.addresses == ("::1",)


def test_public_user_defined_target_resolves_without_allowlist(monkeypatch):
    _patch_resolution(monkeypatch, PUBLIC_V4)

    resolved = resolve_target("https://api.example.com/v1")

    assert resolved.base_url == "https://api.example.com/v1"
    assert resolved.addresses == (PUBLIC_V4,)


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fe80::1"],
)
def test_public_hostname_resolving_to_prohibited_address_is_rejected(
    monkeypatch, address
):
    _patch_resolution(monkeypatch, address)

    with pytest.raises(TargetValidationError):
        resolve_target("https://public.example")


def test_validation_only_does_not_resolve_authorized_hostname(monkeypatch):
    def fail_getaddrinfo(*args, **kwargs):
        raise AssertionError("authorized validation must not resolve DNS")

    monkeypatch.setattr(security.socket, "getaddrinfo", fail_getaddrinfo)

    assert validate_target_url(DEFAULT_AUTHORIZED_ORIGIN) == (
        DEFAULT_AUTHORIZED_ORIGIN
    )


def test_pinned_backend_connects_to_approved_ip_and_rejects_other_origins():
    backend = RecordingBackend()
    pinned = PinnedNetworkBackend(
        "example.test",
        443,
        (PUBLIC_V4,),
        backend=backend,
    )

    stream = pinned.connect_tcp("example.test.", 443)

    assert isinstance(stream, RecordingStream)
    assert backend.calls == [(PUBLIC_V4, 443)]

    with pytest.raises(httpcore.ConnectError):
        pinned.connect_tcp("evil.test", 443)
    with pytest.raises(httpcore.ConnectError):
        pinned.connect_tcp("example.test", 80)
    with pytest.raises(httpcore.ConnectError):
        pinned.connect_unix_socket("socket.uds")

    assert backend.calls == [(PUBLIC_V4, 443)]


def test_pinned_backend_tries_all_approved_addresses():
    backend = SelectiveBackend(PUBLIC_V4)
    pinned = PinnedNetworkBackend(
        "example.test",
        443,
        (PUBLIC_V4, PUBLIC_V4_ALT),
        backend=backend,
    )

    pinned.connect_tcp("example.test", 443)

    assert backend.calls == [(PUBLIC_V4, 443), (PUBLIC_V4_ALT, 443)]


def test_pinned_backend_fails_closed_when_all_addresses_fail():
    backend = SelectiveBackend(PUBLIC_V4)
    pinned = PinnedNetworkBackend(
        "example.test",
        443,
        (PUBLIC_V4,),
        backend=backend,
    )

    with pytest.raises(httpcore.ConnectError):
        pinned.connect_tcp("example.test", 443)

    assert backend.calls == [(PUBLIC_V4, 443)]


@pytest.mark.parametrize("addresses", [(), ("not-an-ip",)])
def test_pinned_backend_requires_ip_literals(addresses):
    with pytest.raises(ValueError):
        PinnedNetworkBackend("example.test", 443, addresses)


def test_pinned_transport_preserves_host_header_and_tls_sni():
    backend = RecordingBackend()
    transport = PinnedAddressTransport(
        "example.test",
        443,
        (PUBLIC_V4,),
        network_backend=backend,
    )

    with httpx.Client(transport=transport) as client:
        response = client.get("https://example.test/openapi.json")

    assert response.status_code == 200
    assert response.json() == {}
    assert backend.calls == [(PUBLIC_V4, 443)]
    assert backend.streams[0].sni_hostname == "example.test"
    assert b"host: example.test" in bytes(backend.streams[0].written).lower()


def test_pinned_transport_rejects_host_and_port_mismatch():
    backend = RecordingBackend()
    transport = PinnedAddressTransport(
        "example.test",
        443,
        (PUBLIC_V4,),
        network_backend=backend,
    )

    with httpx.Client(transport=transport) as client:
        with pytest.raises(httpx.ConnectError):
            client.get("https://evil.test/")
        with pytest.raises(httpx.ConnectError):
            client.get("https://example.test:444/")

    assert backend.calls == []


def test_pinned_executor_ignores_environment_proxies(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)

    backend = RecordingBackend()
    executor = _pinned_executor(monkeypatch, backend)
    try:
        result = executor.execute(
            ExecutionRequest(method="GET", path="/openapi.json")
        )
    finally:
        executor.close()

    assert result.response_status == 200
    assert backend.calls == [(PUBLIC_V4, 443)]


def test_pinned_executor_does_not_follow_redirects(monkeypatch):
    redirect = (
        b"HTTP/1.1 302 Found\r\n"
        b"Location: https://evil.example/steal\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    backend = RecordingBackend(response=redirect)
    executor = _pinned_executor(monkeypatch, backend)
    try:
        result = executor.execute(
            ExecutionRequest(method="GET", path="/openapi.json")
        )
    finally:
        executor.close()

    assert result.response_status == 302
    assert result.response_headers.get("location") == "https://evil.example/steal"
    assert backend.calls == [(PUBLIC_V4, 443)]


def test_pinned_executor_enforces_response_size_limit(monkeypatch):
    body = b"x" * (MAX_RESPONSE_BYTES + 1)
    oversized = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        + body
    )
    backend = RecordingBackend(response=oversized)
    executor = _pinned_executor(monkeypatch, backend)
    try:
        with pytest.raises(TransportError, match="byte limit"):
            executor.execute(
                ExecutionRequest(method="GET", path="/openapi.json")
            )
    finally:
        executor.close()

    assert backend.calls == [(PUBLIC_V4, 443)]


def test_bolacheck_pins_production_executor(monkeypatch):
    from types import SimpleNamespace

    from api_security_system.authz_bola import service as bola_service
    from api_security_system.targets import security as target_security

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get(self, model, key):
            if model is bola_service.Scan:
                return SimpleNamespace(target_id=1)
            if model is bola_service.Target:
                return SimpleNamespace(base_url=DEFAULT_AUTHORIZED_ORIGIN)
            return None

    captured = {}

    class FakeExecutor:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    monkeypatch.setattr(bola_service, "get_session", lambda: FakeSession())
    monkeypatch.setattr(bola_service, "RequestExecutor", FakeExecutor)
    monkeypatch.setattr(
        bola_service, "select_bola_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        bola_service,
        "run_bfla_checks",
        lambda *args, **kwargs: ([], "unsupported", "test"),
    )
    monkeypatch.setattr(
        target_security,
        "resolve_target",
        lambda url: SimpleNamespace(addresses=("127.0.0.1",)),
    )

    bola_service.run_bola_check(
        scan_id=1,
        allow_identity_registration=True,
        llm_client=object(),
    )

    assert captured["base_url"] == DEFAULT_AUTHORIZED_ORIGIN
    assert captured["pinned_addresses"] == ("127.0.0.1",)
    assert "transport" not in captured


def test_sensitive_data_check_pins_production_executor(monkeypatch):
    from types import SimpleNamespace

    from api_security_system.auth import AuthenticationError
    from api_security_system.sensitive_data import service as sensitive_service
    from api_security_system.targets import security as target_security

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get(self, model, key):
            if model is sensitive_service.Scan:
                return SimpleNamespace(target_id=1)
            if model is sensitive_service.Target:
                return SimpleNamespace(base_url=DEFAULT_AUTHORIZED_ORIGIN)
            return None

    captured = {}

    class FakeExecutor:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    def fail_provision(*args, **kwargs):
        raise AuthenticationError("test stop")

    monkeypatch.setattr(sensitive_service, "get_session", lambda: FakeSession())
    monkeypatch.setattr(sensitive_service, "RequestExecutor", FakeExecutor)
    monkeypatch.setattr(sensitive_service, "provision_identity", fail_provision)
    monkeypatch.setattr(sensitive_service, "_select_get_endpoints", lambda scan_id: [])
    monkeypatch.setattr(
        target_security,
        "resolve_target",
        lambda url: SimpleNamespace(addresses=("127.0.0.1",)),
    )

    sensitive_service.run_sensitive_data_check(
        scan_id=1,
        allow_identity_registration=True,
    )

    assert captured["base_url"] == DEFAULT_AUTHORIZED_ORIGIN
    assert captured["pinned_addresses"] == ("127.0.0.1",)
    assert "transport" not in captured


def test_bolacheck_reuses_validated_target_without_dns(monkeypatch):
    from types import SimpleNamespace

    from api_security_system.authz_bola import service as bola_service
    from api_security_system.targets import security as target_security

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get(self, model, key):
            if model is bola_service.Scan:
                return SimpleNamespace(target_id=1)
            if model is bola_service.Target:
                return SimpleNamespace(base_url=DEFAULT_AUTHORIZED_ORIGIN)
            return None

    captured = {}

    class FakeExecutor:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    monkeypatch.setattr(bola_service, "get_session", lambda: FakeSession())
    monkeypatch.setattr(bola_service, "RequestExecutor", FakeExecutor)
    monkeypatch.setattr(
        bola_service, "select_bola_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        bola_service,
        "run_bfla_checks",
        lambda *args, **kwargs: ([], "unsupported", "test"),
    )
    monkeypatch.setattr(
        target_security,
        "resolve_target",
        lambda url: pytest.fail("active check re-resolved the target"),
    )
    monkeypatch.setattr(
        target_security.socket,
        "getaddrinfo",
        lambda *args, **kwargs: pytest.fail("active check performed DNS"),
    )

    bola_service.run_bola_check(
        scan_id=1,
        allow_identity_registration=True,
        llm_client=object(),
        resolved_target=_authorized_resolved_target(),
    )

    assert captured["base_url"] == DEFAULT_AUTHORIZED_ORIGIN
    assert captured["pinned_addresses"] == ("127.0.0.1",)
    assert "transport" not in captured


def test_sensitive_data_check_reuses_validated_target_without_dns(monkeypatch):
    from types import SimpleNamespace

    from api_security_system.auth import AuthenticationError
    from api_security_system.sensitive_data import service as sensitive_service
    from api_security_system.targets import security as target_security

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get(self, model, key):
            if model is sensitive_service.Scan:
                return SimpleNamespace(target_id=1)
            if model is sensitive_service.Target:
                return SimpleNamespace(base_url=DEFAULT_AUTHORIZED_ORIGIN)
            return None

    captured = {}

    class FakeExecutor:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    def fail_provision(*args, **kwargs):
        raise AuthenticationError("test stop")

    monkeypatch.setattr(sensitive_service, "get_session", lambda: FakeSession())
    monkeypatch.setattr(sensitive_service, "RequestExecutor", FakeExecutor)
    monkeypatch.setattr(sensitive_service, "provision_identity", fail_provision)
    monkeypatch.setattr(sensitive_service, "_select_get_endpoints", lambda scan_id: [])
    monkeypatch.setattr(
        target_security,
        "resolve_target",
        lambda url: pytest.fail("active check re-resolved the target"),
    )
    monkeypatch.setattr(
        target_security.socket,
        "getaddrinfo",
        lambda *args, **kwargs: pytest.fail("active check performed DNS"),
    )

    sensitive_service.run_sensitive_data_check(
        scan_id=1,
        allow_identity_registration=True,
        resolved_target=_authorized_resolved_target(),
    )

    assert captured["base_url"] == DEFAULT_AUTHORIZED_ORIGIN
    assert captured["pinned_addresses"] == ("127.0.0.1",)
    assert "transport" not in captured


def test_bolacheck_injected_transport_skips_pinning(monkeypatch):
    from types import SimpleNamespace

    from api_security_system.authz_bola import service as bola_service
    from api_security_system.targets import security as target_security

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get(self, model, key):
            if model is bola_service.Scan:
                return SimpleNamespace(target_id=1)
            if model is bola_service.Target:
                return SimpleNamespace(base_url=DEFAULT_AUTHORIZED_ORIGIN)
            return None

    captured = {}

    class FakeExecutor:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    monkeypatch.setattr(bola_service, "get_session", lambda: FakeSession())
    monkeypatch.setattr(bola_service, "RequestExecutor", FakeExecutor)
    monkeypatch.setattr(
        bola_service, "select_bola_candidates", lambda *args, **kwargs: []
    )
    monkeypatch.setattr(
        bola_service,
        "run_bfla_checks",
        lambda *args, **kwargs: ([], "unsupported", "test"),
    )
    monkeypatch.setattr(
        target_security,
        "resolve_target",
        lambda url: pytest.fail("injected transport performed DNS validation"),
    )

    transport = httpx.MockTransport(lambda request: httpx.Response(200))
    bola_service.run_bola_check(
        scan_id=1,
        allow_identity_registration=True,
        llm_client=object(),
        executor_transport=transport,
    )

    assert captured["transport"] is transport
    assert "pinned_addresses" not in captured


@pytest.mark.parametrize(
    "addresses",
    [
        ("93.184.216.34",),
        ("10.0.0.1",),
        ("100.64.0.1",),
        ("::1", "93.184.216.34"),
        ("not-an-ip",),
        (),
    ],
)
def test_validate_resolved_target_rejects_disallowed_authorized_addresses(
    addresses,
):
    with pytest.raises(TargetValidationError):
        validate_resolved_target(
            DEFAULT_AUTHORIZED_ORIGIN,
            _authorized_resolved_target(addresses),
        )


@pytest.mark.parametrize(
    "addresses",
    [
        ("127.0.0.1",),
        ("10.0.0.1",),
        ("100.64.0.1",),
        ("::1",),
        (PUBLIC_V4, "10.0.0.1"),
        ("not-an-ip",),
        (),
    ],
)
def test_validate_resolved_target_rejects_disallowed_public_addresses(addresses):
    with pytest.raises(TargetValidationError):
        validate_resolved_target(
            "https://public.example",
            _public_resolved_target(addresses),
        )


def test_validate_resolved_target_rejects_mismatched_url():
    with pytest.raises(TargetValidationError):
        validate_resolved_target(
            DEFAULT_AUTHORIZED_ORIGIN + "/other",
            _authorized_resolved_target(),
        )


def test_validate_resolved_target_does_not_resolve_again(monkeypatch):
    resolutions = []

    def changing_getaddrinfo(host, port, *args, **kwargs):
        resolutions.append((host, port))
        address = PUBLIC_V4 if len(resolutions) == 1 else "127.0.0.1"
        return [_addr_info(address, port)]

    monkeypatch.setattr(security.socket, "getaddrinfo", changing_getaddrinfo)

    resolved = resolve_target("https://public.example")
    addresses = validate_resolved_target("https://public.example", resolved)

    assert addresses == (PUBLIC_V4,)
    assert len(resolutions) == 1


def test_assessment_active_summaries_forward_resolved_target(monkeypatch):
    from api_security_system.targets import service as target_service

    resolved = _authorized_resolved_target()
    seen = {}

    def fail_bola(**kwargs):
        seen["bola"] = kwargs
        raise RuntimeError("stop")

    def fail_sensitive(**kwargs):
        seen["sensitive"] = kwargs
        raise RuntimeError("stop")

    monkeypatch.setattr(target_service, "run_bola_check", fail_bola)
    monkeypatch.setattr(target_service, "run_sensitive_data_check", fail_sensitive)

    authorization = target_service._authorization_summary(
        1,
        DEFAULT_AUTHORIZED_ORIGIN,
        True,
        10,
        resolved_target=resolved,
    )
    sensitive_data = target_service._sensitive_summary(
        1,
        DEFAULT_AUTHORIZED_ORIGIN,
        True,
        10,
        resolved_target=resolved,
    )

    assert authorization["status"] == "failed"
    assert sensitive_data["status"] == "failed"
    assert seen["bola"]["resolved_target"] is resolved
    assert seen["sensitive"]["resolved_target"] is resolved


def test_dns_change_after_validation_cannot_redirect_connection(monkeypatch):
    resolutions = []

    def changing_getaddrinfo(host, port, *args, **kwargs):
        resolutions.append((host, port))
        address = PUBLIC_V4 if len(resolutions) == 1 else "127.0.0.1"
        return [_addr_info(address, port)]

    monkeypatch.setattr(security.socket, "getaddrinfo", changing_getaddrinfo)

    resolved = resolve_target("https://public.example")
    backend = RecordingBackend()
    transport = PinnedAddressTransport(
        resolved.hostname,
        resolved.port,
        resolved.addresses,
        network_backend=backend,
    )

    with httpx.Client(transport=transport) as client:
        response = client.get("https://public.example/openapi.json")

    assert response.status_code == 200
    assert backend.calls == [(PUBLIC_V4, 443)]
    assert len(resolutions) == 1


def test_acquire_spec_pins_explicit_and_discovery_candidates(monkeypatch):
    calls = []

    def fake_fetch(url, resolved_addresses):
        calls.append((url, resolved_addresses))
        return b'{"openapi": "3.0.0", "paths": {}}'

    monkeypatch.setattr(spec_fetch, "_fetch", fake_fetch)

    explicit = spec_fetch.acquire_spec(
        "https://public.example",
        "https://public.example/openapi.json",
        resolved_addresses=(PUBLIC_V4,),
    )
    assert explicit.document == {"openapi": "3.0.0", "paths": {}}
    assert calls == [
        ("https://public.example/openapi.json", (PUBLIC_V4,))
    ]

    calls.clear()
    spec_fetch.acquire_spec(
        "https://public.example",
        resolved_addresses=(PUBLIC_V4,),
    )
    assert calls == [
        ("https://public.example/openapi.json", (PUBLIC_V4,))
    ]


def test_acquire_spec_resolves_once_when_addresses_not_supplied(monkeypatch):
    _patch_resolution(monkeypatch, PUBLIC_V4)
    calls = []

    def fake_fetch(url, resolved_addresses):
        calls.append((url, resolved_addresses))
        return b'{"openapi": "3.0.0", "paths": {}}'

    monkeypatch.setattr(spec_fetch, "_fetch", fake_fetch)

    spec_fetch.acquire_spec("https://public.example")

    assert calls == [
        ("https://public.example/openapi.json", (PUBLIC_V4,))
    ]


def test_acquire_spec_treats_explicit_default_port_as_same_origin(monkeypatch):
    calls = []

    def fake_fetch(url, resolved_addresses):
        calls.append((url, resolved_addresses))
        return b'{"openapi": "3.0.0", "paths": {}}'

    monkeypatch.setattr(spec_fetch, "_fetch", fake_fetch)

    spec_fetch.acquire_spec(
        "http://public.example",
        "http://public.example:80/openapi.json",
        resolved_addresses=(PUBLIC_V4,),
    )

    assert calls == [
        ("http://public.example:80/openapi.json", (PUBLIC_V4,))
    ]


def test_acquire_spec_rejects_empty_addresses():
    with pytest.raises(TargetValidationError):
        spec_fetch.acquire_spec(
            "https://public.example",
            resolved_addresses=(),
        )


@pytest.mark.parametrize(
    "addresses",
    [
        "93.184.216.34",
        ("not-an-ip",),
        ("93.184.216.34", ""),
    ],
)
def test_acquire_spec_rejects_invalid_supplied_addresses(addresses):
    with pytest.raises(TargetValidationError):
        spec_fetch.acquire_spec(
            "https://public.example",
            resolved_addresses=addresses,
        )


@pytest.mark.parametrize(
    "addresses",
    [
        ("127.0.0.1",),
        ("10.0.0.1",),
        ("100.64.0.1",),
        ("fe80::1",),
        ("169.254.169.254",),
        ("::ffff:127.0.0.1",),
        ("224.0.0.1",),
        ("0.0.0.0",),
        ("240.0.0.1",),
        ("64:ff9b::1",),
        (PUBLIC_V4, "127.0.0.1"),
    ],
)
def test_acquire_spec_rejects_disallowed_public_target_addresses(addresses):
    with pytest.raises(TargetValidationError):
        spec_fetch.acquire_spec(
            "https://public.example",
            resolved_addresses=addresses,
        )


@pytest.mark.parametrize(
    "addresses",
    [
        ("93.184.216.34",),
        ("10.0.0.1",),
        ("100.64.0.1",),
    ],
)
def test_acquire_spec_rejects_disallowed_authorized_loopback_addresses(addresses):
    with pytest.raises(TargetValidationError):
        spec_fetch.acquire_spec(
            DEFAULT_AUTHORIZED_ORIGIN,
            resolved_addresses=addresses,
        )


def test_acquire_spec_accepts_authorized_loopback_addresses(monkeypatch):
    calls = []

    def fake_fetch(url, resolved_addresses):
        calls.append((url, resolved_addresses))
        return b'{"openapi": "3.0.0", "paths": {}}'

    monkeypatch.setattr(spec_fetch, "_fetch", fake_fetch)

    spec_fetch.acquire_spec(
        DEFAULT_AUTHORIZED_ORIGIN,
        resolved_addresses=("127.0.0.1",),
    )

    assert calls == [
        (DEFAULT_AUTHORIZED_ORIGIN + "/openapi.json", ("127.0.0.1",))
    ]


def test_acquire_spec_reuses_resolved_target_without_dns(monkeypatch):
    calls = []

    def fake_fetch(url, resolved_addresses):
        calls.append((url, resolved_addresses))
        return b'{"openapi": "3.0.0", "paths": {}}'

    monkeypatch.setattr(spec_fetch, "_fetch", fake_fetch)
    monkeypatch.setattr(
        security.socket,
        "getaddrinfo",
        lambda *args, **kwargs: pytest.fail("acquire_spec performed DNS"),
    )

    spec_fetch.acquire_spec(
        "https://public.example",
        resolved_target=_public_resolved_target(),
    )

    assert calls == [
        ("https://public.example/openapi.json", (PUBLIC_V4,))
    ]


def test_acquire_spec_rejects_mismatched_resolved_target():
    mismatched = ResolvedTarget(
        base_url="https://other.example",
        scheme="https",
        hostname="other.example",
        port=443,
        addresses=(PUBLIC_V4,),
    )

    with pytest.raises(TargetValidationError):
        spec_fetch.acquire_spec(
            "https://public.example",
            resolved_target=mismatched,
        )


def test_acquire_spec_rejects_both_address_forms():
    with pytest.raises(TargetValidationError):
        spec_fetch.acquire_spec(
            "https://public.example",
            resolved_addresses=(PUBLIC_V4,),
            resolved_target=_public_resolved_target(),
        )


def test_request_executor_builds_pinned_transport(monkeypatch):
    created = []

    class RecordingTransport(httpx.BaseTransport):
        def __init__(self, host, port, addresses):
            created.append((host, port, addresses))
            self._inner = httpx.MockTransport(
                lambda request: httpx.Response(200, json={"ok": True})
            )

        def handle_request(self, request):
            return self._inner.handle_request(request)

        def close(self):
            pass

    monkeypatch.setattr(
        executor_module,
        "PinnedAddressTransport",
        RecordingTransport,
    )

    executor = RequestExecutor(
        base_url="https://public.example",
        pinned_addresses=(PUBLIC_V4,),
    )
    try:
        result = executor.execute(
            ExecutionRequest(method="GET", path="/openapi.json")
        )
    finally:
        executor.close()

    assert result.response_status == 200
    assert created == [("public.example", 443, (PUBLIC_V4,))]


def test_request_executor_rejects_ambiguous_or_empty_pinning():
    with pytest.raises(TargetOriginError):
        RequestExecutor(
            base_url="https://public.example",
            transport=httpx.MockTransport(lambda request: httpx.Response(200)),
            pinned_addresses=(PUBLIC_V4,),
        )

    with pytest.raises(TargetOriginError):
        RequestExecutor(
            base_url="https://public.example",
            pinned_addresses=(),
        )

    with pytest.raises(TargetOriginError):
        RequestExecutor(
            base_url="https://public.example",
            pinned_addresses=("not-an-ip",),
        )
