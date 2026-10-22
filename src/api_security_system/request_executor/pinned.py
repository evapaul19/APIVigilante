"""HTTP transport that connects only to a supplied set of IP addresses.

The transport enforces IP-literal syntax and hostname/port binding. It does
not classify addresses as public, private, loopback, CGNAT, or otherwise
allowed; callers must apply the target-address policy before constructing it.
"""

from __future__ import annotations

import contextlib
import ipaddress
import typing

import httpcore
import httpx

_HTTPCORE_EXCEPTION_MAP: dict[type[Exception], type[httpx.HTTPError]] = {
    httpcore.TimeoutException: httpx.TimeoutException,
    httpcore.ConnectTimeout: httpx.ConnectTimeout,
    httpcore.ReadTimeout: httpx.ReadTimeout,
    httpcore.WriteTimeout: httpx.WriteTimeout,
    httpcore.PoolTimeout: httpx.PoolTimeout,
    httpcore.NetworkError: httpx.NetworkError,
    httpcore.ConnectError: httpx.ConnectError,
    httpcore.ReadError: httpx.ReadError,
    httpcore.WriteError: httpx.WriteError,
    httpcore.ProxyError: httpx.ProxyError,
    httpcore.UnsupportedProtocol: httpx.UnsupportedProtocol,
    httpcore.ProtocolError: httpx.ProtocolError,
    httpcore.LocalProtocolError: httpx.LocalProtocolError,
    httpcore.RemoteProtocolError: httpx.RemoteProtocolError,
}


@contextlib.contextmanager
def _map_httpcore_exceptions() -> typing.Iterator[None]:
    try:
        yield
    except Exception as exc:
        mapped_exc = None
        for from_exc, to_exc in _HTTPCORE_EXCEPTION_MAP.items():
            if not isinstance(exc, from_exc):
                continue
            if mapped_exc is None or issubclass(to_exc, mapped_exc):
                mapped_exc = to_exc

        if mapped_exc is None:
            raise

        raise mapped_exc(str(exc)) from exc


class PinnedNetworkBackend(httpcore.SyncBackend):
    """Connect only to the supplied IPs for one bound origin.

    The supplied addresses are assumed to have passed target policy checks;
    this backend checks syntax and origin binding, not public/private status.
    """

    def __init__(
        self,
        host: str,
        port: int,
        addresses: typing.Sequence[str],
        backend: httpcore.SyncBackend | None = None,
    ) -> None:
        self._host = self._normalize_host(host)
        self._port = int(port)
        self._backend = backend or httpcore.SyncBackend()

        approved: list[str] = []
        for address in addresses:
            value = str(address).strip()
            try:
                ip = ipaddress.ip_address(value.split("%", 1)[0])
            except ValueError as exc:
                raise ValueError(
                    f"Pinned address is not an IP literal: {value!r}"
                ) from exc
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
                ip = ip.ipv4_mapped
            approved.append(str(ip))

        if not approved:
            raise ValueError("At least one pinned IP address is required.")

        self._addresses = tuple(approved)

    @staticmethod
    def _normalize_host(host: str) -> str:
        return str(host).rstrip(".").lower()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        if (
            self._normalize_host(host) != self._host
            or int(port) != self._port
        ):
            raise httpcore.ConnectError(
                "Connection target does not match the validated origin."
            )

        last_error: Exception | None = None
        for address in self._addresses:
            try:
                return self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc

        if last_error is not None:
            raise last_error
        raise httpcore.ConnectError("No pinned IP address was available.")

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        raise httpcore.ConnectError(
            "Unix sockets are not supported for pinned target connections."
        )

    def sleep(self, seconds: float) -> None:
        self._backend.sleep(seconds)


class _ResponseStream(httpx.SyncByteStream):
    def __init__(self, httpcore_stream: typing.Iterable[bytes]) -> None:
        self._httpcore_stream = httpcore_stream

    def __iter__(self) -> typing.Iterator[bytes]:
        with _map_httpcore_exceptions():
            yield from self._httpcore_stream

    def close(self) -> None:
        close = getattr(self._httpcore_stream, "close", None)
        if close is not None:
            close()


class PinnedAddressTransport(httpx.BaseTransport):
    """An HTTPX transport whose TCP connections use only the supplied IPs.

    Callers must apply target-address policy before passing addresses here;
    this class enforces IP-literal syntax and host/port binding only.
    Supplying this transport explicitly to HTTPX also disables automatic
    environment-proxy discovery. That is intentional: a proxy could resolve
    or connect to a destination outside the validated address set, bypassing
    the DNS pinning guarantee. Pinned requests therefore fail closed when a
    direct connection is unavailable; any proxy integration must be explicit
    and must not re-resolve the target hostname.
    """

    def __init__(
        self,
        host: str,
        port: int,
        addresses: typing.Sequence[str],
        *,
        network_backend: httpcore.SyncBackend | None = None,
        limits: httpx.Limits | None = None,
    ) -> None:
        limits = limits or httpx.Limits()
        backend = PinnedNetworkBackend(
            host,
            port,
            addresses,
            backend=network_backend,
        )
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=True, trust_env=True),
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            network_backend=backend,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        assert isinstance(request.stream, httpx.SyncByteStream)

        httpcore_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )

        with _map_httpcore_exceptions():
            httpcore_response = self._pool.handle_request(httpcore_request)

        return httpx.Response(
            status_code=httpcore_response.status,
            headers=httpcore_response.headers,
            stream=_ResponseStream(httpcore_response.stream),
            extensions=httpcore_response.extensions,
        )

    def close(self) -> None:
        self._pool.close()
