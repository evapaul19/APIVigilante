"""Local TLS tests for the pinned transport.

These tests use a loopback HTTPS server and repository-local test
certificates. No external network access is required.
"""

from __future__ import annotations

import http.server
import ssl
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest

from api_security_system.request_executor import (
    ExecutionRequest,
    RequestExecutor,
    TransportError,
)

CERT_DIR = Path(__file__).resolve().parent / "certs"
TRUSTED_CA = CERT_DIR / "ca.pem"
SERVER_CERT = CERT_DIR / "server.pem"
SERVER_KEY = CERT_DIR / "server-key.pem"
SELF_SIGNED_CERT = CERT_DIR / "self-signed.pem"
SELF_SIGNED_KEY = CERT_DIR / "self-signed-key.pem"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@contextmanager
def _tls_server(cert: Path, key: Path):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _execute_https(host: str, port: int):
    executor = RequestExecutor(
        base_url=f"https://{host}:{port}",
        pinned_addresses=("127.0.0.1",),
    )
    try:
        return executor.execute(ExecutionRequest(method="GET", path="/"))
    finally:
        executor.close()


def test_pinned_transport_accepts_certificate_for_original_host(monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(TRUSTED_CA))

    with _tls_server(SERVER_CERT, SERVER_KEY) as port:
        result = _execute_https("example.test", port)

    assert result.response_status == 200
    assert result.response_body == {"ok": True}


def test_pinned_transport_rejects_hostname_mismatch(monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(TRUSTED_CA))

    with _tls_server(SERVER_CERT, SERVER_KEY) as port:
        with pytest.raises(TransportError) as exc_info:
            _execute_https("wrong.example", port)

    cause = exc_info.value.__cause__
    assert cause is not None
    assert "CERTIFICATE_VERIFY_FAILED" in str(cause)
    assert "Hostname mismatch" in str(cause)


def test_pinned_transport_rejects_untrusted_self_signed_certificate(monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(TRUSTED_CA))

    with _tls_server(SELF_SIGNED_CERT, SELF_SIGNED_KEY) as port:
        with pytest.raises(TransportError) as exc_info:
            _execute_https("example.test", port)

    cause = exc_info.value.__cause__
    assert cause is not None
    assert "CERTIFICATE_VERIFY_FAILED" in str(cause)
    assert "self-signed certificate" in str(cause)
