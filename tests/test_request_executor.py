"""Tests for RequestExecutor. All use httpx.MockTransport - no real
network calls, no dependency on a live target."""

import httpx
import pytest

from api_security_system.request_executor import (
    ExecutionRequest,
    RequestExecutor,
    TargetOriginError,
    TransportError,
)

BASE_URL = "http://localhost:5000"


def _executor(handler) -> RequestExecutor:
    return RequestExecutor(base_url=BASE_URL, transport=httpx.MockTransport(handler))


def test_successful_get_captures_status_headers_and_json_body():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "http://localhost:5000/users/v1/alice"
        return httpx.Response(200, json={"username": "alice"}, headers={"X-Test": "yes"})

    executor = _executor(handler)
    result = executor.execute(ExecutionRequest(method="GET", path="/users/v1/alice"))

    assert result.response_status == 200
    assert result.response_body == {"username": "alice"}
    assert result.response_headers.get("x-test") == "yes"
    assert result.response_body_raw is None


def test_successful_post_sends_json_body():
    def handler(request: httpx.Request) -> httpx.Response:
        import json
        assert json.loads(request.content) == {"title": "New Book"}
        return httpx.Response(201, json={"id": 1})

    executor = _executor(handler)
    result = executor.execute(
        ExecutionRequest(method="POST", path="/books/v1", json_body={"title": "New Book"})
    )

    assert result.response_status == 201
    assert result.request_body == {"title": "New Book"}


def test_non_json_response_falls_back_to_raw_text():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="plain text, not json")

    executor = _executor(handler)
    result = executor.execute(ExecutionRequest(method="GET", path="/"))

    assert result.response_body is None
    assert result.response_body_raw == "plain text, not json"


def test_empty_response_body_is_not_treated_as_an_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204)

    executor = _executor(handler)
    result = executor.execute(ExecutionRequest(method="DELETE", path="/users/v1/alice"))

    assert result.response_status == 204
    assert result.response_body is None
    assert result.response_body_raw is None


@pytest.mark.parametrize("status", [401, 403, 404, 500, 503])
def test_http_error_statuses_are_returned_not_raised(status):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": "details"})

    executor = _executor(handler)
    result = executor.execute(ExecutionRequest(method="GET", path="/users/v1/ghost"))

    assert result.response_status == status
    assert result.response_body == {"error": "details"}


def test_redirect_is_captured_as_evidence_not_followed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://evil.example.com/"})

    executor = _executor(handler)
    result = executor.execute(ExecutionRequest(method="GET", path="/old-path"))

    assert result.response_status == 302
    assert result.response_headers.get("location") == "http://evil.example.com/"


def test_connection_failure_raises_transport_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    executor = _executor(handler)
    with pytest.raises(TransportError):
        executor.execute(ExecutionRequest(method="GET", path="/"))


def test_timeout_raises_transport_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    executor = _executor(handler)
    with pytest.raises(TransportError):
        executor.execute(ExecutionRequest(method="GET", path="/", timeout_seconds=1.0))


@pytest.mark.parametrize(
    "bad_path",
    [
        "http://evil.example.com/steal",
        "https://evil.example.com/steal",
        "//evil.example.com/steal",
        "/a/../../../etc/passwd",
    ],
)
def test_unsafe_paths_are_rejected_before_any_request(bad_path):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    executor = _executor(handler)
    with pytest.raises(TargetOriginError):
        executor.execute(ExecutionRequest(method="GET", path=bad_path))

    assert calls == []  # no request was ever sent


def test_path_with_query_string_is_rejected_in_favor_of_query_params():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    executor = _executor(handler)
    with pytest.raises(TargetOriginError):
        executor.execute(ExecutionRequest(method="GET", path="/search?q=test"))


def test_zero_or_negative_timeout_is_rejected():
    with pytest.raises(ValueError):
        ExecutionRequest(method="GET", path="/", timeout_seconds=0)
    with pytest.raises(ValueError):
        ExecutionRequest(method="GET", path="/", timeout_seconds=-5)


def test_infinite_timeout_is_rejected():
    with pytest.raises(ValueError):
        ExecutionRequest(method="GET", path="/", timeout_seconds=float("inf"))


def test_excessive_timeout_is_rejected():
    with pytest.raises(ValueError):
        ExecutionRequest(method="GET", path="/", timeout_seconds=999999)


def test_unsupported_method_is_rejected():
    with pytest.raises(ValueError):
        ExecutionRequest(method="TRACE", path="/")


def test_execution_result_repr_redacts_authorization_header():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    executor = _executor(handler)
    result = executor.execute(
        ExecutionRequest(
            method="GET",
            path="/users/v1/alice",
            headers={"Authorization": "Bearer super-secret-token-123"},
        )
    )

    # Real value is still accessible to an authorized caller.
    assert result.request_headers["Authorization"] == "Bearer super-secret-token-123"

    # But repr/str - what would end up in a log line or exception context - must not leak it.
    rendered = repr(result)
    assert "super-secret-token-123" not in rendered
    assert "REDACTED" in rendered
    assert str(result) == rendered


def test_base_url_with_path_prefix_is_preserved():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "http://localhost:5000/api/users/v1/alice"
        return httpx.Response(200)

    executor = RequestExecutor(
        base_url="http://localhost:5000/api",
        transport=httpx.MockTransport(handler),
    )
    executor.execute(ExecutionRequest(method="GET", path="/users/v1/alice"))