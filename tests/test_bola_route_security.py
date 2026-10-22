"""The manual BOLA route must not accept caller-supplied address pinning."""

from types import SimpleNamespace

from fastapi import Request

from api_security_system import api


def _post_request(query_string: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/scans/1/bola-check",
            "headers": [],
            "query_string": query_string.encode("ascii"),
        }
    )


def test_manual_bola_route_does_not_forward_caller_addresses(monkeypatch):
    captured = {}

    def fake_run(scan_id, **kwargs):
        captured["scan_id"] = scan_id
        captured.update(kwargs)
        return SimpleNamespace(
            scan_id=scan_id,
            target_base_url="http://localhost:5000",
            requests_used=0,
            request_budget=kwargs["request_budget"],
            endpoint_results=[],
            bfla_status="not_applicable",
            bfla_reason=None,
            bfla_results=[],
            stopped_early=False,
            stopped_reason=None,
        )

    monkeypatch.setattr(api, "run_bola_check", fake_run)

    response = api.trigger_bola_check(
        1,
        object(),
        _post_request(
            "allow_identity_registration=true"
            "&request_budget=7"
            "&resolved_addresses=127.0.0.1"
            "&pinned_addresses=93.184.216.34"
        ),
    )

    assert response["scan_id"] == 1
    assert response["request_budget"] == 7
    assert captured == {
        "scan_id": 1,
        "allow_identity_registration": True,
        "request_budget": 7,
    }
