"""Tests for LLM-based risk classification (classifier.py).

Uses a mocked LLMClient - no real API calls are made in this file.
"""

from unittest.mock import MagicMock

import pytest

from api_security_system.llm import LLMResponse, Provider
from api_security_system.recon.classifier import ClassificationError, classify_endpoint
from api_security_system.recon.schemas import EndpointRiskLevel, ParsedEndpoint

ENDPOINT = ParsedEndpoint(
    method="GET",
    path="/users/v1/{username}",
    operation_id="get_user",
    resource_type="user",
    id_param_name="username",
    raw_spec_fragment={},
)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("api_security_system.recon.classifier.time.sleep", lambda s: None)


def _mock_client(text: str) -> MagicMock:
    client = MagicMock()
    client.generate.return_value = LLMResponse(provider=Provider.GOOGLE, model="gemini-3.5-flash-lite", text=text)
    return client


def test_classify_endpoint_success():
    client = _mock_client('{"risk_level": "high", "rationale": "BOLA risk via username param", "confidence": 0.8}')
    result = classify_endpoint(ENDPOINT, client)
    assert result.risk_level == EndpointRiskLevel.HIGH
    assert result.confidence == 0.8
    assert client.generate.call_count == 1


def test_classify_endpoint_strips_code_fences():
    client = _mock_client('```json\n{"risk_level": "low", "rationale": "static content"}\n```')
    result = classify_endpoint(ENDPOINT, client)
    assert result.risk_level == EndpointRiskLevel.LOW


def test_classify_endpoint_retries_once_then_fails_on_malformed_json():
    client = _mock_client("not valid json at all")
    with pytest.raises(ClassificationError):
        classify_endpoint(ENDPOINT, client)
    assert client.generate.call_count == 2


def test_classify_endpoint_retries_once_then_fails_on_invalid_schema():
    client = _mock_client('{"risk_level": "not_a_real_level", "rationale": "x"}')
    with pytest.raises(ClassificationError):
        classify_endpoint(ENDPOINT, client)
    assert client.generate.call_count == 2


def test_classify_endpoint_succeeds_on_second_attempt():
    client = MagicMock()
    client.generate.side_effect = [
        LLMResponse(provider=Provider.GOOGLE, model="m", text="garbage"),
        LLMResponse(provider=Provider.GOOGLE, model="m", text='{"risk_level": "medium", "rationale": "ok"}'),
    ]
    result = classify_endpoint(ENDPOINT, client)
    assert result.risk_level == EndpointRiskLevel.MEDIUM
    assert client.generate.call_count == 2