"""Tests for the AMBIGUOUS-only LLM rationale helper. Mocked LLMClient
- no real API calls."""

from unittest.mock import MagicMock

from api_security_system.authz_bola.classifier import generate_ambiguous_rationale
from api_security_system.llm import LLMResponse, Provider


def test_generate_ambiguous_rationale_success():
    client = MagicMock()
    client.generate.return_value = LLMResponse(
        provider=Provider.GOOGLE, model="m", text='{"rationale": "Response pattern is inconclusive."}'
    )
    rationale = generate_ambiguous_rationale("evidence", client)
    assert rationale == "Response pattern is inconclusive."


def test_generate_ambiguous_rationale_malformed_json_falls_back_without_raising():
    client = MagicMock()
    client.generate.return_value = LLMResponse(provider=Provider.GOOGLE, model="m", text="not json")
    rationale = generate_ambiguous_rationale("evidence", client)
    assert "unavailable" in rationale.lower()


def test_generate_ambiguous_rationale_llm_exception_falls_back_without_raising():
    client = MagicMock()
    client.generate.side_effect = RuntimeError("API error")
    rationale = generate_ambiguous_rationale("evidence", client)
    assert "unavailable" in rationale.lower()