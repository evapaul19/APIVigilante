"""Smoke tests for the LLM provider abstraction.

These make real API calls. A provider's test is skipped automatically
if its API key isn't set, so the suite doesn't hard-fail when only
one provider is configured yet.
"""

import os

import pytest

from api_security_system.llm import LLMClient, LLMRequest, LLMResponse, Provider

GOOGLE_SMOKE_MODEL = "gemini-3.5-flash-lite"
OPENROUTER_SMOKE_MODEL = "deepseek/deepseek-v4.1-flash"  # verify this slug in your OpenRouter dashboard


def _assert_valid_response(response: LLMResponse) -> None:
    assert isinstance(response, LLMResponse)
    assert response.text.strip() != ""


@pytest.mark.skipif(not os.environ.get("GEMINI_API_KEY"), reason="GEMINI_API_KEY not set")
def test_google_smoke() -> None:
    client = LLMClient()
    response = client.generate(
        LLMRequest(
            provider=Provider.GOOGLE,
            model=GOOGLE_SMOKE_MODEL,
            prompt="Reply with exactly one word: pong",
            max_tokens=16,
        )
    )
    _assert_valid_response(response)


@pytest.mark.skipif(not os.environ.get("OPENROUTER_API_KEY"), reason="OPENROUTER_API_KEY not set")
def test_openrouter_smoke() -> None:
    client = LLMClient()
    response = client.generate(
        LLMRequest(
            provider=Provider.OPENROUTER,
            model=OPENROUTER_SMOKE_MODEL,
            prompt="Reply with exactly one word: pong",
            max_tokens=16,
        )
    )
    _assert_valid_response(response)