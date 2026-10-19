"""OpenRouter provider using the OpenAI-compatible client."""

from __future__ import annotations

import os

from openai import OpenAI

from .models import LLMRequest, LLMResponse, Provider

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


class OpenRouterProvider:
    """Thin wrapper around OpenRouter's OpenAI-compatible chat completions API."""

    def __init__(self, api_key: str | None = None) -> None:
        key = api_key or os.environ.get("OPENROUTER_API_KEY")
        if not key:
            raise RuntimeError("OPENROUTER_API_KEY is not set. Add it to your .env file.")
        self._client = OpenAI(base_url=OPENROUTER_BASE_URL, api_key=key)

    def generate(self, request: LLMRequest) -> LLMResponse:
        messages = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        messages.append({"role": "user", "content": request.prompt})

        completion = self._client.chat.completions.create(
            model=request.model,
            messages=messages,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            # Some OpenRouter models (e.g. DeepSeek V4.1 Flash) enable hidden
            # reasoning by default, at "high" effort. Reasoning tokens count
            # against max_tokens like any other output, so a small budget can
            # get fully consumed by reasoning, leaving message.content empty.
            # This provider's contract is "answer text only," so reasoning is
            # disabled here rather than silently eating the token budget.
            extra_body={"reasoning": {"enabled": False}},
        )

        message = completion.choices[0].message
        text = message.content or ""

        return LLMResponse(
            provider=Provider.OPENROUTER,
            model=request.model,
            text=text,
        )