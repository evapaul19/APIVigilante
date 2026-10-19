"""Google Gemini provider using the official google-genai SDK."""

from __future__ import annotations

import os

from google import genai
from google.genai import types

from .models import LLMRequest, LLMResponse, Provider


class GoogleProvider:
    """Thin wrapper around the official Google GenAI SDK."""

    def __init__(self, api_key: str | None = None) -> None:
        key = api_key or os.environ.get("GEMINI_API_KEY")
        if not key:
            raise RuntimeError("GEMINI_API_KEY is not set. Add it to your .env file.")
        self._client = genai.Client(api_key=key)

    def generate(self, request: LLMRequest) -> LLMResponse:
        config = types.GenerateContentConfig(
            temperature=request.temperature,
            max_output_tokens=request.max_tokens,
            system_instruction=request.system,
        )

        response = self._client.models.generate_content(
            model=request.model,
            contents=request.prompt,
            config=config,
        )

        return LLMResponse(
            provider=Provider.GOOGLE,
            model=request.model,
            text=response.text or "",
        )