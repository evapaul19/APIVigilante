"""Provider-agnostic LLM client.

Callers build an LLMRequest and call LLMClient.generate(...). No part of
the rest of the application should import a specific provider module
directly — that defeats the point of this abstraction.
"""

from __future__ import annotations

from dotenv import load_dotenv

from .google_provider import GoogleProvider
from .models import LLMRequest, LLMResponse, Provider
from .openrouter_provider import OpenRouterProvider

load_dotenv()


class LLMClient:
    """Routes an LLMRequest to the correct provider.

    Providers are instantiated lazily, on first use, so a missing API
    key only raises when that specific provider is actually called.
    """

    def __init__(self) -> None:
        self._providers: dict[Provider, object] = {}

    def _get_provider(self, provider: Provider):
        if provider not in self._providers:
            if provider == Provider.GOOGLE:
                self._providers[provider] = GoogleProvider()
            elif provider == Provider.OPENROUTER:
                self._providers[provider] = OpenRouterProvider()
            else:
                raise ValueError(f"Unknown provider: {provider}")
        return self._providers[provider]

    def generate(self, request: LLMRequest) -> LLMResponse:
        provider = self._get_provider(request.provider)
        return provider.generate(request)