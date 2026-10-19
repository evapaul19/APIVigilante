"""LLM provider abstraction.

Usage:
    from api_security_system.llm import LLMClient, LLMRequest, Provider

    client = LLMClient()
    response = client.generate(
        LLMRequest(provider=Provider.GOOGLE, model="gemini-3.5-flash-lite", prompt="hello")
    )
"""

from .client import LLMClient
from .models import LLMRequest, LLMResponse, Provider

__all__ = ["LLMClient", "LLMRequest", "LLMResponse", "Provider"]
