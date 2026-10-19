"""Normalized data models for the LLM provider abstraction."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class Provider(str, Enum):
    """Supported LLM providers."""

    GOOGLE = "google"
    OPENROUTER = "openrouter"


class LLMRequest(BaseModel):
    """A provider-agnostic request to an LLM."""

    provider: Provider
    model: str
    prompt: str
    system: str | None = None
    max_tokens: int = 512
    temperature: float = 0.0


class LLMResponse(BaseModel):
    """A provider-agnostic response from an LLM."""

    provider: Provider
    model: str
    text: str