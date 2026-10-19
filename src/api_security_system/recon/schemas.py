"""Pydantic schemas for the Recon module."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ParsedEndpoint(BaseModel):
    """A single endpoint extracted deterministically from an OpenAPI spec."""

    method: str
    path: str
    operation_id: Optional[str] = None
    resource_type: Optional[str] = None
    id_param_name: Optional[str] = None
    raw_spec_fragment: dict = Field(default_factory=dict)


class EndpointRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskClassification(BaseModel):
    """LLM-produced risk classification for a single endpoint, validated
    before it is allowed to reach the database."""

    risk_level: EndpointRiskLevel
    rationale: str
    confidence: Optional[float] = None