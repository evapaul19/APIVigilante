"""Recon: deterministic OpenAPI spec parsing + LLM risk classification.

No target API HTTP requests happen here - purely local spec parsing
and risk classification.
"""

from .classifier import ClassificationError, classify_endpoint
from .parser import (
    SpecParseError,
    parse_openapi_spec,
    parse_openapi_spec_with_coverage,
)
from .schemas import (
    CoverageIssue,
    EndpointRiskLevel,
    NormalizedParameter,
    ParsedEndpoint,
    ParsedSpec,
    ReconCoverage,
    RiskClassification,
)
from .service import ReconResult, ScanNotFoundError, run_recon

__all__ = [
    "run_recon",
    "ReconResult",
    "ScanNotFoundError",
    "parse_openapi_spec",
    "parse_openapi_spec_with_coverage",
    "SpecParseError",
    "classify_endpoint",
    "ClassificationError",
    "ParsedEndpoint",
    "ParsedSpec",
    "ReconCoverage",
    "NormalizedParameter",
    "CoverageIssue",
    "RiskClassification",
    "EndpointRiskLevel",
]
