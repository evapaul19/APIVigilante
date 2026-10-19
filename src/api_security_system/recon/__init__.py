"""Recon: deterministic OpenAPI spec parsing + LLM risk classification.

No target API HTTP requests happen here - purely local spec parsing
and risk classification.
"""

from .classifier import ClassificationError, classify_endpoint
from .parser import SpecParseError, parse_openapi_spec
from .schemas import EndpointRiskLevel, ParsedEndpoint, RiskClassification
from .service import ReconResult, ScanNotFoundError, run_recon

__all__ = [
    "run_recon",
    "ReconResult",
    "ScanNotFoundError",
    "parse_openapi_spec",
    "SpecParseError",
    "classify_endpoint",
    "ClassificationError",
    "ParsedEndpoint",
    "RiskClassification",
    "EndpointRiskLevel",
]