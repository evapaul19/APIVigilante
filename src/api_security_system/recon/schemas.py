"""Pydantic schemas for the Recon module."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class NormalizedParameter(BaseModel):
    """Inventory metadata for one OpenAPI parameter.

    No parameter values are synthesized. ``schema_type`` describes the
    declared contract only; downstream checks still decide whether and how
    a concrete value can be supplied safely.
    """

    name: Optional[str] = None
    location: str = "unknown"
    required: bool = False
    schema_type: Optional[str] = None
    schema_format: Optional[str] = None
    has_schema: bool = False
    unresolved_reference: Optional[str] = None


class CoverageIssue(BaseModel):
    """A non-fatal inventory limitation tied to one operation or parameter."""

    method: Optional[str] = None
    path: Optional[str] = None
    operation_id: Optional[str] = None
    parameter: Optional[str] = None
    location: Optional[str] = None
    reason: str


class ParsedEndpoint(BaseModel):
    """A single endpoint extracted deterministically from an OpenAPI spec."""

    method: str
    path: str
    operation_id: Optional[str] = None
    resource_type: Optional[str] = None
    id_param_name: Optional[str] = None
    raw_spec_fragment: dict = Field(default_factory=dict)
    parameters: list[NormalizedParameter] = Field(default_factory=list)
    required_parameter_count: int = 0
    optional_parameter_count: int = 0
    unresolved_required_parameters: list[str] = Field(default_factory=list)
    request_body_required: bool = False
    request_body_media_types: list[str] = Field(default_factory=list)
    operation_id_generated: bool = False


class ReconCoverage(BaseModel):
    """Counts and limitations for spec-to-inventory normalization.

    Counts are deliberately separated:

    * ``operations_discovered`` counts unique method/path operations in the
      specification, including unsupported ones.
    * ``operations_normalized`` counts operations represented as endpoints.
    * ``operations_persisted`` is set by Recon after database writes and
      includes operations that were already persisted for the scan.

    The limitation lists are indicators, not additional operation totals;
    one operation can appear in more than one list. Lists are capped by the
    parser to keep persisted stage details bounded.
    """

    spec_format: Optional[str] = None
    spec_version: Optional[str] = None
    base_path: Optional[str] = None
    servers: list[str] = Field(default_factory=list)
    applied_path_prefix: Optional[str] = None
    operations_discovered: int = 0
    operations_normalized: int = 0
    operations_persisted: int = 0
    operations_inserted: int = 0
    operations_skipped_duplicate: int = 0
    operations_unsupported: int = 0
    operations_excluded_unsafe: int = 0
    operations_execution_restricted: int = 0
    operations_with_required_parameters: int = 0
    operations_with_unresolved_required_parameters: int = 0
    operations_requiring_request_body: int = 0
    missing_operation_ids: int = 0
    duplicate_operation_ids: int = 0
    generated_operation_ids: int = 0
    parameter_locations: dict[str, int] = Field(default_factory=dict)
    unsupported_operations: list[CoverageIssue] = Field(default_factory=list)
    excluded_operations: list[CoverageIssue] = Field(default_factory=list)
    unresolved_parameters: list[CoverageIssue] = Field(default_factory=list)
    required_request_bodies: list[CoverageIssue] = Field(default_factory=list)
    execution_restrictions: list[CoverageIssue] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    details_truncated: bool = False


class ParsedSpec(BaseModel):
    """Normalized endpoint inventory plus explicit coverage accounting."""

    endpoints: list[ParsedEndpoint] = Field(default_factory=list)
    coverage: ReconCoverage = Field(default_factory=ReconCoverage)


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