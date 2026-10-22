"""Target ingestion, SSRF-safe spec acquisition, and assessment orchestration."""

from .security import (
    AUTHORIZED_ORIGINS,
    TEST_ONLY_AUTHORIZED_ORIGIN,
    TEST_ONLY_ORIGIN_ENV,
    ResolvedTarget,
    TargetValidationError,
    authorized_origins,
    is_authorized_origin,
    origin_of,
    resolve_target,
    test_only_origin_enabled,
    validate_pinned_addresses,
    validate_resolved_target,
    validate_spec_url,
    validate_target_url,
)
from .service import (
    DEFAULT_ASSESSMENT_REQUEST_BUDGET,
    AssessmentSchemaError,
    create_assessment,
)
from .spec_fetch import SpecUnavailableError, acquire_spec, save_spec

__all__ = [
    "AUTHORIZED_ORIGINS",
    "TEST_ONLY_AUTHORIZED_ORIGIN",
    "TEST_ONLY_ORIGIN_ENV",
    "DEFAULT_ASSESSMENT_REQUEST_BUDGET",
    "AssessmentSchemaError",
    "ResolvedTarget",
    "TargetValidationError",
    "SpecUnavailableError",
    "authorized_origins",
    "is_authorized_origin",
    "origin_of",
    "resolve_target",
    "test_only_origin_enabled",
    "validate_pinned_addresses",
    "validate_resolved_target",
    "validate_target_url",
    "validate_spec_url",
    "acquire_spec",
    "save_spec",
    "create_assessment",
]
