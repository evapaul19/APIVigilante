"""Pydantic schemas and exception types for the AuthZ/BOLA MVP."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class UnauthorizedTargetError(Exception):
    """Raised when the scan's Target.base_url is not the explicitly
    authorized local VAmPI origin. Raised before any request -
    including identity registration - is sent."""


class BudgetExceededError(Exception):
    """Raised when a BOLA run would exceed its request budget. Always
    raised before the request that would exceed it is sent, never
    after - the budget check happens first."""


class AttemptOutcome(str, Enum):
    ACCESS_DENIED = "access_denied"
    CONFIRMED = "confirmed"
    RULED_OUT = "ruled_out"
    AMBIGUOUS = "ambiguous"
    NOT_APPLICABLE = "not_applicable"


class BolaCandidate(BaseModel):
    """A single object-level, authentication-required 'user' endpoint
    eligible for BOLA testing - confirmed via Resource Graph's
    IDENTIFIES edges plus the endpoint's own spec-declared security
    requirement."""

    endpoint_id: int
    method: str
    path: str
    operation_id: Optional[str] = None
    id_param_name: str
    summary: Optional[str] = None
    description: Optional[str] = None


class BflaCandidate(BaseModel):
    """An operation that documentation semantics say requires a higher
    privilege. Deliberately independent of Resource Graph IDENTIFIES
    edges (e.g. /me or DELETE /users/{username} need not be object-level
    BOLA candidates to be BFLA candidates)."""

    endpoint_id: int
    method: str
    path: str
    operation_id: Optional[str] = None
    id_param_name: Optional[str] = None
    signal: str
    rationale: str


class EndpointTestResult(BaseModel):
    """The outcome of testing one candidate endpoint. ACCESS_DENIED and
    RULED_OUT never produce a Finding - the outcome itself, plus the
    preserved TestExecution evidence, is the record of a ruled-out or
    correctly-denied test."""

    operation_id: Optional[str] = None
    path: str
    outcome: AttemptOutcome
    check_type: str = "bola"
    attempt_execution_id: Optional[int] = None
    verification_execution_ids: list[int] = Field(default_factory=list)
    finding_id: Optional[int] = None
    rationale: Optional[str] = None


class BolaCheckResult(BaseModel):
    """The full result of one authorization-check run against the 'user'
    resource. BOLA and BFLA results are kept separate."""

    scan_id: int
    target_base_url: str
    requests_used: int
    request_budget: int
    endpoint_results: list[EndpointTestResult] = Field(default_factory=list)
    bfla_results: list[EndpointTestResult] = Field(default_factory=list)
    bfla_status: str = "not_run"
    bfla_reason: Optional[str] = None
    stopped_early: bool = False
    stopped_reason: Optional[str] = None