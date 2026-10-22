"""Pydantic schemas for sensitive-data exposure checks.

The result vocabulary deliberately distinguishes four outcomes:

- confirmed: evidence establishes that authentication secrets or private
  key material were disclosed to a caller that should not receive them
  (for example, plaintext passwords served without any credentials).
- candidate: sensitive-looking data (typically personal information) was
  observed, but the available evidence cannot establish that disclosure
  was inappropriate: the endpoint may be an intended public directory.
- ruled_out: no sensitive value was found, values were masked/placeholders,
  data belonged to the requesting identity, or the response was a
  legitimate token issuance.
- unsupported: the endpoint could not be inspected safely (unresolvable
  path parameter, side-effecting GET, transport failure, or no identity
  available for an authenticated endpoint).
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class SensitiveOutcome(str, Enum):
    CONFIRMED = "confirmed"
    CANDIDATE = "candidate"
    RULED_OUT = "ruled_out"
    UNSUPPORTED = "unsupported"


class SensitiveFieldObservation(BaseModel):
    """One normalized sensitive field pattern found in a response.

    `path` is normalized (`users[*].password`) and `occurrences` counts
    how many leaves matched. Raw values are never part of this object.
    """

    path: str
    category: str
    value_kind: str
    occurrences: int = 1
    declared_in_schema: bool = False


class SensitiveEndpointResult(BaseModel):
    endpoint_id: int
    method: str
    path: str
    operation_id: Optional[str] = None
    outcome: SensitiveOutcome
    inspected: bool = False
    auth_mode: str = "anonymous"
    subject_count: int = 0
    fields: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    finding_id: Optional[int] = None
    execution_id: Optional[int] = None
    rationale: str = ""


class SensitiveDataCheckResult(BaseModel):
    """Aggregate result of one sensitive-data inspection run."""

    scan_id: int
    target_base_url: str
    requests_used: int
    request_budget: int
    status: str = "not_run"
    reason: Optional[str] = None
    results: list[SensitiveEndpointResult] = Field(default_factory=list)

    @property
    def confirmed_findings(self) -> int:
        return sum(
            1 for item in self.results if item.outcome is SensitiveOutcome.CONFIRMED
        )

    @property
    def candidate_findings(self) -> int:
        return sum(
            1 for item in self.results if item.outcome is SensitiveOutcome.CANDIDATE
        )
