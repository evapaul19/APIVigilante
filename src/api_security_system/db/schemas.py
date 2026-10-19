"""Pydantic validation boundary for data entering the database.

SQLModel's table=True classes don't enforce Pydantic validation on
construction — this class is where enum membership is actually
checked for data that didn't originate from fully-trusted, already-
typed Python code (e.g. a finding categorized by the AuthZ Agent).
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from .enums import FindingSeverity, FindingType


class FindingCreate(BaseModel):
    scan_id: int
    endpoint_id: int
    finding_type: FindingType
    severity: FindingSeverity
    description: str
    confidence: Optional[float] = None