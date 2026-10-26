"""Shared enum types for the database layer.

These are Python enums backed by plain string columns in PostgreSQL,
not native Postgres enum types — see project notes on why: native
enums make adding a value (e.g. a new vulnerability category) a real
migration with transaction restrictions, which conflicts with how
often finding_type in particular is expected to grow.
"""

from __future__ import annotations

from enum import Enum


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    # PARTIAL means the assessment finished, produced an inventory, but one
    # or more security stages failed. It must not be presented as a clean
    # completed assessment.
    PARTIAL = "partial"
    FAILED = "failed"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    BOLA = "bola"
    BFLA = "bfla"
    SENSITIVE_DATA = "sensitive_data"
    # New vulnerability categories are added here as agents land —
    # no migration needed, since the column is a plain string.


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"