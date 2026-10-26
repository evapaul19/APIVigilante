"""SQLModel table definitions for the API security testing database."""


from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import CheckConstraint, Column, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, Relationship, SQLModel

from .enums import FindingSeverity, FindingStatus, FindingType, ScanStatus


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Target(SQLModel, table=True):
    __tablename__ = "targets"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    base_url: str
    openapi_spec_path: str
    created_at: datetime = Field(default_factory=_utcnow)

    scans: list["Scan"] = Relationship(back_populates="target")


class Scan(SQLModel, table=True):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','running','completed','partial','failed')",
            name="ck_scans_status",
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="targets.id")
    status: ScanStatus = Field(default=ScanStatus.PENDING, sa_column=Column(String(32)))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    target: Target = Relationship(back_populates="scans")
    endpoints: list["Endpoint"] = Relationship(back_populates="scan")
    test_identities: list["TestIdentity"] = Relationship(back_populates="scan")
    findings: list["Finding"] = Relationship(back_populates="scan")


class AssessmentStage(SQLModel, table=True):
    """Persisted outcome of one assessment stage for a scan.

    One row per stage per scan. `details` holds stage-specific counts and
    check results only; secrets must be sanitized before persistence.
    """

    __tablename__ = "assessment_stages"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "stage_name",
            name="uq_assessment_stages_scan_id_stage_name",
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scans.id")
    stage_name: str
    sequence: int
    status: str = Field(sa_column=Column(String(64)))
    reason: Optional[str] = None
    details: dict = Field(default_factory=dict, sa_column=Column(JSONB))
    recorded_at: datetime = Field(default_factory=_utcnow)


class Endpoint(SQLModel, table=True):
    __tablename__ = "endpoints"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scans.id")
    path: str
    method: str
    operation_id: Optional[str] = None
    resource_type: Optional[str] = None
    id_param_name: Optional[str] = None
    risk_classification: Optional[str] = None
    raw_spec_fragment: dict = Field(default_factory=dict, sa_column=Column(JSONB))

    scan: Scan = Relationship(back_populates="endpoints")
    test_executions: list["TestExecution"] = Relationship(back_populates="endpoint")
    findings: list["Finding"] = Relationship(back_populates="endpoint")


class TestIdentity(SQLModel, table=True):
    __tablename__ = "test_identities"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scans.id")
    role_label: str
    description: Optional[str] = None

    scan: Scan = Relationship(back_populates="test_identities")
    test_executions: list["TestExecution"] = Relationship(back_populates="identity")


class TestExecution(SQLModel, table=True):
    __tablename__ = "test_executions"

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scans.id")
    endpoint_id: int = Field(foreign_key="endpoints.id")
    identity_id: Optional[int] = Field(default=None, foreign_key="test_identities.id")
    request_headers: dict = Field(default_factory=dict, sa_column=Column(JSONB))
    request_body: Optional[dict] = Field(default=None, sa_column=Column(JSONB))
    response_status: int
    response_headers: dict = Field(default_factory=dict, sa_column=Column(JSONB))
    response_body: Optional[dict] = Field(default=None, sa_column=Column(JSONB))
    latency_ms: int
    executed_at: datetime = Field(default_factory=_utcnow)

    endpoint: Endpoint = Relationship(back_populates="test_executions")
    identity: Optional[TestIdentity] = Relationship(back_populates="test_executions")
    finding_evidence: list["FindingEvidence"] = Relationship(back_populates="execution")


class Finding(SQLModel, table=True):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="ck_findings_severity",
        ),
        CheckConstraint(
            "status IN ('candidate','confirmed','false_positive')",
            name="ck_findings_status",
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scans.id")
    endpoint_id: int = Field(foreign_key="endpoints.id")
    finding_type: FindingType = Field(sa_column=Column(String(64)))
    severity: FindingSeverity = Field(sa_column=Column(String(16)))
    description: str
    status: FindingStatus = Field(default=FindingStatus.CANDIDATE, sa_column=Column(String(32)))
    confidence: Optional[float] = None

    scan: Scan = Relationship(back_populates="findings")
    endpoint: Endpoint = Relationship(back_populates="findings")
    evidence: list["FindingEvidence"] = Relationship(back_populates="finding")


class FindingEvidence(SQLModel, table=True):
    __tablename__ = "finding_evidence"

    finding_id: int = Field(foreign_key="findings.id", primary_key=True)
    execution_id: int = Field(foreign_key="test_executions.id", primary_key=True)

    finding: Finding = Relationship(back_populates="evidence")
    execution: TestExecution = Relationship(back_populates="finding_evidence")