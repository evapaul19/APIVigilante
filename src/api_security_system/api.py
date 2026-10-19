
"""HTTP API for the API security assessment system."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import text
from sqlmodel import Session, select

from api_security_system.db import (
    Finding,
    Scan,
    ScanStatus,
    Target,
    get_session,
)
from api_security_system.recon.service import run_recon, ScanNotFoundError


def database_session():
    """Provide one database session for a request."""
    with get_session() as session:
        yield session


SessionDep = Annotated[Session, Depends(database_session)]


class ScanCreate(BaseModel):
    """Request body for creating a scan record."""

    target_id: int


class ScanResponse(BaseModel):
    """Public representation of a scan."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    status: ScanStatus
    started_at: datetime | None
    completed_at: datetime | None


class FindingResponse(BaseModel):
    """Public representation of a finding."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    endpoint_id: int
    finding_type: str
    severity: str
    description: str
    status: str
    confidence: float | None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize application resources when needed."""
    yield


app = FastAPI(
    title="API Security Assessment System",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health(session: SessionDep):
    """Report application and database health."""
    try:
        session.exec(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        ) from exc

    return {"status": "ok", "database": "connected"}


@app.post("/scans", response_model=ScanResponse, status_code=201)
def create_scan(payload: ScanCreate, session: SessionDep):
    """Create a pending scan for an existing target."""
    target = session.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = Scan(
        target_id=target.id,
        status=ScanStatus.PENDING,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    return scan


@app.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, session: SessionDep):
    """Retrieve a scan's current lifecycle state."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@app.get("/scans/{scan_id}/findings", response_model=list[FindingResponse])
def get_scan_findings(scan_id: int, session: SessionDep):
    """List findings persisted for a scan."""
    if session.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return session.exec(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.id)
    ).all()


@app.post("/scans/{scan_id}/recon", response_model=dict)
def trigger_recon(scan_id: int, session: SessionDep):
    """Explicitly trigger reconnaissance for a scan.

    Parses the target's OpenAPI specification, persists endpoint inventory,
    and runs LLM-based risk classification. Existing endpoint inventory
    is preserved if classification fails (two-phase persistence pattern).

    Does NOT mark the scan as completed - that is a separate lifecycle step.
    """
    from api_security_system.llm import LLMClient

    # Ensure scan exists
    if session.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    llm_client = LLMClient()
    try:
        result = run_recon(scan_id, llm_client=llm_client)
    except ScanNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Update scan started/completed timestamps for the recon stage
    scan = session.get(Scan, scan_id)
    if scan.started_at is None:
        from datetime import datetime, timezone
        scan.started_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()

    return {
        "scan_id": scan_id,
        "endpoints_found": result.endpoints_found,
        "endpoints_inserted": result.endpoints_inserted,
        "endpoints_skipped_duplicate": result.endpoints_skipped_duplicate,
        "classifications_succeeded": result.classifications_succeeded,
        "classifications_failed": result.classifications_failed,
        "stage": "recon_complete",
    }
