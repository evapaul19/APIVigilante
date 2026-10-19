"""Integration tests for run_bola_check. Real Postgres (skipped if
DATABASE_URL unset, same pattern as other DB-backed tests in this
suite), mocked HTTP transport via RequestExecutor's injectable
transport - no real network calls, no dependency on a live VAmPI
instance.
"""

import os
import pytest
from pathlib import Path

# Resolve repository root from this file's location so the real spec
# works regardless of CWD when pytest is invoked from elsewhere.
TEST_FILE = Path(__file__).resolve()
PROJECT_ROOT = TEST_FILE.parent.parent  # .../api-security-system

from sqlmodel import select

from api_security_system.authz_bola import (
    AttemptOutcome,
    UnauthorizedTargetError,
    run_bola_check,
)
from api_security_system.authz_bola.schemas import BudgetExceededError
from api_security_system.db import (
    Endpoint,
    Finding,
    FindingEvidence,
    Scan,
    Target,
    TestExecution,
    TestIdentity,
    get_session,
)
from api_security_system.db.redaction import REDACTED_VALUE
from api_security_system.llm import LLMResponse, Provider
from api_security_system.recon.parser import parse_openapi_spec

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set",
)

REAL_SPEC_PATH = str(PROJECT_ROOT / "targets/vampi-openapi.yml")
AUTHORIZED_ORIGIN = "http://localhost:5000"