"""Tests for Resource Graph construction (builder.py).

Pure-function tests build endpoints directly in memory - no database,
including synthetic nested paths that don't exist in the real VAmPI
spec. DB-backed tests build against a real persisted VAmPI scan.

The spec path is resolved relative to the repository root so that
DB-backed tests work regardless of the caller's working directory.
"""
import os
from pathlib import Path

# Resolve repository root from this file's location so the real spec
# works regardless of CWD when pytest is invoked from elsewhere.
TEST_FILE = Path(__file__).resolve()
PROJECT_ROOT = TEST_FILE.parent.parent  # .../api-security-system

from sqlmodel import select

from api_security_system.db import Endpoint, Scan, Target, get_session
from api_security_system.recon.parser import parse_openapi_spec
from api_security_system.resource_graph import (
    EdgeRelation,
    ScanNotFoundError,
    build_resource_graph,
    build_resource_graph_from_endpoints,
)

REAL_SPEC_PATH = str(PROJECT_ROOT / "targets/vampi-openapi.yml")