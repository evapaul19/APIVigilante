"""Tests for deterministic OpenAPI spec parsing (parser.py).

No LLM calls, no database, no network requests - pure spec parsing
against the real target spec plus a locally-built invalid spec for
the failure path.

The spec path is resolved relative to the repository root so that
tests work regardless of CWD when pytest is invoked from elsewhere.
"""
import os
import pytest
import tempfile
from pathlib import Path

# Resolve repository root from this file's location so the real spec
# works regardless of CWD when pytest is invoked from elsewhere.
TEST_FILE = Path(__file__).resolve()
PROJECT_ROOT = TEST_FILE.parent.parent  # .../api-security-system

from api_security_system.recon.parser import SpecParseError, parse_openapi_spec

REAL_SPEC_PATH = str(PROJECT_ROOT / "targets/vampi-openapi.yml")


def test_parse_real_spec_succeeds():
    endpoints = parse_openapi_spec(REAL_SPEC_PATH)
    assert len(endpoints) > 0
    for ep in endpoints:
        assert ep.method in {"GET", "POST", "PUT", "PATCH", "DELETE"}
        assert ep.path.startswith("/")


def test_parse_real_spec_no_duplicate_method_path_pairs():
    endpoints = parse_openapi_spec(REAL_SPEC_PATH)
    keys = [(ep.method, ep.path) for ep in endpoints]
    assert len(keys) == len(set(keys))


def test_parse_real_spec_resource_identification_only_for_param_paths():
    endpoints = parse_openapi_spec(REAL_SPEC_PATH)
    for ep in endpoints:
        if "{" not in ep.path:
            assert ep.resource_type is None
            assert ep.id_param_name is None


def test_parse_malformed_spec_raises_spec_parse_error():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write("this: is: not: valid: openapi: [unclosed")
        temp_path = f.name

    try:
        with pytest.raises(SpecParseError):
            parse_openapi_spec(temp_path)
    finally:
        Path(temp_path).unlink()


def test_parse_missing_file_raises_spec_parse_error():
    with pytest.raises(SpecParseError):
        parse_openapi_spec("targets/does-not-exist.yml")