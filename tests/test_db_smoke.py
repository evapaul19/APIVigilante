"""Smoke test for the database foundation. Skipped if DATABASE_URL isn't set."""

import os

import pytest
from sqlmodel import select

from api_security_system.db import Target, get_session


@pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="DATABASE_URL not set")
def test_db_roundtrip() -> None:
    with get_session() as session:
        target = Target(
            name="smoke-test-target",
            base_url="http://localhost:9999",
            openapi_spec_path="targets/smoke.yml",
        )
        session.add(target)
        session.commit()
        session.refresh(target)

        found = session.exec(select(Target).where(Target.id == target.id)).first()
        assert found is not None
        assert found.name == "smoke-test-target"

        session.delete(found)
        session.commit()