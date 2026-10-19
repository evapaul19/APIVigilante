"""Database engine and session management."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlmodel import Session

# Load .env from the project root directory regardless of CWD.
# The engine module is at src/api_security_system/db/engine.py,
# so the project root is three levels up: .../db/engine.py -> .../db/ -> .../src/ -> project root.
_ENGINE_MODULE_PATH = Path(__file__).resolve()
_PROJECT_ROOT = _ENGINE_MODULE_PATH.parent.parent.parent  # .../api-security-system
load_dotenv(dotenv_path=_PROJECT_ROOT / ".env")


@lru_cache
def get_engine():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set. Add it to your .env file.")
    return create_engine(url)


def get_session() -> Session:
    return Session(get_engine())