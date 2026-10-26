"""Database engine and session management."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlmodel import Session

DATABASE_CONNECT_TIMEOUT_SECONDS = 2
DATABASE_STATEMENT_TIMEOUT_MS = 5000
DATABASE_POOL_TIMEOUT_SECONDS = 5

# Load .env from the project root directory regardless of CWD.
# The engine module is at src/api_security_system/db/engine.py, so the
# project root is four levels up: engine.py -> db -> api_security_system -> src -> root.
_ENGINE_MODULE_PATH = Path(__file__).resolve()
_PROJECT_ROOT = _ENGINE_MODULE_PATH.parents[3]  # .../api-security-system
load_dotenv(dotenv_path=_PROJECT_ROOT / ".env")


@lru_cache
def get_engine():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set. Add it to your .env file.")

    parsed_url = make_url(url)
    engine_options = {
        "pool_pre_ping": True,
        "pool_timeout": DATABASE_POOL_TIMEOUT_SECONDS,
    }
    if parsed_url.get_backend_name() == "postgresql":
        engine_options["connect_args"] = {
            "connect_timeout": DATABASE_CONNECT_TIMEOUT_SECONDS,
            "options": f"-c statement_timeout={DATABASE_STATEMENT_TIMEOUT_MS}",
        }

    return create_engine(url, **engine_options)


def get_session() -> Session:
    return Session(get_engine())