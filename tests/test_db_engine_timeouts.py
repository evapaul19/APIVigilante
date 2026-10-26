"""Database connection options keep unavailable PostgreSQL operations bounded."""

from api_security_system.db import engine as db_engine


def test_postgresql_engine_uses_bounded_connect_and_statement_timeouts(monkeypatch):
    captured = {}

    def fake_create_engine(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://user:password@localhost:5432/database",
    )
    monkeypatch.setattr(db_engine, "create_engine", fake_create_engine)
    db_engine.get_engine.cache_clear()
    try:
        db_engine.get_engine()
    finally:
        db_engine.get_engine.cache_clear()

    assert captured["kwargs"]["pool_pre_ping"] is True
    assert captured["kwargs"]["pool_timeout"] == db_engine.DATABASE_POOL_TIMEOUT_SECONDS
    assert captured["kwargs"]["connect_args"] == {
        "connect_timeout": db_engine.DATABASE_CONNECT_TIMEOUT_SECONDS,
        "options": (
            f"-c statement_timeout={db_engine.DATABASE_STATEMENT_TIMEOUT_MS}"
        ),
    }
