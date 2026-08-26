from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from phishguard.core.config import Settings
from phishguard.db.models import Base

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None

# Sentinel columns that must exist after v4+/market migrations.
_REQUIRED: dict[str, set[str]] = {
    "scans": {"reporter_id", "campaign_id", "bec_score", "decision_log_json"},
    "allowlist": {"scope", "expires_at"},
    "campaigns": {"fingerprint"},
    "click_tokens": {"target_url"},
    "users": {"password_hash"},
}


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("Database not initialized")
    return _engine


def _sqlite_schema_ok(engine: Engine) -> bool:
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    for table, cols in _REQUIRED.items():
        if table not in tables:
            return False
        existing = {c["name"] for c in insp.get_columns(table)}
        if not cols.issubset(existing):
            return False
    return True


def init_db(settings: Settings) -> None:
    global _engine, _SessionLocal
    url = settings.database_url
    connect_args = {}
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        if ":memory:" not in url:
            path = url.split("///")[-1]
            Path(path).parent.mkdir(parents=True, exist_ok=True)
    _engine = create_engine(url, connect_args=connect_args, future=True, pool_pre_ping=True)
    if url.startswith("sqlite") and ":memory:" not in url and not _sqlite_schema_ok(_engine):
        Base.metadata.drop_all(_engine)
    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)


def check_db() -> bool:
    if _engine is None:
        return False
    try:
        with _engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def get_session() -> Generator[Session, None, None]:
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized")
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
