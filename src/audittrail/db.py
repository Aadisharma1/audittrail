"""SQLite storage (default) with a clean seam for PostgreSQL."""

from __future__ import annotations

import contextlib
import os
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
    ts         TEXT NOT NULL,
    user_id    TEXT,
    event_type TEXT NOT NULL,
    resource   TEXT,
    severity   INTEGER NOT NULL DEFAULT 0 CHECK (severity BETWEEN 0 AND 4),
    ip         TEXT,
    details    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
"""


def connect(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or os.environ.get("AUDITTRAIL_DB", str(Path("data") / "audit.db"))
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


@contextlib.contextmanager
def tx(conn: sqlite3.Connection):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")
