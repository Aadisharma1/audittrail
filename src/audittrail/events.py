"""Event schema + storage operations."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from audittrail.db import tx

ALLOWED_TYPES = {
    "auth_success", "auth_failed", "state_change", "request",
    "privilege_grant", "role_escalation", "account_disabled", "password_reset",
}


class EventError(ValueError):
    pass


def _validate(event: dict) -> None:
    if not event.get("event_id"):
        raise EventError("event_id is required")
    if event.get("event_type") not in ALLOWED_TYPES:
        raise EventError(f"event_type must be one of {sorted(ALLOWED_TYPES)}")
    sev = event.get("severity", 0)
    if not isinstance(sev, int) or not 0 <= sev <= 4:
        raise EventError("severity must be an integer 0-4")
    if not event.get("ts"):
        raise EventError("ts is required (ISO-8601)")
    try:
        datetime.fromisoformat(event["ts"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise EventError(f"ts is not valid ISO-8601: {exc}") from exc


def insert_event(conn: sqlite3.Connection, event: dict) -> bool:
    """Insert an event; returns False if it was a duplicate event_id."""
    _validate(event)
    try:
        with tx(conn):
            conn.execute(
                "INSERT INTO events (event_id, ts, user_id, event_type, resource, severity, ip, details)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event["event_id"], event["ts"], event.get("user_id"),
                    event["event_type"], event.get("resource"),
                    int(event.get("severity", 0)), event.get("ip"),
                    json.dumps(event.get("details") or {}),
                ),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def _filter_sql_and_params(user_id: str | None, event_type: str | None,
                           severity_min: int | None, ts_from: str | None,
                           ts_to: str | None) -> tuple[str, list]:
    sql = " WHERE 1=1"
    params: list = []
    if user_id:
        sql += " AND user_id = ?"
        params.append(user_id)
    if event_type:
        sql += " AND event_type = ?"
        params.append(event_type)
    if severity_min is not None:
        sql += " AND severity >= ?"
        params.append(severity_min)
    if ts_from:
        sql += " AND ts >= ?"
        params.append(ts_from)
    if ts_to:
        sql += " AND ts <= ?"
        params.append(ts_to)
    return sql, params


def query_events(conn: sqlite3.Connection, user_id: str | None = None,
                 event_type: str | None = None, severity_min: int | None = None,
                 ts_from: str | None = None, ts_to: str | None = None,
                 limit: int = 100, offset: int = 0) -> list[dict]:
    where, params = _filter_sql_and_params(user_id, event_type, severity_min,
                                           ts_from, ts_to)
    sql = "SELECT * FROM events" + where
    sql += " ORDER BY ts DESC LIMIT ? OFFSET ?"
    params += [max(1, min(limit, 1000)), max(0, offset)]
    rows = conn.execute(sql, params).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["details"] = json.loads(d["details"] or "{}")
        out.append(d)
    return out


def count_events(conn: sqlite3.Connection, user_id: str | None = None,
                 event_type: str | None = None, severity_min: int | None = None,
                 ts_from: str | None = None, ts_to: str | None = None) -> int:
    """Total matching rows, independent of pagination — lets the API return
    honest `total` metadata alongside a page of events."""
    where, params = _filter_sql_and_params(user_id, event_type, severity_min,
                                           ts_from, ts_to)
    row = conn.execute("SELECT COUNT(*) FROM events" + where, params).fetchone()
    return int(row[0])
