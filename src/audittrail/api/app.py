"""FastAPI app: ingestion, query, risk, compliance reports (JWT-protected)."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from audittrail import auth, events
from audittrail.db import connect, init_schema
from audittrail.rules import evaluate_rules, load_rules


class EventIn(BaseModel):
    event_id: str = Field(min_length=1)
    ts: str = Field(min_length=1)
    user_id: str | None = None
    event_type: str
    resource: str | None = None
    severity: int = 0
    ip: str | None = None
    details: dict = Field(default_factory=dict)


class EventBatch(BaseModel):
    events: list[EventIn] = Field(min_length=1)


class TokenRequest(BaseModel):
    username: str
    password: str


def create_app(db_path: str | None = None, rules_path: str | None = None) -> FastAPI:
    db_path = db_path or os.environ.get("AUDITTRAIL_DB", str(Path("data") / "audit.db"))
    rules_path = rules_path or os.environ.get("AUDITTRAIL_RULES") or \
        Path(__file__).resolve().parents[3] / "configs" / "rules.json"
    conn = connect(db_path)
    init_schema(conn)
    rules = load_rules(rules_path)

    app = FastAPI(title="AuditTrail", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.conn = conn
    app.state.rules = rules

    def require_auth(authorization: str | None = Header(default=None)) -> dict:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        claims = auth.verify_token(authorization.removeprefix("Bearer ").strip())
        if not claims:
            raise HTTPException(status_code=401, detail="invalid or expired token")
        return claims

    @app.post("/auth/token")
    def token(req: TokenRequest) -> dict:
        user = auth.authenticate(req.username, req.password)
        if not user:
            raise HTTPException(status_code=401, detail="bad credentials")
        return {"access_token": auth.issue_token(user), "role": user["role"]}

    @app.post("/events")
    def post_events(batch: EventBatch, claims: dict = Depends(require_auth)) -> dict:
        accepted, duplicates = 0, 0
        for ev in batch.events:
            try:
                if events.insert_event(conn, ev.model_dump()):
                    accepted += 1
                else:
                    duplicates += 1
            except events.EventError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"accepted": accepted, "duplicates_ignored": duplicates}

    @app.get("/events")
    def get_events(
        user_id: str | None = None,
        event_type: str | None = None,
        severity_min: int | None = Query(default=None, ge=0, le=4),
        ts_from: str | None = None,
        ts_to: str | None = None,
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> dict:
        rows = events.query_events(conn, user_id, event_type, severity_min,
                                   ts_from, ts_to, limit, offset)
        total = events.count_events(conn, user_id, event_type, severity_min,
                                    ts_from, ts_to)
        return {
            "events": rows,
            "count": len(rows),
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @app.get("/risk")
    def risk(claims: dict = Depends(require_auth)) -> dict:
        all_events = events.query_events(conn, limit=1000)
        return {"risk_events": evaluate_rules(all_events, rules)}

    @app.get("/reports/compliance")
    def compliance(days: int = Query(default=30, ge=1, le=365),
                   claims: dict = Depends(require_auth)) -> dict:
        rows = events.query_events(conn, limit=1000)
        per_day: dict[str, int] = {}
        per_type: dict[str, int] = {}
        failed_by_user: dict[str, int] = {}
        events_by_user: dict[str, int] = {}
        for r in rows:
            day = r["ts"][:10]
            per_day[day] = per_day.get(day, 0) + 1
            per_type[r["event_type"]] = per_type.get(r["event_type"], 0) + 1
            if r["user_id"]:
                events_by_user[r["user_id"]] = events_by_user.get(r["user_id"], 0) + 1
            if r["event_type"] == "auth_failed" and r["user_id"]:
                failed_by_user[r["user_id"]] = failed_by_user.get(r["user_id"], 0) + 1
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "window_days": days,
            "total_events": len(rows),
            "events_per_day": dict(sorted(per_day.items())),
            "events_per_type": dict(sorted(per_type.items(), key=lambda kv: -kv[1])),
            "failed_logins_per_user": dict(sorted(failed_by_user.items(), key=lambda kv: -kv[1])),
            "top_users_by_activity": dict(sorted(events_by_user.items(), key=lambda kv: -kv[1])[:10]),
            "risk_events": evaluate_rules(rows, rules),
        }
        return report

    @app.get("/health")
    def health() -> dict:
        n = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        return {"status": "ok", "events_stored": n}

    return app


app = create_app()
