"""Configurable risk rules evaluated over stored events."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path


def load_rules(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _window_events(events: list[dict], minutes: float) -> list[dict]:
    """Events within the last `minutes` of the newest event timestamp
    (deterministic for a fixed event set, independent of wall clock)."""
    if not events:
        return []
    newest = max(_parse(e["ts"]) for e in events)
    cutoff = newest - timedelta(minutes=minutes)
    return [e for e in events if _parse(e["ts"]) >= cutoff]


def evaluate_rules(events: list[dict], rules: dict) -> list[dict]:
    """Return risk events found by every enabled rule. Pure function of
    (events, rules) -> deterministic and unit-testable."""
    risk: list[dict] = []

    cfg = rules.get("repeated_failed_login", {})
    if cfg.get("enabled"):
        window = _window_events([e for e in events if e["event_type"] == "auth_failed"],
                                cfg.get("window_minutes", 15))
        per_user: dict[str, int] = {}
        for e in window:
            if e.get("user_id"):
                per_user[e["user_id"]] = per_user.get(e["user_id"], 0) + 1
        for user, count in sorted(per_user.items()):
            if count >= cfg.get("max_failures", 5):
                risk.append({
                    "rule": "repeated_failed_login", "user_id": user,
                    "severity": cfg.get("severity", 3),
                    "detail": f"{count} failed logins within {cfg.get('window_minutes', 15)} min",
                })

    cfg = rules.get("impossible_frequency", {})
    if cfg.get("enabled") and events:
        window = _window_events(events, cfg.get("window_minutes", 1))
        per_user: dict[str, int] = {}
        for e in window:
            if e.get("user_id"):
                per_user[e["user_id"]] = per_user.get(e["user_id"], 0) + 1
        span = max(cfg.get("window_minutes", 1), 1e-9)
        for user, count in sorted(per_user.items()):
            if count > cfg.get("max_events_per_minute", 30) * span:
                risk.append({
                    "rule": "impossible_frequency", "user_id": user,
                    "severity": cfg.get("severity", 2),
                    "detail": f"{count} events in {cfg.get('window_minutes', 1)} min window",
                })

    cfg = rules.get("suspicious_state_transition", {})
    if cfg.get("enabled"):
        pairs = {tuple(p) for p in cfg.get("transitions", [])}
        minutes = cfg.get("window_minutes", 30)
        by_user: dict[str, list[dict]] = {}
        for e in events:
            if e.get("user_id"):
                by_user.setdefault(e["user_id"], []).append(e)
        for user, user_events in sorted(by_user.items()):
            window = sorted(_window_events(user_events, minutes), key=lambda e: e["ts"])
            types = [e["event_type"] for e in window]
            for i in range(len(types) - 1):
                if (types[i], types[i + 1]) in pairs:
                    risk.append({
                        "rule": "suspicious_state_transition", "user_id": user,
                        "severity": cfg.get("severity", 4),
                        "detail": f"{types[i]} -> {types[i+1]} within {minutes} min",
                    })
                    break

    cfg = rules.get("unusual_request_volume", {})
    if cfg.get("enabled") and events:
        hour_window = _window_events(events, 60)
        if len(hour_window) > cfg.get("max_events_per_hour", 500):
            risk.append({
                "rule": "unusual_request_volume", "user_id": None,
                "severity": cfg.get("severity", 2),
                "detail": f"{len(hour_window)} events in the last hour "
                          f"(threshold {cfg.get('max_events_per_hour', 500)})",
            })

    return sorted(risk, key=lambda r: -r["severity"])
