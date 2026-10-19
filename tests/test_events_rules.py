from datetime import datetime, timedelta, timezone

import pytest

from audittrail import events as ev
from audittrail.db import connect, init_schema
from audittrail.rules import evaluate_rules
from audittrail.events import EventError

BASE = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def ts(minutes: float) -> str:
    return (BASE + timedelta(minutes=minutes)).isoformat()


def make_event(event_id, event_type, minutes=0, user="u1", severity=1):
    return {
        "event_id": event_id, "ts": ts(minutes), "user_id": user,
        "event_type": event_type, "resource": "res", "severity": severity,
        "ip": "10.0.0.1", "details": {},
    }


@pytest.fixture()
def conn(tmp_path):
    c = connect(tmp_path / "test.db")
    init_schema(c)
    yield c
    c.close()


RULES = {
    "repeated_failed_login": {"enabled": True, "max_failures": 3, "window_minutes": 15, "severity": 3},
    "impossible_frequency": {"enabled": True, "max_events_per_minute": 10, "window_minutes": 1, "severity": 2},
    "suspicious_state_transition": {
        "enabled": True,
        "transitions": [["auth_failed", "password_reset"]],
        "window_minutes": 30, "severity": 4},
    "unusual_request_volume": {"enabled": True, "max_events_per_hour": 500, "severity": 2},
}


def test_validate_rejects_bad_events():
    with pytest.raises(EventError):
        ev._validate({"event_id": "x", "ts": ts(0), "event_type": "nope"})
    with pytest.raises(EventError):
        ev._validate({"event_id": "x", "ts": "not-a-date", "event_type": "auth_success"})
    with pytest.raises(EventError):
        ev._validate({"event_id": "", "ts": ts(0), "event_type": "auth_success"})
    with pytest.raises(EventError):
        ev._validate({"event_id": "x", "ts": ts(0), "event_type": "auth_success", "severity": 9})


def test_ingest_duplicate_ignored(conn):
    e = make_event("dup-1", "auth_success")
    assert ev.insert_event(conn, e) is True
    assert ev.insert_event(conn, e) is False
    assert conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"] == 1


def test_query_filters(conn):
    ev.insert_event(conn, make_event("1", "auth_failed", minutes=0, user="alice", severity=3))
    ev.insert_event(conn, make_event("2", "auth_success", minutes=10, user="bob"))
    ev.insert_event(conn, make_event("3", "auth_failed", minutes=20, user="bob", severity=2))

    assert len(ev.query_events(conn)) == 3
    assert len(ev.query_events(conn, user_id="bob")) == 2
    assert len(ev.query_events(conn, event_type="auth_failed")) == 2
    assert len(ev.query_events(conn, severity_min=3)) == 1
    both = ev.query_events(conn, ts_from=ts(5), ts_to=ts(15))
    assert [r["event_id"] for r in both] == ["2"]


def test_repeated_failed_login_rule():
    events = [make_event(f"f{i}", "auth_failed", minutes=i, user="mallory") for i in range(4)]
    risk = evaluate_rules(events, RULES)
    assert any(r["rule"] == "repeated_failed_login" and r["user_id"] == "mallory"
               and "4 failed" in r["detail"] for r in risk)
    events = events[:2]
    assert not any(r["rule"] == "repeated_failed_login" for r in evaluate_rules(events, RULES))


def test_suspicious_transition_rule():
    events = [
        make_event("s1", "auth_failed", minutes=0, user="sneaky"),
        make_event("s2", "password_reset", minutes=5, user="sneaky"),
    ]
    risk = evaluate_rules(events, RULES)
    assert any(r["rule"] == "suspicious_state_transition" and r["severity"] == 4 for r in risk)


def test_impossible_frequency_rule():
    events = [make_event(f"q{i}", "request", minutes=0, user="bot") for i in range(15)]
    risk = evaluate_rules(events, RULES)
    assert any(r["rule"] == "impossible_frequency" and r["user_id"] == "bot" for r in risk)


def test_unusual_volume_rule():
    events = [make_event(f"v{i}", "request", minutes=i % 60, user=f"u{i % 7}")
              for i in range(501)]
    risk = evaluate_rules(events, RULES)
    assert any(r["rule"] == "unusual_request_volume" for r in risk)


def test_rules_deterministic():
    import random

    events = [make_event(f"d{i}", random.Random(i).choice(["auth_failed", "request"]),
                         minutes=i % 30, user=f"u{i % 3}") for i in range(50)]
    assert evaluate_rules(events, RULES) == evaluate_rules(events, RULES)
