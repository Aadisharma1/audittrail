from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from audittrail.api.app import create_app

BASE = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def ts(minutes: float = 0) -> str:
    return (BASE + timedelta(minutes=minutes)).isoformat()


def make_events():
    out = []
    for i in range(6):
        out.append({"event_id": f"f{i}", "ts": ts(i), "user_id": "mallory",
                    "event_type": "auth_failed", "severity": 3, "details": {}})
    out.append({"event_id": "ok1", "ts": ts(2), "user_id": "alice",
                "event_type": "auth_success", "severity": 0, "details": {}})
    out.append({"event_id": "sc1", "ts": ts(3), "user_id": "alice",
                "event_type": "state_change", "resource": "profile", "severity": 1,
                "details": {"field": "email"}})
    return out


@pytest.fixture()
def client(tmp_path):
    app = create_app(str(tmp_path / "api.db"))
    with TestClient(app) as c:
        yield c


def _token(client, username="auditor", password="audit-demo-2025") -> str:
    r = client.post("/auth/token", json={"username": username, "password": password})
    assert r.status_code == 200
    return r.json()["access_token"]


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_cors_allows_dashboard_origin(client):
    r = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "*"


def test_ingest_requires_auth(client):
    r = client.post("/events", json={"events": make_events()[:1]})
    assert r.status_code == 401


def test_token_bad_credentials(client):
    r = client.post("/auth/token", json={"username": "auditor", "password": "wrong"})
    assert r.status_code == 401


def test_ingest_and_duplicate_handling(client):
    token = _token(client)
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/events", json={"events": make_events()}, headers=headers)
    assert r.status_code == 200
    assert r.json() == {"accepted": 8, "duplicates_ignored": 0}
    r2 = client.post("/events", json={"events": make_events()}, headers=headers)
    assert r2.json() == {"accepted": 0, "duplicates_ignored": 8}
    assert client.get("/health").json()["events_stored"] == 8


def test_ingest_validation_error(client):
    token = _token(client)
    headers = {"Authorization": f"Bearer {token}"}
    bad = {"events": [{"event_id": "b1", "ts": ts(), "event_type": "nope"}]}
    assert client.post("/events", json=bad, headers=headers).status_code == 422


def test_filters(client):
    token = _token(client)
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/events", json={"events": make_events()}, headers=headers)
    assert client.get("/events", params={"user_id": "mallory"}).json()["count"] == 6
    assert client.get("/events", params={"event_type": "auth_failed"}).json()["count"] == 6
    assert client.get("/events", params={"severity_min": 3}).json()["count"] == 6
    r = client.get("/events", params={"ts_from": ts(4.5), "limit": 10})
    assert r.json()["count"] == 1 and r.json()["events"][0]["event_id"] == "f5"
    assert client.get("/events", params={"limit": 3}).json()["count"] == 3


def test_pagination_metadata(client):
    token = _token(client)
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/events", json={"events": make_events()}, headers=headers)

    page1 = client.get("/events", params={"limit": 3, "offset": 0}).json()
    assert page1["count"] == 3 and page1["total"] == 8
    assert page1["limit"] == 3 and page1["offset"] == 0

    last = client.get("/events", params={"limit": 3, "offset": 6}).json()
    assert last["count"] == 2 and last["total"] == 8

    filtered = client.get("/events", params={"user_id": "alice", "limit": 1}).json()
    assert filtered["total"] == 2 and filtered["count"] == 1


def test_risk_detection_and_auth(client):
    token = _token(client)
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/events", json={"events": make_events()}, headers=headers)
    assert client.get("/risk").status_code == 401
    r = client.get("/risk", headers=headers)
    assert r.status_code == 200
    risk = r.json()["risk_events"]
    assert any(x["rule"] == "repeated_failed_login" and x["user_id"] == "mallory"
               for x in risk), risk


def test_compliance_report_and_auth(client):
    token = _token(client)
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/events", json={"events": make_events()}, headers=headers)
    assert client.get("/reports/compliance").status_code == 401
    r = client.get("/reports/compliance", headers=headers)
    assert r.status_code == 200
    report = r.json()
    assert report["total_events"] == 8
    assert report["failed_logins_per_user"] == {"mallory": 6}
    assert report["events_per_type"]["auth_success"] == 1
    assert report["generated_at"]


def test_invalid_token_rejected(client):
    headers = {"Authorization": "Bearer not-a-jwt"}
    assert client.get("/risk", headers=headers).status_code == 401
