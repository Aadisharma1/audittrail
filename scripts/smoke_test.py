"""AuditTrail smoke test: auth -> ingest (+duplicates) -> filters -> risk ->
compliance report, against a fresh in-memory-seeded app instance.

Run:  python scripts/smoke_test.py
"""

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fastapi.testclient import TestClient

from audittrail.api.app import create_app


def main() -> int:
    app = create_app(str(Path(tempfile.mkdtemp()) / "smoke.db"))
    with TestClient(app) as c:
        print("=== AUDITTRAIL SMOKE TEST ===")
        print(f"health: {c.get('/health').json()}")

        r = c.post("/auth/token", json={"username": "auditor", "password": "audit-demo-2025"})
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"token issued for role: {r.json()['role']}")

        now = datetime.now(timezone.utc)
        events = [
            {"event_id": f"sm-f{i}", "ts": (now - timedelta(minutes=i)).isoformat(),
             "user_id": "mallory", "event_type": "auth_failed", "severity": 3, "details": {}}
            for i in range(6)
        ]
        r = c.post("/events", json={"events": events}, headers=headers)
        print(f"ingest: {r.json()}")
        assert r.json() == {"accepted": 6, "duplicates_ignored": 0}
        r = c.post("/events", json={"events": events}, headers=headers)
        print(f"ingest replay: {r.json()}")
        assert r.json() == {"accepted": 0, "duplicates_ignored": 6}

        assert c.get("/events", params={"user_id": "mallory"}).json()["count"] == 6

        risk = c.get("/risk", headers=headers).json()["risk_events"]
        print(f"risk events: {[(x['rule'], x.get('user_id')) for x in risk]}")
        assert any(x["rule"] == "repeated_failed_login" for x in risk)

        report = c.get("/reports/compliance", headers=headers).json()
        print(f"compliance report: total={report['total_events']} "
              f"failed_logins={report['failed_logins_per_user']}")
        assert report["total_events"] == 6

        assert c.get("/risk").status_code == 401
        print("unauthenticated /risk correctly rejected (401)")
    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
