"""Seed a demo dataset (some benign, some risky) into a fresh DB.

Run:  python scripts/seed_demo.py [--db data/audit.db]
"""

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from audittrail.db import connect, init_schema
from audittrail.events import insert_event


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="data/audit.db")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    conn = connect(args.db)
    init_schema(conn)
    rng = random.Random(args.seed)
    now = datetime.now(timezone.utc)

    users = ["alice", "bob", "carol", "dave"]
    benign_types = ["auth_success", "request", "state_change"]
    batch = []
    n = 0

    for i in range(200):
        ts = now - timedelta(minutes=rng.randrange(0, 1440))
        batch.append({
            "event_id": f"demo-b{i}", "ts": ts.isoformat(),
            "user_id": rng.choice(users), "event_type": rng.choice(benign_types),
            "resource": "portal", "severity": 0,
            "ip": f"10.0.{rng.randrange(255)}.{rng.randrange(255)}", "details": {},
        })
        n += 1

    for i in range(8):
        batch.append({
            "event_id": f"demo-f{i}", "ts": (now - timedelta(minutes=i)).isoformat(),
            "user_id": "mallory", "event_type": "auth_failed",
            "resource": "login", "severity": 3, "ip": "203.0.113.9", "details": {},
        })
        n += 1

    batch.append({"event_id": "demo-t1", "ts": (now - timedelta(minutes=20)).isoformat(),
                  "user_id": "sneaky", "event_type": "auth_failed", "severity": 2, "details": {}})
    batch.append({"event_id": "demo-t2", "ts": (now - timedelta(minutes=19)).isoformat(),
                  "user_id": "sneaky", "event_type": "password_reset", "severity": 4, "details": {}})
    n += 2

    inserted = sum(1 for e in batch if insert_event(conn, e))
    conn.close()
    print(json.dumps({"seeded": inserted, "total": n, "db": args.db}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
