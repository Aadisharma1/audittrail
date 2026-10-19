# AuditTrail

Centralized risk & audit logging microservice: FastAPI + SQLite backend with a
structured event schema, JWT-protected endpoints, configurable risk rules
(repeated failed logins, impossible frequency, suspicious state transitions,
unusual volume), audit query APIs, aggregation/compliance reports, and a
**Next.js** dashboard (recent events, failed logins, risk feed, severity
badges, filters + date ranges, per-user activity, report panel).

**Status:** code complete, NOT YET EXECUTED. Run the verification below on
your machine for real results.

## Architecture

```mermaid
flowchart LR
    APP[Applications] -->|POST /events (JWT)| API
    subgraph Backend [FastAPI + SQLite]
        API[Ingest / Query / Risk / Reports]
        DB[(events table<br/>WAL, indexed)]
        R[Configurable risk rules<br/>configs/rules.json]
        A[JWT auth<br/>AUDITTRAIL_JWT_SECRET env]
        API --> DB
        API --> R
        API --> A
    end
    DASH[Next.js dashboard] -->|GET events/risk/reports| API
```

## API

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/auth/token` | — | demo users from `configs/users.json` |
| GET | `/health` | — | liveness + stored count |
| POST | `/events` | Bearer | batch ingest; duplicate `event_id` → `duplicates_ignored` |
| GET | `/events` | — | filters: user, type, severity_min, ts_from/to, limit/offset |
| GET | `/risk` | Bearer | evaluates all enabled rules, returns risk events |
| GET | `/reports/compliance` | Bearer | aggregates by day/type/user + risk feed |

Auth: PyJWT HS256; secret from `AUDITTRAIL_JWT_SECRET` env (dev default logs a
loud warning; no real secret is ever hardcoded).

## Setup / Usage

```bash
cd audittrail
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python scripts/serve.py --port 8300
python scripts/seed_demo.py               # 210 events incl. planted risk patterns
python scripts/smoke_test.py
python -m pytest tests -q

# dashboard (needs Node 18+)
cd frontend && npm install && npm run dev   # http://localhost:3001 (compose) / 3000 (dev)
```

## Sample output format

```
=== AUDITTRAIL SMOKE TEST ===
health: {'status': 'ok', 'events_stored': 0}
ingest: {'accepted': 6, 'duplicates_ignored': 0}
ingest replay: {'accepted': 0, 'duplicates_ignored': 6}
risk events: [('repeated_failed_login', 'mallory')]
unauthenticated /risk correctly rejected (401)
SMOKE OK
```

## Verification

`pytest`
(frontend build auto-skips when `npm` is not installed)

## Known limitations

- SQLite default; single-node. Postgres swap follows the same seam as 07_ledgerx
  (documented, not implemented).
- Rules evaluate the most recent 1000 events per query — a production system
  would stream/aggregate incrementally.
- Demo credentials ship in `configs/users.json`; they are explicitly demo-grade.
- The dashboard fetches from the browser; CORS/hosts need alignment when
  deployed behind different origins.
