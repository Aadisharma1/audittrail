# 09 — Risk Rules: Semantics, Configuration, Tuning

The four built-in risk rules, their exact window math, how to configure and
tune them, and how to add new ones. All rules live in `src/audittrail/rules.py`
and are pure functions of `(events, config)` — deterministic, unit-testable,
no hidden state.

## Window anchoring (read this first)

All time windows are anchored to the **newest event's timestamp in the queried
set**, not to the wall clock. `GET /risk` therefore returns identical results
for identical stored data regardless of *when* you call it — which is what
makes the rules unit-testable with frozen timestamps and what makes the
report deterministic. The trade-off: on a quiet system, "last 15 minutes"
means "the 15 minutes up to the most recent event", which can be much older
than 15 minutes ago. A production deployment that wants wall-clock semantics
passes a `now` parameter through; the function signature is already shaped for
it.

## The rules

### 1. `repeated_failed_login`

```json
{"enabled": true, "max_failures": 5, "window_minutes": 15, "severity": 3}
```

Counts `auth_failed` events per user within the window; fires once per user at
or above `max_failures`, with the observed count in the detail. This is the
classic credential-stuffing / brute-force signal. The threshold test asserts
the boundary precisely: 4 failures against a threshold of 3 fires; 2 failures
stay silent.

### 2. `impossible_frequency`

```json
{"enabled": true, "max_events_per_minute": 30, "window_minutes": 1, "severity": 2}
```

Counts *all* events per user inside the window and fires when the rate
exceeds `max_events_per_minute` scaled to the window length. Intended for
automation/bot bursts that never produce auth failures. Fires at most once per
user per evaluation.

### 3. `suspicious_state_transition`

```json
{"enabled": true,
 "transitions": [["account_disabled", "privilege_grant"],
                 ["auth_failed", "password_reset"]],
 "window_minutes": 30, "severity": 4}
```

For each user, orders their events in the window by timestamp and fires if any
*consecutive pair* matches a configured `(from_type, to_type)` transition —
e.g. a failed login immediately followed by a password reset is the standard
account-takeover shape. Only consecutive pairs are checked (not all pairs),
which keeps the rule explainable: the report shows the exact transition that
fired. One risk event per user per evaluation (the first matching pair), even
if several pairs match.

### 4. `unusual_request_volume`

```json
{"enabled": true, "max_events_per_hour": 500, "severity": 2}
```

A global (not per-user) volume gate over the last hour of the queried set.
Fires at most once per evaluation with the observed count and threshold in the
detail. Think of it as a system-level canary rather than an attribution rule.

## Evaluation contract

- **Output**: a list of risk events sorted by descending severity, each shaped
  `{"rule", "user_id" (or null), "severity", "detail"}`. `/risk` returns it
  verbatim; `/reports/compliance` embeds it.
- **Disabled rules** (`"enabled": false`) contribute nothing and are skipped
  cheaply.
- **Determinism**: same events + same config → byte-identical output, tested
  explicitly. No wall clock, no RNG.
- **Auth**: `/risk` requires a bearer token; the rules themselves are pure and
  are exercised directly by `tests/test_events_rules.py` without HTTP.

## Query scope and honest limits

- Rules evaluate the most recent **1000 events** (the API's max page). A
  production system would evaluate incrementally at ingest time and persist
  risk events; that machinery is deliberately not faked here.
- Windows are computed per rule; a rule change is a config edit plus a
  service restart (no hot reload — stated, not hidden).
- Severity values are ints 0–4, enforced at ingest time by the event schema;
  rule severities come straight from the config.

## Adding a rule

1. Write a pure function `(events, cfg) -> list[risk_event]` in `rules.py`.
2. Add its config block to `configs/rules.json` (with `"enabled"`).
3. Call it from `evaluate_rules` and append its output.
4. Add tests: boundary (fires / stays silent at the threshold), determinism,
   and the disabled case.

The pattern to copy is `repeated_failed_login` — the smallest complete
example.
