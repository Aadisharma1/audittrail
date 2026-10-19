"use client";

import { useCallback, useEffect, useState } from "react";

const API_URL =
  (typeof process !== "undefined" && process.env.NEXT_PUBLIC_API_URL) ||
  "http://127.0.0.1:8300";

type AuditEvent = {
  event_id: string;
  ts: string;
  user_id: string | null;
  event_type: string;
  resource: string | null;
  severity: number;
  ip: string | null;
  details: Record<string, unknown>;
};
type RiskEvent = {
  rule: string;
  user_id: string | null;
  severity: number;
  detail: string;
};
type Report = {
  generated_at: string;
  total_events: number;
  events_per_day: Record<string, number>;
  events_per_type: Record<string, number>;
  failed_logins_per_user: Record<string, number>;
  top_users_by_activity: Record<string, number>;
  risk_events: RiskEvent[];
};

const DEMO_USER = { username: "auditor", password: "audit-demo-2025" };

export default function Page() {
  const [token, setToken] = useState("");
  const [authError, setAuthError] = useState("");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [risk, setRisk] = useState<RiskEvent[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [filterUser, setFilterUser] = useState("");
  const [filterType, setFilterType] = useState("");
  const [filterFrom, setFilterFrom] = useState("");
  const [filterTo, setFilterTo] = useState("");

  const login = useCallback(async () => {
    setAuthError("");
    try {
      const r = await fetch(`${API_URL}/auth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(DEMO_USER),
      });
      if (!r.ok) throw new Error(`login failed (${r.status})`);
      const body = await r.json();
      setToken(body.access_token);
    } catch (e) {
      setAuthError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    if (!token) void login();
  }, [token, login]);

  const load = useCallback(async () => {
    if (!token) return;
    const params = new URLSearchParams();
    if (filterUser) params.set("user_id", filterUser);
    if (filterType) params.set("event_type", filterType);
    if (filterFrom) params.set("ts_from", filterFrom);
    if (filterTo) {
      params.set("ts_to", filterTo.length === 10 ? `${filterTo}T23:59:59` : filterTo);
    }
    const [evRes, riskRes, repRes] = await Promise.all([
      fetch(`${API_URL}/events?${params.toString()}`),
      fetch(`${API_URL}/risk`, { headers: { Authorization: `Bearer ${token}` } }),
      fetch(`${API_URL}/reports/compliance`, { headers: { Authorization: `Bearer ${token}` } }),
    ]);
    if (evRes.ok) setEvents((await evRes.json()).events ?? []);
    if (riskRes.ok) setRisk((await riskRes.json()).risk_events ?? []);
    if (repRes.ok) setReport(await repRes.json());
  }, [token, filterUser, filterType, filterFrom, filterTo]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <main className="container">
      <h1>AuditTrail Dashboard</h1>
      <div className="subtitle">
        centralized audit events, risk detection, compliance reports
      </div>

      <div className="panel">
        <div className="token-row">
          <input
            value={token ? "token loaded (auditor demo account)" : "no token"}
            readOnly
          />
          <button onClick={() => void login()}>Re-login</button>
          <button onClick={() => void load()}>Refresh</button>
        </div>
        {authError && <div className="error">auth error: {authError}</div>}
        {!token && !authError && <div className="muted">obtaining token…</div>}
      </div>

      <div className="panel">
        <h2>Risk events ({risk.length})</h2>
        {risk.length === 0 && <div className="muted">no risk events detected</div>}
        {risk.map((r, i) => (
          <div key={i} className="risk-item">
            <strong>{r.rule}</strong> — {r.detail}
            <div className="meta">
              user: {r.user_id ?? "—"} · severity <span className={`sev sev${r.severity}`}>{r.severity}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="panel">
        <h2>Recent events</h2>
        <div className="controls">
          <input placeholder="user id" value={filterUser}
                 onChange={(e) => setFilterUser(e.target.value)} />
          <select value={filterType} onChange={(e) => setFilterType(e.target.value)}>
            <option value="">any type</option>
            {["auth_success", "auth_failed", "state_change", "request",
              "privilege_grant", "role_escalation", "account_disabled", "password_reset"]
              .map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input type="date" value={filterFrom} onChange={(e) => setFilterFrom(e.target.value)} />
          <input type="date" value={filterTo} onChange={(e) => setFilterTo(e.target.value)} />
          <button onClick={() => void load()}>Apply filters</button>
        </div>
        <table>
          <thead>
            <tr>
              <th>time</th><th>user</th><th>type</th><th>resource</th>
              <th>severity</th><th>ip</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.event_id}>
                <td>{e.ts.replace("T", " ").slice(0, 19)}</td>
                <td>{e.user_id ?? "—"}</td>
                <td>{e.event_type}</td>
                <td>{e.resource ?? "—"}</td>
                <td><span className={`sev sev${e.severity}`}>{e.severity}</span></td>
                <td>{e.ip ?? "—"}</td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr><td colSpan={6} className="muted">no events match the filters</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="grid">
        <div className="panel">
          <h2>Per-user activity</h2>
          <table>
            <thead><tr><th>user</th><th>events</th><th>failed logins</th></tr></thead>
            <tbody>
              {Object.keys({ ...report?.top_users_by_activity, ...report?.failed_logins_per_user })
                .map((u) => (
                  <tr key={u}>
                    <td>{u}</td>
                    <td>{report?.top_users_by_activity[u] ?? 0}</td>
                    <td>{report?.failed_logins_per_user[u] ?? 0}</td>
                  </tr>
                ))}
              {!report && (
                <tr><td colSpan={3} className="muted">report not loaded</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <h2>Compliance report</h2>
          {report ? (
            <>
              <div className="muted">generated {report.generated_at} · {report.total_events} events</div>
              <h2 style={{ marginTop: 12 }}>by type</h2>
              <table>
                <tbody>
                  {Object.entries(report.events_per_type).map(([t, n]) => (
                    <tr key={t}><td>{t}</td><td>{n}</td></tr>
                  ))}
                </tbody>
              </table>
              <h2 style={{ marginTop: 12 }}>by day</h2>
              <table>
                <tbody>
                  {Object.entries(report.events_per_day).map(([d, n]) => (
                    <tr key={d}><td>{d}</td><td>{n}</td></tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : (
            <div className="muted">report not loaded</div>
          )}
        </div>
      </div>
    </main>
  );
}
