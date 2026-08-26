import { useCallback, useEffect, useMemo, useState, type CSSProperties, type FormEvent } from "react";
import "./App.css";

type User = { id: string; email: string; display_name: string; role: string };

type ScanResult = {
  id: string;
  kind: string;
  verdict: string;
  confidence: number;
  phishing_score: number;
  low_confidence?: boolean;
  note?: string | null;
  flagged_keywords?: string[] | null;
  reasons?: string[] | null;
  extracted_urls?: string[] | null;
  status?: string;
  reported?: boolean;
  qr_payload?: string | null;
  disposition_note?: string | null;
};

type AllowEntry = { id: string; value: string; kind: string; note?: string | null };

const URL_SAMPLE = "https://www.wikipedia.org/wiki/Python";
const EMAIL_SAMPLE =
  "From: PayPal Security <alerts@paypa1-secure.xyz>\nReturn-Path: <bounce@evil.tk>\n\nUrgent: verify your account within 2 hours or access will be locked.\nClick http://secure-payrol1-update.example/login";
const LOOKALIKE_SAMPLE = "https://paypa1.com/signin";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

function verdictTone(verdict: string): string {
  const v = verdict.toLowerCase();
  if (v.includes("phish")) return "var(--risk)";
  if (v.includes("safe")) return "var(--safe)";
  if (v.includes("uncertain") || v.includes("suspicious")) return "var(--warn)";
  return "var(--uncertain)";
}

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [boot, setBoot] = useState(true);
  const [email, setEmail] = useState("employee@demo.local");
  const [password, setPassword] = useState("employee123");
  const [authError, setAuthError] = useState<string | null>(null);

  const [view, setView] = useState<"scan" | "history" | "queue" | "allowlist">("scan");
  const [tab, setTab] = useState<"url" | "email" | "qr">("url");
  const [url, setUrl] = useState(URL_SAMPLE);
  const [emailBody, setEmailBody] = useState(
    "Meeting notes attached. Thanks for reviewing before Friday.",
  );
  const [qrFile, setQrFile] = useState<File | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [queue, setQueue] = useState<ScanResult[]>([]);
  const [allowlist, setAllowlist] = useState<AllowEntry[]>([]);
  const [allowValue, setAllowValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<ScanResult | null>(null);
  const [dispNote, setDispNote] = useState("");

  const refreshMe = useCallback(async () => {
    try {
      const me = await api<User>("/api/v1/auth/me");
      setUser(me);
      setView(me.role === "analyst" ? "queue" : "scan");
    } catch {
      setUser(null);
    } finally {
      setBoot(false);
    }
  }, []);

  useEffect(() => {
    refreshMe();
  }, [refreshMe]);

  const scoreStyle = useMemo(() => {
    if (!result) return undefined;
    return {
      ["--p" as string]: String(Math.max(0, Math.min(100, result.phishing_score))),
      ["--c" as string]: verdictTone(result.verdict),
    } as CSSProperties;
  }, [result]);

  async function login(e: FormEvent) {
    e.preventDefault();
    setAuthError(null);
    try {
      const me = await api<User>("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      setUser(me);
      setView(me.role === "analyst" ? "queue" : "scan");
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : "Login failed");
    }
  }

  async function logout() {
    await api("/api/v1/auth/logout", { method: "POST" }).catch(() => undefined);
    setUser(null);
    setResult(null);
  }

  async function runScan(e?: FormEvent) {
    e?.preventDefault();
    setLoading(true);
    setError(null);
    try {
      if (tab === "qr") {
        if (!qrFile) throw new Error("Choose a QR image first");
        const fd = new FormData();
        fd.append("file", qrFile);
        const res = await fetch("/api/v1/scans/qr", { method: "POST", body: fd, credentials: "include" });
        if (!res.ok) throw new Error(await res.text());
        setResult(await res.json());
      } else if (tab === "url") {
        setResult(await api<ScanResult>("/api/v1/urls/scans", { method: "POST", body: JSON.stringify({ url }) }));
      } else {
        setResult(
          await api<ScanResult>("/api/v1/emails/scans", {
            method: "POST",
            body: JSON.stringify({ text: emailBody }),
          }),
        );
      }
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  async function loadHistory() {
    try {
      const data = await api<{ scans: ScanResult[] }>("/api/v1/me/scans");
      setHistory(data.scans);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load history");
    }
  }

  async function loadQueue() {
    try {
      const data = await api<{ scans: ScanResult[] }>("/api/v1/analyst/queue");
      setQueue(data.scans);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load queue");
    }
  }

  async function loadAllowlist() {
    try {
      const data = await api<{ entries: AllowEntry[] }>("/api/v1/allowlist");
      setAllowlist(data.entries);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load allowlist");
    }
  }

  useEffect(() => {
    if (!user) return;
    if (view === "history") loadHistory();
    if (view === "queue") loadQueue();
    if (view === "allowlist") loadAllowlist();
  }, [view, user]);

  async function reportCurrent() {
    if (!result) return;
    try {
      const updated = await api<ScanResult>(`/api/v1/scans/${result.id}/report`, { method: "POST" });
      setResult(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Report failed");
    }
  }

  async function dispose(status: string) {
    const target = selected || result;
    if (!target) return;
    try {
      const updated = await api<ScanResult>(`/api/v1/scans/${target.id}/disposition`, {
        method: "POST",
        body: JSON.stringify({
          status,
          note: dispNote || null,
          allowlist_value: status === "allowlisted" ? allowValue || undefined : undefined,
        }),
      });
      setSelected(updated);
      setResult(updated);
      await loadQueue();
      if (status === "allowlisted") await loadAllowlist();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Disposition failed");
    }
  }

  async function addAllow() {
    try {
      await api("/api/v1/allowlist", {
        method: "POST",
        body: JSON.stringify({
          value: allowValue,
          kind: allowValue.includes("@") ? "email" : "domain",
        }),
      });
      setAllowValue("");
      await loadAllowlist();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Allowlist add failed");
    }
  }

  if (boot) {
    return (
      <div className="shell">
        <div className="atmosphere" aria-hidden />
        <div className="frame">
          <p className="hint">Loading…</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="shell">
        <div className="atmosphere" aria-hidden>
          <div className="mesh" />
        </div>
        <div className="frame login-frame">
          <section className="hero">
            <p className="hero-brand">PhishGuard</p>
            <h2>Report &amp; investigate.</h2>
            <p>
              Employees get an explainable verdict. Analysts get a queue — not another opaque score.
            </p>
          </section>
          <form className="panel login-panel" onSubmit={login}>
            <h3>Sign in</h3>
            <div className="field">
              <label htmlFor="email">Email</label>
              <input id="email" value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            {authError && <pre className="error">{authError}</pre>}
            <div className="actions">
              <button className="btn-primary" type="submit">
                Continue
              </button>
              <button
                className="btn-ghost"
                type="button"
                onClick={() => {
                  setEmail("analyst@demo.local");
                  setPassword("analyst123");
                }}
              >
                Use analyst demo
              </button>
            </div>
            <p className="hint">Demo: employee@demo.local / employee123</p>
          </form>
        </div>
      </div>
    );
  }

  const isAnalyst = user.role === "analyst";

  return (
    <div className={`shell${loading ? " scanning" : ""}`}>
      <div className="atmosphere" aria-hidden>
        <div className="mesh" />
      </div>
      <div className="frame">
        <header className="topbar">
          <a className="brand-mark" href="/">
            <span className="brand-glyph" aria-hidden>
              PG
            </span>
            <span>PhishGuard</span>
          </a>
          <div className="top-actions">
            <span className="user-chip">
              {user.display_name} · {user.role}
            </span>
            <button className="top-link" type="button" onClick={logout}>
              Sign out
            </button>
          </div>
        </header>

        <nav className="nav-tabs" aria-label="Workspace">
          {!isAnalyst && (
            <>
              <button className={view === "scan" ? "active" : ""} type="button" onClick={() => setView("scan")}>
                Scan
              </button>
              <button
                className={view === "history" ? "active" : ""}
                type="button"
                onClick={() => setView("history")}
              >
                My reports
              </button>
            </>
          )}
          {isAnalyst && (
            <>
              <button className={view === "queue" ? "active" : ""} type="button" onClick={() => setView("queue")}>
                Analyst queue
              </button>
              <button className={view === "scan" ? "active" : ""} type="button" onClick={() => setView("scan")}>
                Scan desk
              </button>
              <button
                className={view === "allowlist" ? "active" : ""}
                type="button"
                onClick={() => setView("allowlist")}
              >
                Allowlist
              </button>
            </>
          )}
        </nav>

        {error && <pre className="error">{error}</pre>}

        {view === "scan" && (
          <>
            <section className="hero compact">
              <h2>Know before you click.</h2>
              <p>URL, email, or QR — fused model + lookalike / header / redirect evidence.</p>
            </section>
            <div className="workspace">
              <form className="panel" onSubmit={runScan}>
                <div className="mode-row three" role="tablist">
                  {(["url", "email", "qr"] as const).map((t) => (
                    <button
                      key={t}
                      type="button"
                      className={tab === t ? "active" : ""}
                      onClick={() => {
                        setTab(t);
                        setResult(null);
                      }}
                    >
                      {t === "url" ? "URL" : t === "email" ? "Email" : "QR"}
                    </button>
                  ))}
                </div>
                {tab === "url" && (
                  <div className="field">
                    <label htmlFor="url">Paste a URL</label>
                    <input id="url" value={url} onChange={(e) => setUrl(e.target.value)} required />
                  </div>
                )}
                {tab === "email" && (
                  <div className="field">
                    <label htmlFor="em">Paste email (headers + body)</label>
                    <textarea id="em" value={emailBody} onChange={(e) => setEmailBody(e.target.value)} required />
                  </div>
                )}
                {tab === "qr" && (
                  <div className="field">
                    <label htmlFor="qr">Upload QR image</label>
                    <input
                      id="qr"
                      type="file"
                      accept="image/*"
                      onChange={(e) => setQrFile(e.target.files?.[0] || null)}
                    />
                  </div>
                )}
                <div className="actions">
                  <button className="btn-primary" type="submit" disabled={loading}>
                    {loading ? "Analyzing…" : "Run scan"}
                  </button>
                  <button
                    className="btn-ghost"
                    type="button"
                    onClick={() => {
                      if (tab === "url") setUrl(LOOKALIKE_SAMPLE);
                      else if (tab === "email") setEmailBody(EMAIL_SAMPLE);
                    }}
                  >
                    Load risky sample
                  </button>
                </div>
              </form>

              <aside className="panel result-panel" aria-live="polite">
                {!result ? (
                  <div className="result-empty">
                    <strong>Evidence appears here</strong>
                    <span>Verdict, reasons, and extracted links.</span>
                  </div>
                ) : (
                  <div className="result-live">
                    <div className="verdict-row">
                      <div className="score-ring" style={scoreStyle}>
                        <span>{Math.round(result.phishing_score)}%</span>
                      </div>
                      <div className="verdict-copy">
                        <h3 style={{ color: verdictTone(result.verdict) }}>{result.verdict}</h3>
                        <p>
                          {result.kind.toUpperCase()} · {Math.round(result.confidence)}% confidence ·{" "}
                          {result.status}
                          {result.reported ? " · reported" : ""}
                        </p>
                      </div>
                    </div>
                    {result.reasons && result.reasons.length > 0 && (
                      <div className="tags" aria-label="Reasons">
                        {result.reasons.map((r) => (
                          <span className="tag" key={r}>
                            {r}
                          </span>
                        ))}
                      </div>
                    )}
                    {result.extracted_urls && result.extracted_urls.length > 0 && (
                      <div className="meta">
                        <small>Extracted URLs</small>
                        <strong className="wrap">{result.extracted_urls.join(" · ")}</strong>
                      </div>
                    )}
                    {result.qr_payload && (
                      <div className="meta">
                        <small>QR payload</small>
                        <strong className="wrap">{result.qr_payload}</strong>
                      </div>
                    )}
                    {result.note && <p className="note">{result.note}</p>}
                    <div className="actions">
                      <button className="btn-primary" type="button" onClick={reportCurrent}>
                        Report to analyst
                      </button>
                    </div>
                  </div>
                )}
              </aside>
            </div>
          </>
        )}

        {view === "history" && (
          <section className="panel">
            <h3>My scans</h3>
            <ul className="case-list">
              {history.map((s) => (
                <li key={s.id}>
                  <button type="button" onClick={() => setResult(s)}>
                    <strong style={{ color: verdictTone(s.verdict) }}>{s.verdict}</strong>
                    <span>
                      {s.kind} · {Math.round(s.phishing_score)}% · {s.status}
                    </span>
                  </button>
                </li>
              ))}
              {history.length === 0 && <p className="hint">No scans yet.</p>}
            </ul>
          </section>
        )}

        {view === "queue" && (
          <div className="workspace">
            <section className="panel">
              <h3>Open cases</h3>
              <ul className="case-list">
                {queue.map((s) => (
                  <li key={s.id}>
                    <button type="button" onClick={() => setSelected(s)}>
                      <strong style={{ color: verdictTone(s.verdict) }}>{s.verdict}</strong>
                      <span>
                        {s.kind} · {s.reported ? "reported · " : ""}
                        {s.id.slice(0, 8)}
                      </span>
                    </button>
                  </li>
                ))}
                {queue.length === 0 && <p className="hint">Queue is clear.</p>}
              </ul>
            </section>
            <aside className="panel">
              {!selected ? (
                <div className="result-empty">
                  <strong>Select a case</strong>
                  <span>Dispose as phish, false positive, or allowlist.</span>
                </div>
              ) : (
                <div className="result-live">
                  <h3 style={{ color: verdictTone(selected.verdict) }}>{selected.verdict}</h3>
                  <p className="hint">
                    Score {Math.round(selected.phishing_score)}% · {selected.kind}
                  </p>
                  <div className="tags">
                    {(selected.reasons || []).map((r) => (
                      <span className="tag" key={r}>
                        {r}
                      </span>
                    ))}
                  </div>
                  <div className="field">
                    <label htmlFor="note">Disposition note</label>
                    <textarea id="note" rows={3} value={dispNote} onChange={(e) => setDispNote(e.target.value)} />
                  </div>
                  <div className="field">
                    <label htmlFor="al">Allowlist value (if allowlisting)</label>
                    <input id="al" value={allowValue} onChange={(e) => setAllowValue(e.target.value)} />
                  </div>
                  <div className="actions">
                    <button className="btn-primary" type="button" onClick={() => dispose("confirmed_phish")}>
                      Confirm phish
                    </button>
                    <button className="btn-ghost" type="button" onClick={() => dispose("false_positive")}>
                      False positive
                    </button>
                    <button className="btn-ghost" type="button" onClick={() => dispose("allowlisted")}>
                      Allowlist
                    </button>
                  </div>
                </div>
              )}
            </aside>
          </div>
        )}

        {view === "allowlist" && (
          <section className="panel">
            <h3>Org allowlist</h3>
            <div className="actions">
              <input
                placeholder="partner.com or user@partner.com"
                value={allowValue}
                onChange={(e) => setAllowValue(e.target.value)}
              />
              <button className="btn-primary" type="button" onClick={addAllow}>
                Add
              </button>
            </div>
            <ul className="case-list">
              {allowlist.map((a) => (
                <li key={a.id}>
                  <strong>{a.value}</strong>
                  <span>{a.kind}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        <p className="footer-note">
          PhishGuard · employee report + analyst desk · ONNX/skops + lookalike/QR fusion
        </p>
      </div>
    </div>
  );
}

export default App;
