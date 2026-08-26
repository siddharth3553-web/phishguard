import { useMemo, useState, type CSSProperties, type FormEvent } from "react";
import "./App.css";

type ScanResult = {
  id: string;
  kind: string;
  verdict: string;
  confidence: number;
  phishing_score: number;
  low_confidence?: boolean;
  note?: string | null;
  flagged_keywords?: string[] | null;
};

const URL_SAMPLE = "https://www.wikipedia.org/wiki/Python";
const EMAIL_SAMPLE =
  "Urgent: verify your payroll account within 2 hours or access will be locked. Click http://secure-payrol1-update.example/login";

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return res.json() as Promise<T>;
}

function verdictTone(verdict: string): string {
  const v = verdict.toLowerCase();
  if (v.includes("phish") || v.includes("malicious") || v.includes("unsafe")) {
    return "var(--risk)";
  }
  if (v.includes("safe") || v.includes("benign") || v.includes("legit")) {
    return "var(--safe)";
  }
  if (v.includes("uncertain") || v.includes("suspicious")) {
    return "var(--warn)";
  }
  return "var(--uncertain)";
}

function App() {
  const [tab, setTab] = useState<"url" | "email">("url");
  const [url, setUrl] = useState(URL_SAMPLE);
  const [email, setEmail] = useState(
    "Meeting notes attached. Thanks for reviewing before Friday.",
  );
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const scoreStyle = useMemo(() => {
    if (!result) return undefined;
    return {
      ["--p" as string]: String(Math.max(0, Math.min(100, result.phishing_score))),
      ["--c" as string]: verdictTone(result.verdict),
    } as CSSProperties;
  }, [result]);

  async function runScan(e?: FormEvent) {
    e?.preventDefault();
    setLoading(true);
    setError(null);
    try {
      if (tab === "url") {
        setResult(await postJson<ScanResult>("/api/v1/urls/scans", { url }));
      } else {
        setResult(await postJson<ScanResult>("/api/v1/emails/scans", { text: email }));
      }
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  function loadSample() {
    setError(null);
    setResult(null);
    if (tab === "url") setUrl(URL_SAMPLE);
    else setEmail(EMAIL_SAMPLE);
  }

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
          <a className="top-link" href="/docs" target="_blank" rel="noreferrer">
            API docs
          </a>
        </header>

        <section className="hero">
          <p className="hero-brand">PhishGuard</p>
          <h2>Know before you click.</h2>
          <p>
            Instant phishing triage for suspicious links and email copy — clear
            verdict, score, and confidence in one pass.
          </p>
        </section>

        <div className="workspace">
          <form className="panel" onSubmit={runScan}>
            <div className="mode-row" role="tablist" aria-label="Scan type">
              <button
                type="button"
                role="tab"
                aria-selected={tab === "url"}
                className={tab === "url" ? "active" : ""}
                onClick={() => {
                  setTab("url");
                  setResult(null);
                  setError(null);
                }}
              >
                Scan URL
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={tab === "email"}
                className={tab === "email" ? "active" : ""}
                onClick={() => {
                  setTab("email");
                  setResult(null);
                  setError(null);
                }}
              >
                Scan email
              </button>
            </div>

            {tab === "url" ? (
              <div className="field">
                <label htmlFor="url">Paste a URL</label>
                <input
                  id="url"
                  name="url"
                  inputMode="url"
                  autoComplete="url"
                  placeholder="https://…"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  required
                />
              </div>
            ) : (
              <div className="field">
                <label htmlFor="email">Paste email body</label>
                <textarea
                  id="email"
                  name="email"
                  placeholder="Subject + body text…"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
            )}

            <div className="actions">
              <button className="btn-primary" type="submit" disabled={loading}>
                {loading ? (
                  <>
                    <span className="pulse" aria-hidden />
                    Analyzing…
                  </>
                ) : tab === "url" ? (
                  "Run URL scan"
                ) : (
                  "Run email scan"
                )}
              </button>
              <button className="btn-ghost" type="button" onClick={loadSample}>
                Load sample
              </button>
            </div>
            <p className="hint">Models stay on your machine. Results are advisory.</p>
          </form>

          <aside className="panel result-panel" aria-live="polite">
            {!result && !error && (
              <div className="result-empty">
                <strong>Waiting for a scan</strong>
                <span>Verdict and risk score will appear here.</span>
              </div>
            )}

            {error && <pre className="error">{error}</pre>}

            {result && (
              <div className="result-live">
                <div className="verdict-row">
                  <div className="score-ring" style={scoreStyle}>
                    <span>{Math.round(result.phishing_score)}%</span>
                  </div>
                  <div className="verdict-copy">
                    <h3 style={{ color: verdictTone(result.verdict) }}>{result.verdict}</h3>
                    <p>
                      {result.kind.toUpperCase()} risk score ·{" "}
                      {Math.round(result.confidence)}% model confidence
                    </p>
                  </div>
                </div>

                <div className="meta-grid">
                  <div className="meta">
                    <small>Confidence</small>
                    <strong>{Math.round(result.confidence)}%</strong>
                  </div>
                  <div className="meta">
                    <small>Scan ID</small>
                    <strong title={result.id}>{result.id.slice(0, 8)}…</strong>
                  </div>
                </div>

                {result.note && <p className="note">{result.note}</p>}

                {result.flagged_keywords && result.flagged_keywords.length > 0 && (
                  <div className="tags" aria-label="Flagged keywords">
                    {result.flagged_keywords.map((k) => (
                      <span className="tag" key={k}>
                        {k}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
          </aside>
        </div>

        <p className="footer-note">
          PhishGuard · ONNX URL forest + skops email pipeline · FastAPI
        </p>
      </div>
    </div>
  );
}

export default App;
