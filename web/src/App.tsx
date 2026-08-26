import { useState } from "react";
import "./App.css";

type ScanResult = {
  id: string;
  kind: string;
  verdict: string;
  confidence: number;
  phishing_score: number;
  note?: string | null;
  flagged_keywords?: string[] | null;
};

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

function App() {
  const [tab, setTab] = useState<"url" | "email">("url");
  const [url, setUrl] = useState("https://www.wikipedia.org/wiki/Python");
  const [email, setEmail] = useState(
    "Meeting notes attached. Thanks for reviewing before Friday.",
  );
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function scanUrl() {
    setLoading(true);
    setError(null);
    try {
      setResult(await postJson<ScanResult>("/api/v1/urls/scans", { url }));
    } catch (e) {
      setResult(null);
      setError(e instanceof Error ? e.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  async function scanEmail() {
    setLoading(true);
    setError(null);
    try {
      setResult(await postJson<ScanResult>("/api/v1/emails/scans", { text: email }));
    } catch (e) {
      setResult(null);
      setError(e instanceof Error ? e.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <header>
        <h1>PhishGuard</h1>
        <p>URL and email phishing detection — FastAPI + ONNX/skops</p>
        <a href="/docs" target="_blank" rel="noreferrer">
          OpenAPI docs
        </a>
      </header>

      <div className="tabs">
        <button className={tab === "url" ? "active" : ""} onClick={() => setTab("url")}>
          URL
        </button>
        <button className={tab === "email" ? "active" : ""} onClick={() => setTab("email")}>
          Email
        </button>
      </div>

      {tab === "url" ? (
        <section className="card">
          <label htmlFor="url">URL</label>
          <input id="url" value={url} onChange={(e) => setUrl(e.target.value)} />
          <button disabled={loading} onClick={scanUrl}>
            {loading ? "Scanning…" : "Scan URL"}
          </button>
        </section>
      ) : (
        <section className="card">
          <label htmlFor="email">Email body</label>
          <textarea id="email" rows={6} value={email} onChange={(e) => setEmail(e.target.value)} />
          <button disabled={loading} onClick={scanEmail}>
            {loading ? "Scanning…" : "Scan email"}
          </button>
        </section>
      )}

      {error && <pre className="error">{error}</pre>}

      {result && (
        <section className="card result">
          <h2>{result.verdict}</h2>
          <p>Score: {result.phishing_score}% · Confidence: {result.confidence}%</p>
          <p className="muted">Scan ID: {result.id}</p>
          {result.note && <p>{result.note}</p>}
          {result.flagged_keywords && result.flagged_keywords.length > 0 && (
            <p>Keywords: {result.flagged_keywords.join(", ")}</p>
          )}
        </section>
      )}
    </div>
  );
}

export default App;
