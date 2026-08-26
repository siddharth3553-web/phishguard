# PhishGuard

**Employee report + analyst investigation desk** for suspicious URLs, email paste, and QR (quishing) — not another generic phishing score.

Industry incumbents (Proofpoint, Defender, Abnormal) own the inbox. The gap this service targets:

- Employees need a **report button** that returns *why* (lookalike domain, header mismatch, shortener, QR decode), not a 0–100 blob.
- **QR / quishing** hides URLs in images that SEGs never extract.
- False positives burn trust — analysts need **disposition + allowlist** so partners stop being re-flagged.

| Layer | Stack |
|------|--------|
| Packaging | **uv** + `uv.lock`, Python 3.12 |
| API | FastAPI · cookie sessions · Postgres + Alembic |
| Detection | ONNX URL + skops email **fused** with lookalike / header / redirect / QR / **BEC** intel |
| UI | React 19 · employee scan desk · analyst queue · ops strip |
| Ops | `/health` `/ready` `/metrics`, structlog, OTEL, Grafana |

## Demo users

| Role | Email | Password |
|------|-------|----------|
| Employee | `employee@demo.local` | `employee123` |
| Analyst | `analyst@demo.local` | `analyst123` |

## Quick start

```bash
uv sync --extra dev
make fixtures
make api                 # http://127.0.0.1:8000/docs

cd web && npm install && npm run dev   # http://127.0.0.1:5173
```

```bash
docker compose up --build
```

## Market parity (we match better — local)

| Incumbent | Their version | Ours |
| --- | --- | --- |
| Abnormal | BEC via months of Graph history | **BEC score** from pasted headers/body (display spoof, wire/gift-card, no-URL payload) |
| Proofpoint Safe Links | Rewrite every URL at the gateway | **Safe-Click tokens** `GET /c/{token}` — re-run intel at click time |
| Hoxhunt / Cortex | Campaign clustering of reports | **Campaign fingerprint** by domain / lookalike brand / QR / reason prefix |
| Adaptive / IRONSCALES | Analyst override | Disposition **scope**: scan / campaign / domain with **expiring allowlist** (default 30d) |
| Abnormal report button | “Thanks, moved to Deleted” | **Coaching card** + disposition visible on **My reports** (closed loop) |

## White space (incumbents hide from SMBs)

| Capability | Why it matters |
| --- | --- |
| **One evidence object** | Same `reasons[]`, BEC score, campaign id for employee *and* analyst |
| **Replayable decision log** | Model → rules → BEC → allowlist → click-time change, surfaced in UI |
| **Local-first** | Works when legal will not grant Microsoft Graph consent |

## What it does

1. Employee pastes URL / email headers+body / uploads QR.
2. Model score **plus** rule evidence (`reasons[]`, `bec_score`, Safe-Click URLs, decision log).
3. **Report to analyst** → coaching card; queue groups by campaign.
4. Analyst disposes (scan / campaign / domain); reporter sees status on My reports.
5. Analyst ops strip: open campaigns, median time-to-disposition, FP rate.

## Honest limits

- No Microsoft Graph / mailbox OAuth ingest.
- No org-wide MX rewrite or gateway Safe Links.
- No AiTM / session-token visibility (needs a browser extension).
- No CAPTCHA-gated sandbox detonation of landing pages.
- Redirect follow is HTTP-only (no JS), max 3 hops.
- Synthetic training data — hold-out AUC is a pipeline smoke test, not real-world detection.

## Docs

- [Architecture](docs/ARCHITECTURE.md)
- [Model card](docs/MODEL_CARD.md)
- [Security](docs/SECURITY.md)
- [Tradeoffs](docs/TRADEOFFS.md)

## License

MIT © Siddhartha Venkatesan
