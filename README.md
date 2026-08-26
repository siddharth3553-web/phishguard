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
| Detection | ONNX URL + skops email **fused** with lookalike / header / redirect / QR intel |
| UI | React 19 · employee scan desk · analyst queue |
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

## What it does

1. Employee pastes URL / email headers+body / uploads QR.
2. Model score **plus** rule evidence (`reasons[]`: `lookalike_of:…`, `qr_decoded`, `from_return_path_mismatch`, …).
3. **Report to analyst** → queue for Uncertain / Phishing / reported cases.
4. Analyst disposes: confirm phish, false positive, or allowlist domain/email.

## Honest limits

- No AiTM / session-token visibility (needs a browser extension).
- No CAPTCHA-gated sandbox detonation of landing pages.
- No live Microsoft 365 mailbox ingest in v1.
- Redirect follow is HTTP-only (no JS), max 3 hops.
- Synthetic training data — hold-out AUC is a pipeline smoke test, not real-world detection.

## Docs

- [Architecture](docs/ARCHITECTURE.md)
- [Model card](docs/MODEL_CARD.md)
- [Security](docs/SECURITY.md)
- [Tradeoffs](docs/TRADEOFFS.md)

## License

MIT © Siddhartha Venkatesan
