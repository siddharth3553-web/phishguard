# PhishGuard

Production-style **ML inference API** (FastAPI) with a **React** UI, **Postgres**, **Prometheus/Grafana**, and **OpenTelemetry**.

| Layer | Stack |
|------|--------|
| Packaging | **uv** + `uv.lock`, Python 3.12 |
| API | FastAPI · Pydantic v2 · Uvicorn |
| Models | URL → **ONNX Runtime**; email → **skops** |
| DB | **Postgres 16** (+ Alembic); SQLite in tests |
| UI | **React 19 + Vite + TypeScript** (nginx) |
| Ops | `/health` `/ready` `/metrics`, structlog, OTEL |

## Quick start

```bash
# API (needs fixture or trained models)
uv sync --extra dev
make fixtures          # CI-sized ONNX + skops artifacts
make api               # http://127.0.0.1:8000/docs

# UI (proxies to API)
cd web && npm install && npm run dev   # http://127.0.0.1:5173
```

Full stack:

```bash
docker compose up --build
```

- UI: http://localhost:3000  
- API: http://localhost:8000/docs  
- Grafana: http://localhost:3001 (admin/admin)  
- Prometheus: http://localhost:9090  

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness |
| GET | `/ready` | Models + DB |
| GET | `/metrics` | Prometheus |
| POST | `/api/v1/urls/scans` | URL scan |
| POST | `/api/v1/emails/scans` | Email scan |
| POST | `/api/v1/scans:batch` | Batch |
| GET | `/api/v1/scans/{id}` | Persisted scan |

## Docs

- [Architecture](docs/ARCHITECTURE.md)
- [Model card](docs/MODEL_CARD.md)
- [Security](docs/SECURITY.md)
- [Tradeoffs](docs/TRADEOFFS.md)

Training data is **synthetic**. Hold-out AUC ≈ 1.0 is a pipeline smoke test, not real-world detection performance.

## License

MIT © Siddhartha Venkatesan
