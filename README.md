# PhishGuard

Production-style **ML inference API** for URL and email phishing detection. FastAPI is the product; Streamlit is an HTTP client. Models are sklearn, trained offline on **synthetic** data.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make data && make train          # real demo models
make api                         # http://127.0.0.1:8000/docs
# other terminal:
make run                         # Streamlit UI → API
```

One command for the full stack:

```bash
docker compose up --build
```

- API: http://localhost:8000/docs  
- UI: http://localhost:8501  
- Prometheus: http://localhost:9090  

## What a reviewer should look at

| Path | Why |
|------|-----|
| `src/phishguard/api/` | Versioned HTTP contracts, lifespan model load |
| `docs/ARCHITECTURE.md` | Service boundaries |
| `docs/MODEL_CARD.md` | Synthetic-data limits (AUC ≈ 1.0 is **not** real-world) |
| `docs/TRADEOFFS.md` | Why no k8s / Postgres / Redis |
| `tests/test_api.py` | Contract tests on fixture models (CI always runs) |
| `.github/workflows/ci.yml` | Lint, tests, Docker build, Trivy, Gitleaks |

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness |
| GET | `/ready` | Models loaded |
| GET | `/metrics` | Prometheus |
| GET | `/version` | App + model version + git SHA |
| POST | `/api/v1/urls/scans` | Scan a URL (201 + id) |
| POST | `/api/v1/emails/scans` | Scan email text |
| POST | `/api/v1/scans:batch` | Up to 50 items |
| GET | `/api/v1/scans/{id}` | Persisted scan |

Set `API_KEY` to require `X-API-Key`. `ENVIRONMENT=production` disables `/docs`.

## Latency (local smoke)

Measured 2026-08-26 on a laptop via FastAPI `TestClient` (fixture models, in-process): URL scan p50 typically **under 50 ms**. Use `load/k6/smoke.js` against a running server for wall-clock numbers:

```bash
k6 run -e BASE_URL=http://localhost:8000 load/k6/smoke.js
```

## Stack

Python 3.10+ · FastAPI · Pydantic v2 · SQLAlchemy · scikit-learn · Prometheus · Docker Compose · Streamlit (UI)

## License

MIT © Siddhartha Venkatesan
