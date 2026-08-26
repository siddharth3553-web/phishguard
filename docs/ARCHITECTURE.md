# Architecture

```
Browser ──► React (nginx :3000) ──/api──► FastAPI (:8000)
OpenAPI / curl ─────────────────────────► FastAPI
                                              │
                          ┌───────────────────┼───────────────────┐
                          ▼                   ▼                   ▼
                     Postgres            ONNX / skops         /metrics
                                                              Prometheus
                                                                  │
                                                              Grafana
FastAPI ──OTLP──► otel-collector (traces logged; wire Tempo for storage)
```

| Layer | Responsibility |
| --- | --- |
| `web/` | Vite React UI; nginx proxies `/api` to the API |
| `api/` | HTTP contracts, auth gate, persistence |
| `services/predictor.py` | ONNX URL + skops email inference |
| `core/` | Settings, structlog, metrics, middleware, OTEL |
| `db/` + Alembic | Scan resource store |

Models load once in lifespan. `/ready` requires models **and** DB connectivity.
