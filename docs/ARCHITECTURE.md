# Architecture

```
Browser ──► Streamlit UI (:8501) ──HTTP──► FastAPI (:8000)
OpenAPI / curl ──────────────────────────► FastAPI
                                              │
                          ┌───────────────────┼───────────────────┐
                          │                   │                   │
                     Predictor          SQLite scans         /metrics
                     (sklearn,              file           Prometheus
                      loaded once)
```

## Boundaries

| Layer | Responsibility |
| --- | --- |
| `api/` | HTTP contracts, auth gate, persistence |
| `services/predictor.py` | Inference only — no FastAPI imports |
| `core/` | Settings, logs, metrics, middleware |
| `db/` | Scan resource store (SQLite) |
| Streamlit | Demo UI. Talks HTTP only. |

Models are loaded in the FastAPI lifespan. `/ready` is 503 until they load. CPU inference uses sync `def` handlers so FastAPI offloads to a thread pool.

## Process model

Local: `uvicorn` one worker. Compose: API + UI + Prometheus. No Kubernetes — a two-model sklearn service does not need a cluster.
