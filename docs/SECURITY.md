# Security

## Threat model

This is a local/demo inference API. It is not hardened for an open internet deployment without an edge proxy.

## Controls in this repo

- Pydantic validation on every write path (length limits, stripped empty strings).
- Request body size cap (`MAX_BODY_BYTES`, default 64 KiB).
- Per-IP sliding-window rate limit (`RATE_LIMIT_PER_MINUTE`).
- Optional `X-API-Key` when `API_KEY` is set.
- CORS allowlist (no `*` with credentials).
- `/docs` and OpenAPI disabled when `ENVIRONMENT=production`.
- Structured JSON logs in production, `X-Request-ID` on every response.
- Models loaded only from a configured directory; never from request bodies.

## Pickle / joblib

Trained `.pkl` files execute Python on load. Only load artifacts you produced with `make train` or the committed CI fixtures. Do not accept model uploads.

## What is out of scope

TLS termination, WAF, multi-tenant auth, and secret managers belong at the edge (nginx, Cloud Run, GKE ingress). This service stays small on purpose.
