# Tradeoffs

## FastAPI as the product, Streamlit as a client

Streamlit-in-process (the original layout) is fast to demo and opaque to review: no contract, no health checks, no persistence. FastAPI is the reviewable surface. Streamlit stays because it is a cheap UI, not because it is the backend.

## SQLite instead of Postgres

A scan log needs durability for `GET /scans/{id}` and for a reviewer to see a resource API. SQLite needs zero ops. Postgres is the right next step if this ever has concurrent writers across hosts.

## In-memory rate limit

Correct for a single Uvicorn process. Multi-worker or multi-replica needs Redis (or the edge). Documented, not faked.

## No Kubernetes / Terraform

Two sklearn models and a SQLite file do not justify a cluster. Compose is the honest runtime. Adding k8s YAML here would be cargo-cult.

## Synthetic data

A public phishing dump would improve realism and immediately create license, PII, and malware-hosting problems. Synthetic data keeps the repo safe to clone. The model card states the metric caveat in plain language.
