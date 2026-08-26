# Tradeoffs

- **uv** + committed `uv.lock` for reproducible installs; CI uses `uv sync --frozen`.
- **React + Vite** for the product UI (typed client against the FastAPI contract).
- **Postgres 16** in Compose; in-memory/file **SQLite** only under pytest.
- **ONNX** for the URL forest; **skops** for email/helpdesk custom pipelines (hybrid TF-IDF mixers do not convert cleanly).
- No Kubernetes / Redis / JWT — scoped for a two-model demo, not a platform rewrite.
