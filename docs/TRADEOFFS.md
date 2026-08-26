# Tradeoffs

- **uv** over pip: lockfile + fast installs; CI uses `uv sync --frozen`.
- **React** over Streamlit: reviewers expect a real product UI; Streamlit stays a prototyping tool.
- **Postgres** in Compose; SQLite only for pytest (zero ops in CI).
- **ONNX for URL**, **skops for email/helpdesk**: convert only what converts cleanly.
- No Kubernetes / Redis / JWT — taste over cargo-cult for a two-model demo.
