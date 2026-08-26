# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim-bookworm
WORKDIR /app
RUN useradd --create-home --uid 10001 appuser
COPY --from=builder /app/.venv /app/.venv
COPY src ./src
COPY alembic ./alembic
COPY alembic.ini ./
COPY artifacts/metrics ./artifacts/metrics
COPY tests/fixtures/models ./artifacts/models
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    ENVIRONMENT=dev \
    MODELS_DIR=/app/artifacts/models \
    DATABASE_URL=postgresql+psycopg://phishguard:phishguard@db:5432/phishguard
RUN mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
CMD ["uvicorn", "phishguard.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
