# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir .

FROM python:3.12-slim
WORKDIR /app
RUN useradd --create-home --uid 10001 appuser
COPY --from=builder /usr/local /usr/local
COPY src ./src
COPY apps ./apps
COPY artifacts/metrics ./artifacts/metrics
COPY tests/fixtures/models ./artifacts/models
COPY pyproject.toml README.md ./
RUN mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser
ENV PYTHONUNBUFFERED=1 \
    ENVIRONMENT=dev \
    MODELS_DIR=/app/artifacts/models \
    DATABASE_URL=sqlite:////app/data/phishguard.db
EXPOSE 8000
CMD ["uvicorn", "phishguard.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
