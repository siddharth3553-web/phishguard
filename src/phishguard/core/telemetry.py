"""Optional OpenTelemetry tracing (OTLP HTTP)."""

from __future__ import annotations

import logging

from phishguard.core.config import Settings

logger = logging.getLogger(__name__)


def setup_telemetry(app, settings: Settings) -> None:
    endpoint = settings.otel_exporter_otlp_endpoint
    if not endpoint:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create({"service.name": settings.otel_service_name})
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
        from phishguard.db.session import get_engine

        engine = get_engine()
        if engine is not None:
            SQLAlchemyInstrumentor().instrument(engine=engine)
        logger.info("OpenTelemetry enabled endpoint=%s", endpoint)
    except Exception:
        logger.exception("failed to enable OpenTelemetry")
