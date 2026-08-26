"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from phishguard import __version__
from phishguard.api.deps import RuntimeState
from phishguard.api.routers.ops import router as ops_router
from phishguard.api.routers.scans import router as scans_router
from phishguard.core.config import Settings, get_settings
from phishguard.core.logging import configure_logging
from phishguard.core.middleware import apply_security_middleware
from phishguard.core.telemetry import setup_telemetry
from phishguard.db.session import init_db
from phishguard.services.predictor import PhishGuardPredictor

logger = structlog.get_logger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db(settings)
        state = RuntimeState()
        try:
            state.predictor = PhishGuardPredictor(settings.resolved_models_dir())
            state.ready = True
            logger.info("models_loaded", path=str(settings.resolved_models_dir()))
        except Exception as exc:
            state.ready = False
            state.ready_error = str(exc)
            logger.exception("model_load_failed")
        app.state.runtime = state
        yield

    docs = None if settings.is_production else "/docs"
    redoc = None if settings.is_production else "/redoc"
    openapi = None if settings.is_production else "/openapi.json"

    app = FastAPI(
        title=settings.app_name,
        description="Production ML API for URL and email phishing detection.",
        version=__version__,
        lifespan=lifespan,
        docs_url=docs,
        redoc_url=redoc,
        openapi_url=openapi,
    )
    app.state.settings = settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
    )
    apply_security_middleware(app, settings)
    app.include_router(ops_router)
    app.include_router(scans_router)
    setup_telemetry(app, settings)
    return app
