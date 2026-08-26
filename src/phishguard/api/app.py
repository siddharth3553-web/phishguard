"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from phishguard import __version__
from phishguard.api.deps import RuntimeState
from phishguard.api.routers.auth import router as auth_router
from phishguard.api.routers.ops import router as ops_router
from phishguard.api.routers.scans import public_router as safe_click_router
from phishguard.api.routers.scans import router as scans_router
from phishguard.core.config import Settings, get_settings
from phishguard.core.logging import configure_logging
from phishguard.core.middleware import apply_security_middleware
from phishguard.core.telemetry import setup_telemetry
from phishguard.db.session import init_db
from phishguard.services.predictor import PhishGuardPredictor
from phishguard.services.seed import seed_demo_data

logger = structlog.get_logger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db(settings)
        try:
            seed_demo_data(settings)
        except Exception:
            logger.exception("seed_demo_failed")
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
        description="Employee report + analyst investigation desk for phishing URLs, email, and QR.",
        version=__version__,
        lifespan=lifespan,
        docs_url=docs,
        redoc_url=redoc,
        openapi_url=openapi,
    )
    app.state.settings = settings
    # SessionMiddleware must be outermost for request.session
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        session_cookie="phishguard_session",
        same_site="lax",
        https_only=settings.is_production,
        max_age=60 * 60 * 12,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
    )
    apply_security_middleware(app, settings)
    app.include_router(ops_router)
    app.include_router(auth_router)
    app.include_router(scans_router)
    app.include_router(safe_click_router)
    setup_telemetry(app, settings)
    return app
