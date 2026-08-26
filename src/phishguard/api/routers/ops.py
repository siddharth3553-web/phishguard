from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response

from phishguard import __version__
from phishguard.api.deps import RuntimeState, runtime, settings_dep
from phishguard.api.schemas import HealthResponse, ReadyResponse, VersionResponse
from phishguard.core.config import Settings
from phishguard.core.metrics import render_metrics

router = APIRouter(tags=["ops"])


@router.get("/health", response_model=HealthResponse)
def health(settings: Settings = Depends(settings_dep)) -> HealthResponse:
    return HealthResponse(status="ok", app=settings.app_name)


@router.get("/ready", response_model=ReadyResponse)
def ready(
    settings: Settings = Depends(settings_dep),
    state: RuntimeState = Depends(runtime),
) -> ReadyResponse:
    if not state.ready:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_ready",
                "models_loaded": False,
                "model_version": settings.model_version,
                "detail": state.ready_error,
            },
        )
    return ReadyResponse(
        status="ready",
        models_loaded=True,
        model_version=settings.model_version,
        detail=None,
    )


@router.get("/metrics")
def metrics() -> Response:
    body, content_type = render_metrics()
    return Response(content=body, media_type=content_type)


@router.get("/version", response_model=VersionResponse)
def version(settings: Settings = Depends(settings_dep)) -> VersionResponse:
    return VersionResponse(
        app=settings.app_name,
        version=__version__,
        git_sha=settings.git_sha,
        model_version=settings.model_version,
        environment=settings.environment,
    )
