from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from phishguard.core.config import Settings, get_settings
from phishguard.db.session import get_session
from phishguard.services.predictor import PhishGuardPredictor

_OPS = {"/health", "/ready", "/metrics", "/version"}


@dataclass
class RuntimeState:
    predictor: PhishGuardPredictor | None = None
    ready: bool = False
    ready_error: str | None = None


def settings_dep(request: Request) -> Settings:
    stored = getattr(request.app.state, "settings", None)
    return stored if isinstance(stored, Settings) else get_settings()


def runtime(request: Request) -> RuntimeState:
    return request.app.state.runtime


def require_ready(state: RuntimeState = Depends(runtime)) -> PhishGuardPredictor:
    if not state.ready or state.predictor is None:
        raise HTTPException(
            status_code=503,
            detail=state.ready_error or "models not loaded",
        )
    return state.predictor


def db_session(session: Session = Depends(get_session)) -> Session:
    return session


def require_api_key(
    request: Request,
    settings: Settings = Depends(settings_dep),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    if request.url.path in _OPS or request.url.path.startswith("/docs"):
        return
    if not settings.api_key:
        return
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
