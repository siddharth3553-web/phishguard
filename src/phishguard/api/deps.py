from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from phishguard.core.config import Settings, get_settings
from phishguard.db.models import AuditEvent, User
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
    if request.url.path.startswith("/api/v1/auth"):
        return
    if not settings.api_key:
        return
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="invalid or missing API key")


def current_user_optional(
    request: Request,
    session: Session = Depends(db_session),
) -> User | None:
    uid = request.session.get("user_id")
    if not uid:
        return None
    return session.get(User, uid)


def require_user(user: User | None = Depends(current_user_optional)) -> User:
    if user is None:
        raise HTTPException(status_code=401, detail="login required")
    return user


def require_analyst(user: User = Depends(require_user)) -> User:
    if user.role != "analyst":
        raise HTTPException(status_code=403, detail="analyst role required")
    return user


def write_audit(
    session: Session,
    *,
    actor_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    session.add(
        AuditEvent(
            id=str(uuid.uuid4()),
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            detail_json=json.dumps(detail or {}, default=str),
            created_at=datetime.now(timezone.utc),
        )
    )
