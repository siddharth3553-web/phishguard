"""Auth: cookie sessions + bcrypt (no JWT)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from phishguard.api.deps import current_user_optional, db_session, require_user, write_audit
from phishguard.api.schemas import LoginRequest, UserOut
from phishguard.core.security import verify_password
from phishguard.db.models import User

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=UserOut)
def login(
    body: LoginRequest,
    request: Request,
    session: Session = Depends(db_session),
) -> UserOut:
    email = body.email.strip().lower()
    user = session.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid email or password")
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["role"] = user.role
    write_audit(
        session,
        actor_id=user.id,
        action="login",
        resource_type="user",
        resource_id=user.id,
    )
    return UserOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
    )


@router.post("/logout")
def logout(request: Request, user: User | None = Depends(current_user_optional)) -> dict[str, str]:
    request.session.clear()
    return {"status": "ok"}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(require_user)) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
    )
