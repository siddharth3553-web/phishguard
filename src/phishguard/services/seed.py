"""Seed demo users and org settings."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select

from phishguard.core.config import Settings
from phishguard.core.security import hash_password
from phishguard.db.models import OrgSetting, User
from phishguard.db.session import get_engine
from phishguard.services.url_intel import DEFAULT_BRANDS
from sqlalchemy.orm import Session

logger = structlog.get_logger(__name__)

DEMO_USERS = [
    {
        "email": "employee@demo.local",
        "display_name": "Demo Employee",
        "role": "employee",
        "password": "employee123",
    },
    {
        "email": "analyst@demo.local",
        "display_name": "Demo Analyst",
        "role": "analyst",
        "password": "analyst123",
    },
]


def seed_demo_data(settings: Settings) -> None:
    _ = settings
    engine = get_engine()
    with Session(engine) as session:
        for u in DEMO_USERS:
            existing = session.scalar(select(User).where(User.email == u["email"]))
            if existing is None:
                session.add(
                    User(
                        id=str(uuid.uuid4()),
                        email=u["email"],
                        display_name=u["display_name"],
                        password_hash=hash_password(u["password"]),
                        role=u["role"],
                        created_at=datetime.now(timezone.utc),
                    )
                )
                logger.info("seeded_user", email=u["email"], role=u["role"])
        if session.get(OrgSetting, "demo") is None:
            session.add(
                OrgSetting(
                    org_id="demo",
                    brand_domains_json=json.dumps(DEFAULT_BRANDS),
                    updated_at=datetime.now(timezone.utc),
                )
            )
        session.commit()
