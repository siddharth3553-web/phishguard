"""Org brand domains + allowlist helpers."""

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishguard.db.models import AllowlistEntry, OrgSetting
from phishguard.services.url_intel import DEFAULT_BRANDS


def get_brand_domains(session: Session, org_id: str = "demo") -> list[str]:
    row = session.get(OrgSetting, org_id)
    if row is None:
        return list(DEFAULT_BRANDS)
    try:
        data = json.loads(row.brand_domains_json)
        if isinstance(data, list) and data:
            return [str(x).lower() for x in data]
    except json.JSONDecodeError:
        pass
    return list(DEFAULT_BRANDS)


def get_allowlist_set(session: Session, org_id: str = "demo") -> set[str]:
    rows = session.scalars(select(AllowlistEntry).where(AllowlistEntry.org_id == org_id)).all()
    return {r.value.lower() for r in rows}
