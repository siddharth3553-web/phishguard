"""Campaign fingerprinting for analyst clustering."""

from __future__ import annotations

import hashlib
import re
from typing import Any


def campaign_fingerprint(result: dict[str, Any]) -> tuple[str, str | None]:
    """Return (fingerprint, brand_hint)."""
    reasons = result.get("reasons") or []
    brand = None
    for r in reasons:
        if r.startswith("lookalike_of:"):
            brand = r.split(":", 1)[1]
            break
        if r.startswith("redirect_lookalike_of:"):
            brand = r.split(":", 1)[1]
            break
        if r.startswith("display_name_brand_spoof:"):
            brand = r.split(":", 1)[1]
            break

    urls = result.get("extracted_urls") or []
    host = ""
    if urls:
        m = re.search(r"https?://([^/]+)", urls[0], re.I)
        host = (m.group(1) if m else "").lower()
    qr = (result.get("qr_payload") or "")[:120]
    key_parts = [
        brand or "",
        host,
        qr,
        "|".join(sorted(r for r in reasons if r.startswith(("lookalike", "bec_", "qr_")))[:5]),
    ]
    raw = "|".join(key_parts).encode()
    fp = hashlib.sha256(raw).hexdigest()[:16]
    return fp, brand
