"""Email intelligence — URL extraction, header mismatch, urgency, brand spoof."""

from __future__ import annotations

import re
from typing import Any

from phishguard.services.url_intel import enrich_url

URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)
HEADER_FROM_RE = re.compile(r"(?im)^From:\s*(.+)$")
HEADER_RETURN_RE = re.compile(r"(?im)^Return-Path:\s*<?([^>\s]+)>?")
DISPLAY_EMAIL_RE = re.compile(r"(.+?)\s*<([^>]+)>")

URGENCY = [
    "urgent",
    "immediately",
    "within 24 hours",
    "within 2 hours",
    "account suspended",
    "verify your account",
    "password expires",
    "click here",
    "act now",
    "unusual activity",
    "confirm your identity",
    "wire transfer",
    "gift card",
]

BRAND_NAMES = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "chase",
    "bank of america",
    "wells fargo",
    "linkedin",
    "facebook",
    "instagram",
]


def extract_urls(text: str) -> list[str]:
    found: list[str] = []
    for m in URL_RE.findall(text or ""):
        u = m.rstrip(").,;]'\"")
        if u.lower().startswith("www."):
            u = "http://" + u
        if u not in found:
            found.append(u)
    return found[:20]


def parse_headers(text: str) -> dict[str, str | None]:
    from_line = None
    m = HEADER_FROM_RE.search(text or "")
    if m:
        from_line = m.group(1).strip()
    ret = None
    m2 = HEADER_RETURN_RE.search(text or "")
    if m2:
        ret = m2.group(1).strip().lower()
    display = None
    addr = None
    if from_line:
        dm = DISPLAY_EMAIL_RE.match(from_line)
        if dm:
            display = dm.group(1).strip().strip('"')
            addr = dm.group(2).strip().lower()
        elif "@" in from_line:
            addr = from_line.strip().lower().strip("<>")
    return {"from_raw": from_line, "from_display": display, "from_addr": addr, "return_path": ret}


def enrich_email(
    text: str,
    *,
    brands: list[str] | None = None,
    allowlisted: set[str] | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    headers = parse_headers(text)
    lower = (text or "").lower()

    urgency_hits = [u for u in URGENCY if u in lower]
    if urgency_hits:
        reasons.append(f"urgency_language:{urgency_hits[0]}")

    from_addr = headers.get("from_addr")
    ret = headers.get("return_path")
    if from_addr and ret and from_addr.split("@")[-1] != ret.split("@")[-1]:
        reasons.append("from_return_path_mismatch")

    display = (headers.get("from_display") or "").lower()
    for brand in BRAND_NAMES:
        if brand in display:
            domain = (from_addr or "").split("@")[-1] if from_addr else ""
            brand_token = brand.replace(" ", "")
            if domain and brand_token not in domain.replace("-", "").replace(".", ""):
                reasons.append(f"display_name_brand_spoof:{brand}")
                break

    urls = extract_urls(text)
    url_intel: list[dict[str, Any]] = []
    for u in urls:
        info = enrich_url(u, brands=brands, allowlisted=allowlisted, follow=len(urls) <= 3)
        url_intel.append(info)
        for r in info.get("reasons") or []:
            if r != "allowlisted":
                reasons.append(f"url:{r}")

    if allowlisted and from_addr:
        domain = from_addr.split("@")[-1]
        if from_addr in allowlisted or domain in allowlisted:
            reasons = ["allowlisted"]
            return {
                "reasons": reasons,
                "headers": headers,
                "extracted_urls": urls,
                "url_intel": url_intel,
                "urgency_hits": urgency_hits,
                "suppress": True,
            }

    return {
        "reasons": reasons,
        "headers": headers,
        "extracted_urls": urls,
        "url_intel": url_intel,
        "urgency_hits": urgency_hits,
        "suppress": False,
    }
