"""BEC / payload-less social-engineering signals from pasted email text.

No Graph history — works from headers + body alone (local-first Alternative to Abnormal).
"""

from __future__ import annotations

import re
from typing import Any

from phishguard.services.email_intel import extract_urls, parse_headers

WIRE_PATTERNS = [
    r"\bwire transfer\b",
    r"\bbank transfer\b",
    r"\bgift\s*cards?\b",
    r"\biTunes\s*card\b",
    r"\bW-?9\b",
    r"\bchange(?:d)? (?:bank|payment|routing|account)\b",
    r"\binvoice\s+(?:attached|overdue|payment)\b",
    r"\burgent(?:ly)? (?:need|require|process)\b",
    r"\bCEO\b",
    r"\bCFO\b",
    r"\bfrom (?:the )?executive\b",
]

BRAND_DISPLAY = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "chase",
    "bank of america",
    "wells fargo",
]


def score_bec(text: str) -> dict[str, Any]:
    reasons: list[str] = []
    score = 0
    lower = (text or "").lower()
    headers = parse_headers(text)
    urls = extract_urls(text)

    for pat in WIRE_PATTERNS:
        if re.search(pat, lower, re.I):
            label = re.sub(r"[\\^$*+?{}()|\\[\\]]", "", pat)[:40]
            reasons.append(f"bec_lang:{label.strip()}")
            score += 18
            break

    display = (headers.get("from_display") or "").lower()
    addr = headers.get("from_addr") or ""
    domain = addr.split("@")[-1] if "@" in addr else ""
    for brand in BRAND_DISPLAY:
        if brand in display:
            token = brand.replace(" ", "")
            if domain and token not in domain.replace("-", "").replace(".", ""):
                reasons.append("bec_display_spoof")
                score += 28
            break

    if not urls and score >= 18:
        reasons.append("bec_no_url_payload")
        score += 22

    from_addr = headers.get("from_addr")
    ret = headers.get("return_path")
    if from_addr and ret and from_addr.split("@")[-1] != ret.split("@")[-1]:
        reasons.append("bec_header_mismatch")
        score += 15

    # first-contact-ish: free mail domain + finance ask
    free = ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "mail.com")
    if domain in free and any(r.startswith("bec_lang:") for r in reasons):
        reasons.append("bec_free_mail_finance")
        score += 12

    score = min(100, score)
    return {
        "bec_score": score,
        "reasons": reasons,
        "payload_less": "bec_no_url_payload" in reasons,
    }
