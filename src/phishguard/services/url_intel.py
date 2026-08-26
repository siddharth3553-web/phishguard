"""URL intelligence — lookalike, homograph, shortener, DNS, redirect hops."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlparse

import httpx
import tldextract

HOMOGLYPH = str.maketrans(
    {
        "а": "a",  # cyrillic
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "０": "0",
        "１": "1",
        "３": "3",
        "４": "4",
        "５": "5",
        "７": "7",
        "８": "8",
        "９": "9",
    }
)

SHORTENERS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "bl.ink",
        "short.io",
        "rebrand.ly",
        "cutt.ly",
    }
)

RISKY_TLDS = frozenset(
    {
        "xyz",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "top",
        "buzz",
        "club",
        "fun",
        "click",
        "link",
        "zip",
        "mov",
    }
)

DEFAULT_BRANDS = [
    "paypal.com",
    "microsoft.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "netflix.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins, delete, sub = cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def normalize_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    try:
        h = h.encode("ascii").decode("idna") if h.startswith("xn--") else h
    except Exception:
        pass
    # strip port
    if ":" in h and not h.count(":") > 1:
        h = h.split(":", 1)[0]
    return h.translate(HOMOGLYPH)


def registered_domain(host: str) -> str:
    ext = tldextract.extract(host)
    if not ext.domain:
        return host
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain


def looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def find_lookalike(host: str, brands: list[str]) -> str | None:
    reg = registered_domain(host)
    base = reg.split(".")[0]
    for brand in brands:
        breg = registered_domain(brand)
        bbase = breg.split(".")[0]
        if reg == breg:
            continue
        # exact brand substring with phishing prefix
        if bbase in base and base != bbase and len(base) - len(bbase) <= 12:
            return brand
        dist = _levenshtein(base, bbase)
        if 0 < dist <= 2 and len(bbase) >= 4:
            return brand
        # digit/letter swaps common in phishing
        if base.replace("1", "l").replace("0", "o") == bbase:
            return brand
        if base.replace("l", "1").replace("o", "0") == bbase:
            return brand
    return None


def dns_signals(host: str) -> dict[str, Any]:
    out: dict[str, Any] = {"resolves": False, "has_mx_hint": False, "ips": []}
    if looks_like_ip(host):
        out["resolves"] = True
        out["ips"] = [host.strip("[]")]
        return out
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        out["resolves"] = bool(ips)
        out["ips"] = ips[:5]
    except OSError:
        pass
    try:
        # lightweight MX probe via getaddrinfo on mail. subdomain is noisy;
        # just note if A record exists — full MX needs dnspython
        pass
    except OSError:
        pass
    return out


def follow_redirects(url: str, max_hops: int = 3, timeout: float = 3.0) -> dict[str, Any]:
    chain: list[str] = [url]
    final = url
    try:
        with httpx.Client(
            follow_redirects=False,
            timeout=timeout,
            headers={"User-Agent": "PhishGuard/3 (+security-check)"},
        ) as client:
            current = url
            for _ in range(max_hops):
                resp = client.get(current)
                if resp.status_code in {301, 302, 303, 307, 308}:
                    loc = resp.headers.get("location")
                    if not loc:
                        break
                    if loc.startswith("/"):
                        p = urlparse(current)
                        loc = f"{p.scheme}://{p.netloc}{loc}"
                    chain.append(loc)
                    current = loc
                    final = loc
                    continue
                final = str(resp.url)
                if final not in chain:
                    chain.append(final)
                break
    except Exception as exc:
        return {"chain": chain, "final_url": final, "error": str(exc)[:200]}
    start_host = normalize_host(urlparse(url).hostname or "")
    final_host = normalize_host(urlparse(final).hostname or "")
    return {
        "chain": chain,
        "final_url": final,
        "host_changed": bool(start_host and final_host and start_host != final_host),
        "final_host": final_host,
    }


def enrich_url(
    url: str,
    *,
    brands: list[str] | None = None,
    allowlisted: set[str] | None = None,
    follow: bool = True,
) -> dict[str, Any]:
    reasons: list[str] = []
    brands = brands or DEFAULT_BRANDS
    allowlisted = allowlisted or set()

    raw = (url or "").strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw
    parsed = urlparse(raw)
    host = normalize_host(parsed.hostname or "")
    reg = registered_domain(host) if host else ""
    ext = tldextract.extract(host) if host else None

    if not host:
        reasons.append("missing_host")
        return {"url": url, "host": "", "reasons": reasons, "signals": {}}

    if reg in allowlisted or host in allowlisted:
        return {
            "url": url,
            "host": host,
            "registered_domain": reg,
            "reasons": ["allowlisted"],
            "signals": {"allowlisted": True},
            "suppress": True,
        }

    signals: dict[str, Any] = {
        "host": host,
        "registered_domain": reg,
        "has_https": parsed.scheme.lower() == "https",
        "is_ip": looks_like_ip(host),
        "is_shortener": reg in SHORTENERS,
        "risky_tld": bool(ext and ext.suffix.split(".")[-1] in RISKY_TLDS),
        "punycode": "xn--" in (parsed.hostname or "").lower(),
    }

    if signals["is_ip"]:
        reasons.append("ip_literal_host")
    if signals["is_shortener"]:
        reasons.append("url_shortener")
    if signals["risky_tld"]:
        reasons.append(f"risky_tld:{ext.suffix if ext else ''}")
    if signals["punycode"]:
        reasons.append("punycode_host")

    lookalike = find_lookalike(host, brands)
    if lookalike:
        reasons.append(f"lookalike_of:{lookalike}")
        signals["lookalike_of"] = lookalike

    dns = dns_signals(host)
    signals["dns"] = dns
    if not dns.get("resolves") and not signals["is_ip"]:
        reasons.append("dns_unresolved")

    redirect: dict[str, Any] = {}
    if follow and not signals["is_ip"]:
        redirect = follow_redirects(raw)
        signals["redirect"] = redirect
        if redirect.get("host_changed"):
            reasons.append(f"redirect_host_changed:{redirect.get('final_host')}")
            final_look = find_lookalike(redirect.get("final_host") or "", brands)
            if final_look:
                reasons.append(f"redirect_lookalike_of:{final_look}")

    return {
        "url": url,
        "normalized_url": raw,
        "host": host,
        "registered_domain": reg,
        "reasons": reasons,
        "signals": signals,
        "suppress": False,
    }
