import math
import re
from urllib.parse import urlparse

import tldextract

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "confirm",
    "password",
    "signin",
    "webscr",
    "ebayisapi",
    "suspend",
    "alert",
    "billing",
    "paypal",
    "authenticate",
]

SHORTENER_DOMAINS = [
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
]

# High-risk TLDs often abused in phishing (single-label suffix)
RISKY_TLD_LABELS = frozenset(
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
        "online",
        "site",
        "work",
        "click",
        "link",
        "win",
    }
)

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_digits",
    "num_special_chars",
    "num_subdomains",
    "has_ip_address",
    "has_at_symbol",
    "has_https",
    "has_www",
    "has_suspicious_keywords",
    "url_entropy",
    "is_shortened",
    "digit_to_letter_ratio",
    # Extended signals for real-world / obfuscated URLs
    "punycode_hint",
    "suspicious_tld",
    "query_length",
    "num_query_params",
    "path_depth",
    "has_nonstandard_port",
    "at_in_path",
    "brand_in_subdomain_spoof",
]


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _has_ip_pattern(url: str) -> int:
    ipv4 = re.compile(
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    )
    return int(bool(ipv4.search(url)))


def _netloc_host_port(netloc: str) -> tuple[str, int | None]:
    if not netloc:
        return "", None
    host = netloc
    port: int | None = None
    if host.startswith("[") and "]" in host:
        return host, None
    if ":" in host:
        left, _, right = host.rpartition(":")
        if right.isdigit():
            try:
                p = int(right)
                if 0 < p <= 65535:
                    host = left
                    port = p
            except ValueError:
                pass
    return host, port


def _tld_risk_flag(ext: tldextract.ExtractResult) -> int:
    suf = (ext.suffix or "").lower()
    if not suf:
        return 0
    label = suf.split(".")[-1]
    return int(label in RISKY_TLD_LABELS)


def _brand_spoof_subdomain(subdomain: str) -> int:
    s = (subdomain or "").lower()
    brands = (
        "google",
        "microsoft",
        "apple",
        "paypal",
        "amazon",
        "facebook",
        "netflix",
        "linkedin",
        "bank",
        "secure",
        "login",
    )
    return int(any(b in s for b in brands) and len(s) > 0)


def extract_features(url: str) -> dict[str, float | int]:
    """Extract numerical features from a URL string."""
    url = (url or "").strip()
    if not url:
        raise ValueError("URL must not be empty")
    if not url.startswith(("http://", "https://")):
        url_for_parse = "http://" + url
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)
    ext = tldextract.extract(url_for_parse)

    domain = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    url_lower = url.lower()

    host, port = _netloc_host_port(domain)
    num_letters = sum(c.isalpha() for c in url)
    num_digits = sum(c.isdigit() for c in url)

    subdomains = ext.subdomain.split(".") if ext.subdomain else []
    num_subdomains = len([s for s in subdomains if s])

    nonstandard_port = 0
    if port is not None and port not in (80, 443):
        nonstandard_port = 1

    query_len = len(query)
    num_query_params = query.count("&") + (1 if query and "=" in query else 0)
    path_depth = max(0, path.count("/") - 1)
    puny = int("xn--" in host.lower())
    at_path = int("@" in path)

    features: dict[str, float | int] = {
        "url_length": len(url),
        "domain_length": len(domain),
        "path_length": len(path),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_digits": num_digits,
        "num_special_chars": sum(
            not c.isalnum() and c not in ".:/-_" for c in url
        ),
        "num_subdomains": num_subdomains,
        "has_ip_address": _has_ip_pattern(url),
        "has_at_symbol": int("@" in url),
        "has_https": int(url_lower.startswith("https")),
        "has_www": int("www." in url_lower),
        "has_suspicious_keywords": int(
            any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS)
        ),
        "url_entropy": round(_shannon_entropy(url), 4),
        "is_shortened": int(any(sd in url_lower for sd in SHORTENER_DOMAINS)),
        "digit_to_letter_ratio": round(
            num_digits / num_letters if num_letters > 0 else float(num_digits),
            4,
        ),
        "punycode_hint": puny,
        "suspicious_tld": _tld_risk_flag(ext),
        "query_length": query_len,
        "num_query_params": num_query_params,
        "path_depth": path_depth,
        "has_nonstandard_port": nonstandard_port,
        "at_in_path": at_path,
        "brand_in_subdomain_spoof": _brand_spoof_subdomain(ext.subdomain),
    }
    return features


def extract_features_array(url: str) -> list[float | int]:
    """Return feature values as a list in FEATURE_NAMES order."""
    feat = extract_features(url)
    return [feat[name] for name in FEATURE_NAMES]
