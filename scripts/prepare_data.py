#!/usr/bin/env python3
"""
Generate synthetic URL and email phishing datasets (offline).

Outputs:
  data/raw/url_data.csv    columns: url, label  (0=legit, 1=phishing)
  data/raw/email_data.csv  columns: text, label

Run: python scripts/prepare_data.py
"""

from __future__ import annotations

import csv
import hashlib
import os
import random
import string

from phishguard.paths import data_raw_dir
from phishguard.settings import DATASET_EMAIL_COUNT, DATASET_URL_COUNT

random.seed(42)

LEGIT_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "linkedin.com",
    "atlassian.com",
    "airbnb.com",
    "netflix.com",
    "paypal.com",
    "wikipedia.org",
    "stackoverflow.com",
    "nytimes.com",
    "bbc.com",
    "cloudflare.com",
]

PHISH_TLDS = ["xyz", "tk", "ml", "ga", "cf", "top", "buzz", "click", "work"]
LEGIT_PATHS = [
    "/",
    "/login",
    "/account",
    "/help",
    "/support",
    "/docs",
    "/pricing",
    "/signup",
    "/contact",
    "/settings/security",
]
PHISH_PATHS = [
    "/verify",
    "/secure-login",
    "/account-update",
    "/confirm",
    "/webscr",
    "/signin",
    "/recover",
    "/billing-alert",
]


def _token(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _legit_url() -> str:
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = "https"
    if random.random() < 0.15:
        q = f"?ref={_token(6)}&utm_source=email"
        return f"{scheme}://{domain}{path}{q}"
    if random.random() < 0.1:
        return f"{scheme}://www.{domain}{path}"
    return f"{scheme}://{domain}{path}"


def _phish_url() -> str:
    host = f"{_token(8)}.{random.choice(PHISH_TLDS)}"
    if random.random() < 0.25:
        brand = random.choice(["paypal", "microsoft", "apple", "google", "amazon"])
        host = f"{brand}-secure.{_token(5)}.{random.choice(PHISH_TLDS)}"
    path = random.choice(PHISH_PATHS)
    scheme = random.choice(["http", "https"])
    q = f"?id={_token(12)}"
    if random.random() < 0.2:
        return f"{scheme}://bit.ly/{_token(7)}"
    if random.random() < 0.1:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        return f"{scheme}://{ip}{path}{q}"
    return f"{scheme}://{host}{path}{q}"


LEGIT_EMAILS = [
    "Your order #{oid} has shipped. Track it at https://amazon.com/orders/{oid}",
    "Meeting reminder: project sync tomorrow at 10:00 AM. Join via Teams.",
    "GitHub: @{user} opened a pull request in {repo}. Review when ready.",
    "Your Netflix invoice for this month is ready in Account > Billing.",
    "Password changed successfully on your Microsoft account. If this wasn't you, contact support.",
    "LinkedIn: You have 3 new connection requests waiting.",
    "Weekly digest from {domain}: top articles for you.",
    "Calendar invite accepted for Design Review on Friday.",
]

PHISH_EMAILS = [
    "Your {brand} account requires immediate verification. Click below to confirm your identity: {url}",
    "URGENT: Unusual sign-in detected. Secure your account now: {url}",
    "Your package could not be delivered due to an incorrect address. Update your shipping info: {url}",
    "We suspended your {brand} wallet. Verify ownership within 24 hours: {url}",
    "Payroll deposit failed. Confirm bank details immediately: {url}",
    "Security alert: password expires today. Reset here: {url}",
    "You have a pending refund of ${amt}. Claim it: {url}",
    "IT Helpdesk: VPN access revoked. Re-authenticate: {url}",
]


def _fill_email(template: str, phishing: bool) -> str:
    brand = random.choice(["PayPal", "Microsoft", "Apple", "Amazon", "Netflix", "Chase"])
    url = _phish_url() if phishing else f"https://{random.choice(LEGIT_DOMAINS)}/account"
    return template.format(
        brand=brand,
        url=url,
        oid=random.randint(100000, 999999),
        user=_token(6),
        repo=random.choice(["platform-api", "webapp", "infra"]),
        domain=random.choice(LEGIT_DOMAINS),
        amt=random.choice([49, 99, 250, 1200]),
    )


def _key(*parts: str) -> str:
    raw = "|".join(p.strip().lower() for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def generate_urls(n: int) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    seen: set[str] = set()
    guard = 0
    while len(rows) < n and guard < n * 40:
        label = 1 if random.random() < 0.5 else 0
        url = _phish_url() if label else _legit_url()
        k = _key(url, str(label))
        guard += 1
        if k in seen:
            continue
        seen.add(k)
        rows.append((url, label))
    random.shuffle(rows)
    return rows


def generate_emails(n: int) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    seen: set[str] = set()
    guard = 0
    while len(rows) < n and guard < n * 40:
        label = 1 if random.random() < 0.5 else 0
        tmpl = random.choice(PHISH_EMAILS if label else LEGIT_EMAILS)
        text = _fill_email(tmpl, phishing=bool(label))
        if random.random() < 0.1:
            text += " Sent from my iPhone."
        k = _key(text, str(label))
        guard += 1
        if k in seen:
            continue
        seen.add(k)
        rows.append((text, label))
    random.shuffle(rows)
    return rows


def _write_csv(path: str, header: list[str], rows: list[tuple]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"[OK] Wrote {len(rows)} rows -> {path}")


def main() -> None:
    out = str(data_raw_dir())
    _write_csv(
        os.path.join(out, "url_data.csv"),
        ["url", "label"],
        generate_urls(DATASET_URL_COUNT),
    )
    _write_csv(
        os.path.join(out, "email_data.csv"),
        ["text", "label"],
        generate_emails(DATASET_EMAIL_COUNT),
    )


if __name__ == "__main__":
    main()
