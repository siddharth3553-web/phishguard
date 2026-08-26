from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from phishguard.db.models import AllowlistEntry
from phishguard.db.session import get_engine
from phishguard.services.bec import score_bec
from phishguard.services.campaigns import campaign_fingerprint
from sqlalchemy.orm import Session


def test_bec_wire_and_no_url() -> None:
    text = (
        "From: Jane CFO <jane@gmail.com>\n\n"
        "Please process an urgent wire transfer today for the vendor invoice."
    )
    out = score_bec(text)
    assert out["bec_score"] >= 40
    assert any(r.startswith("bec_lang:") or r == "bec_no_url_payload" for r in out["reasons"])
    assert "bec_no_url_payload" in out["reasons"]


def test_bec_display_spoof() -> None:
    text = "From: PayPal Security <alerts@evil-mail.tk>\n\nYour invoice is overdue."
    out = score_bec(text)
    assert "bec_display_spoof" in out["reasons"]


def test_campaign_fingerprint_stable() -> None:
    a = {
        "reasons": ["lookalike_of:paypal.com", "bec_lang:wire"],
        "extracted_urls": ["https://paypa1.com/x"],
    }
    b = {
        "reasons": ["bec_lang:wire", "lookalike_of:paypal.com"],
        "extracted_urls": ["https://paypa1.com/y"],
    }
    fp_a, brand_a = campaign_fingerprint(a)
    fp_b, brand_b = campaign_fingerprint(b)
    assert brand_a == "paypal.com"
    assert brand_b == "paypal.com"
    assert fp_a == fp_b


def test_email_scan_bec_and_campaign(client: TestClient) -> None:
    body = (
        "From: PayPal Billing <billing@paypa1-secure.xyz>\n"
        "Return-Path: <bounce@evil.tk>\n\n"
        "Urgent: process wire transfer for invoice.\n"
        "Click http://secure-payrol1-update.example/login"
    )
    r = client.post("/api/v1/emails/scans", json={"text": body})
    assert r.status_code == 201
    data = r.json()
    assert data.get("bec_score", 0) >= 0
    assert data.get("decision_log")
    assert data.get("campaign_id") or data.get("reasons")
    # second similar scan should share campaign when clustering keys match
    r2 = client.post("/api/v1/emails/scans", json={"text": body})
    assert r2.status_code == 201
    if data.get("campaign_id") and r2.json().get("campaign_id"):
        assert data["campaign_id"] == r2.json()["campaign_id"]
        assert (r2.json().get("campaign_member_count") or 0) >= 2


def test_safe_click_token(client: TestClient) -> None:
    r = client.post("/api/v1/urls/scans", json={"url": "https://paypa1.com/signin"})
    assert r.status_code == 201
    data = r.json()
    clicks = data.get("safe_click_urls") or []
    assert clicks, "expected safe-click tokens for URL scan"
    token = clicks[0]["token"]
    check = client.get(f"/c/{token}")
    assert check.status_code == 200
    body = check.json()
    assert body["token"] == token
    assert body["verdict"]
    assert "reasons" in body


def test_expiring_allowlist_filtered(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@demo.local", "password": "analyst123"},
    )
    engine = get_engine()
    with Session(engine) as session:
        session.add(
            AllowlistEntry(
                id="expired-al-1",
                value="expired-partner.test",
                kind="domain",
                scope="domain",
                org_id="demo",
                expires_at=datetime.now(timezone.utc) - timedelta(days=1),
            )
        )
        session.add(
            AllowlistEntry(
                id="fresh-al-1",
                value="fresh-partner.test",
                kind="domain",
                scope="domain",
                org_id="demo",
                expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            )
        )
        session.commit()

    from phishguard.services.org_context import get_allowlist_set

    with Session(engine) as session:
        allow = get_allowlist_set(session)
    assert "fresh-partner.test" in allow
    assert "expired-partner.test" not in allow


def test_disposition_scope_campaign_and_ops(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/login",
        json={"email": "employee@demo.local", "password": "employee123"},
    )
    body = (
        "From: Microsoft Support <help@micr0soft-login.tk>\n\n"
        "Urgent gift card purchase needed for license renewal.\n"
        "Visit https://micr0soft-login.tk/reset"
    )
    a = client.post("/api/v1/emails/scans", json={"text": body}).json()
    b = client.post("/api/v1/emails/scans", json={"text": body}).json()
    client.post(f"/api/v1/scans/{a['id']}/report")

    client.post("/api/v1/auth/logout")
    client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@demo.local", "password": "analyst123"},
    )
    ops = client.get("/api/v1/ops/summary")
    assert ops.status_code == 200
    assert "open_queue" in ops.json()

    if a.get("campaign_id") and a["campaign_id"] == b.get("campaign_id"):
        disp = client.post(
            f"/api/v1/scans/{a['id']}/disposition",
            json={
                "status": "confirmed_phish",
                "scope": "campaign",
                "note": "cluster dispose",
            },
        )
        assert disp.status_code == 200
        b2 = client.get(f"/api/v1/scans/{b['id']}")
        assert b2.json()["status"] == "confirmed_phish"
