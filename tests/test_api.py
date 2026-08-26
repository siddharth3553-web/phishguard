from __future__ import annotations

from fastapi.testclient import TestClient


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "X-Request-ID" in r.headers


def test_ready_and_version(client: TestClient) -> None:
    r = client.get("/ready")
    assert r.status_code == 200
    assert r.json()["models_loaded"] is True
    v = client.get("/version")
    assert v.status_code == 200
    assert v.json()["model_version"] == "fixture"


def test_metrics(client: TestClient) -> None:
    r = client.get("/metrics")
    assert r.status_code == 200
    assert b"phishguard_http_requests_total" in r.content


def test_url_scan_roundtrip(client: TestClient) -> None:
    r = client.post("/api/v1/urls/scans", json={"url": "https://www.wikipedia.org/wiki/Python"})
    assert r.status_code == 201
    body = r.json()
    assert body["kind"] == "url"
    assert body["verdict"] in {"Safe", "Suspicious", "Phishing", "Uncertain"}
    assert "id" in body
    got = client.get(f"/api/v1/scans/{body['id']}")
    assert got.status_code == 200
    assert got.json()["id"] == body["id"]


def test_email_scan(client: TestClient) -> None:
    r = client.post(
        "/api/v1/emails/scans",
        json={"text": "Meeting notes attached. Thanks, see you tomorrow at the office."},
    )
    assert r.status_code == 201
    assert r.json()["kind"] == "email"


def test_batch_scan(client: TestClient) -> None:
    r = client.post(
        "/api/v1/scans:batch",
        json={
            "items": [
                {"kind": "url", "value": "https://github.com"},
                {
                    "kind": "email",
                    "value": "URGENT verify your account http://secure-apple.xyz/confirm",
                },
            ]
        },
    )
    assert r.status_code == 201
    assert len(r.json()["scans"]) == 2


def test_missing_scan(client: TestClient) -> None:
    r = client.get("/api/v1/scans/not-a-real-id")
    assert r.status_code == 404


def test_validation(client: TestClient) -> None:
    r = client.post("/api/v1/urls/scans", json={"url": "   "})
    assert r.status_code == 422
