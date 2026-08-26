from __future__ import annotations

from fastapi.testclient import TestClient


def test_login_and_me(client: TestClient) -> None:
    r = client.post(
        "/api/v1/auth/login",
        json={"email": "employee@demo.local", "password": "employee123"},
    )
    assert r.status_code == 200
    assert r.json()["role"] == "employee"
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "employee@demo.local"


def test_analyst_queue_and_disposition(client: TestClient) -> None:
    client.post(
        "/api/v1/auth/login",
        json={"email": "employee@demo.local", "password": "employee123"},
    )
    scan = client.post(
        "/api/v1/urls/scans",
        json={"url": "https://paypa1.com/login"},
    )
    assert scan.status_code == 201
    sid = scan.json()["id"]
    assert "reasons" in scan.json()
    report = client.post(f"/api/v1/scans/{sid}/report")
    assert report.status_code == 200
    assert report.json()["reported"] is True

    client.post("/api/v1/auth/logout")
    client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@demo.local", "password": "analyst123"},
    )
    queue = client.get("/api/v1/analyst/queue")
    assert queue.status_code == 200
    ids = {s["id"] for s in queue.json()["scans"]}
    assert sid in ids

    disp = client.post(
        f"/api/v1/scans/{sid}/disposition",
        json={"status": "false_positive", "note": "partner domain"},
    )
    assert disp.status_code == 200
    assert disp.json()["status"] == "false_positive"
