import os

import pytest
from fastapi.testclient import TestClient

from cypher.api.app import create_app
from cypher.api.auth import hash_password
from cypher.models import Alert, Severity


@pytest.fixture
def client(settings, monkeypatch):
    from cypher.storage.db import Database

    monkeypatch.setenv("CYPHER_SESSION_SECRET", "test-secret")
    monkeypatch.setenv("CYPHER_ADMIN_PASSWORD_HASH", hash_password("testpass123"))

    # Seed the SAME database file create_app() will open, so the API sees it.
    seed_db = Database(settings.storage.sqlite_path)
    seed_db.insert_alert(Alert(src_ip="203.0.113.5", score=90, severity=Severity.CRITICAL))
    seed_db.close()

    app = create_app(settings)
    return TestClient(app)


def test_unauthenticated_request_is_rejected(client):
    r = client.get("/api/alerts")
    assert r.status_code == 401


def test_healthz_does_not_require_login(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_login_with_wrong_password_fails(client):
    r = client.post("/api/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_login_then_access_protected_routes(client):
    r = client.post("/api/login", json={"username": "admin", "password": "testpass123"})
    assert r.status_code == 200
    assert "cypher_session" in r.cookies

    r = client.get("/api/alerts")
    assert r.status_code == 200
    alerts = r.json()
    assert len(alerts) == 1
    assert alerts[0]["src_ip"] == "203.0.113.5"
    assert alerts[0]["severity"] == "critical"

    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["mode"] == "dry_run"

    r = client.get("/api/blocks")
    assert r.status_code == 200
    assert r.json() == []


def test_logout_invalidates_session(client):
    client.post("/api/login", json={"username": "admin", "password": "testpass123"})
    assert client.get("/api/alerts").status_code == 200

    client.post("/api/logout")
    assert client.get("/api/alerts").status_code == 401


def test_dashboard_index_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Cypher 2.0" in r.text


def test_vendored_chartjs_served(client):
    r = client.get("/static/vendor/chart.umd.min.js")
    assert r.status_code == 200
    assert len(r.text) > 1000


def test_factory_honours_cypher_config_env_var(tmp_path, monkeypatch):
    """`uvicorn --factory` passes no settings, so which config file the API
    uses must be selectable via CYPHER_CONFIG (needed on Windows)."""
    cfg = tmp_path / "custom.toml"
    cfg.write_text(
        '[general]\nmode = "dry_run"\n'
        f'[storage]\nsqlite_path = "{(tmp_path / "x.db").as_posix()}"\n'
        '[respond]\nbackend = "windows_firewall"\n'
    )
    monkeypatch.setenv("CYPHER_CONFIG", str(cfg))
    app = create_app()
    assert app.state.settings.respond.backend == "windows_firewall"
