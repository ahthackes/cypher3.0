"""FastAPI application factory for the Cypher dashboard API.

Runs UNPRIVILEGED (see deploy/systemd/cypher-api.service — no root, no
CAP_NET_ADMIN). It never touches the firewall directly; blocks/unblocks
go through ResponderClient -> the privileged responder daemon's loopback TCP socket.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from cypher.api.auth import create_session_token, hash_password, verify_password
from cypher.api.routes import alerts, blocks, events, health, models
from cypher.api.schemas import LoginRequest
from cypher.api.ws import router as ws_router
from cypher.settings import Settings, load_settings
from cypher.storage.db import Database

_WEB_DIR = Path(__file__).resolve().parents[3] / "web"


def create_app(settings: Settings | None = None) -> FastAPI:
    # `uvicorn --factory` calls this with no arguments, so the config file is
    # chosen via CYPHER_CONFIG (the Windows launcher sets it to
    # config/cypher.windows.toml). Defaults to the Linux config.
    settings = settings or load_settings(os.environ.get("CYPHER_CONFIG", "config/cypher.toml"))
    app = FastAPI(title="Cypher 2.0", version="0.1.0")

    app.state.settings = settings
    app.state.db = Database(settings.storage.sqlite_path)

    app.include_router(events.router)
    app.include_router(alerts.router)
    app.include_router(blocks.router)
    app.include_router(models.router)
    app.include_router(health.router)
    app.include_router(ws_router)

    @app.post("/api/login")
    def login(body: LoginRequest, response: Response):
        admin_hash = os.environ.get("CYPHER_ADMIN_PASSWORD_HASH")
        secret = os.environ.get("CYPHER_SESSION_SECRET")
        if not admin_hash or not secret:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "Admin credentials not configured — see docs/user-guide.md "
                "(set CYPHER_ADMIN_PASSWORD_HASH and CYPHER_SESSION_SECRET)",
            )
        if body.username != "admin" or not verify_password(body.password, admin_hash):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

        token = create_session_token(body.username, secret)
        response.set_cookie(
            "cypher_session", token, httponly=True, samesite="lax",
            secure=False,  # set True once served over HTTPS/behind a reverse proxy
            max_age=8 * 3600,
        )
        return {"ok": True}

    @app.post("/api/logout")
    def logout(response: Response):
        response.delete_cookie("cypher_session")
        return {"ok": True}

    if _WEB_DIR.exists():
        @app.get("/")
        def dashboard_index():
            return FileResponse(_WEB_DIR / "index.html")

        app.mount("/static", StaticFiles(directory=_WEB_DIR), name="static")

    return app


# Hashing helper exported for scripts/set_admin_password.py
__all__ = ["create_app", "hash_password"]
