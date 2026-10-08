from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request

from cypher.api.auth import require_login
from cypher.api.schemas import HealthOut
from cypher.detect.ml.registry import ModelRegistry

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz():
    """Unauthenticated liveness probe — for systemd/monitoring, not the dashboard."""
    return {"status": "ok"}


@router.get("/api/health", response_model=HealthOut)
def health(request: Request, _user: str = Depends(require_login)):
    settings = request.app.state.settings
    registry = ModelRegistry(settings.ml.model_dir)
    meta = registry.latest("isolation_forest")
    return HealthOut(
        mode=settings.general.mode,
        backend=settings.respond.backend,
        model_loaded=meta is not None,
        model_trained_at=meta.trained_at if meta else None,
    )
