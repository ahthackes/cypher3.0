from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from cypher.api.auth import require_login
from cypher.detect.ml.registry import ModelRegistry

router = APIRouter(prefix="/api/models", tags=["models"])


@router.get("")
def list_models(request: Request, _user: str = Depends(require_login)):
    settings = request.app.state.settings
    registry = ModelRegistry(settings.ml.model_dir)
    return [m.__dict__ for m in registry.all()]
