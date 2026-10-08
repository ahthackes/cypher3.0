from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from cypher.api.auth import require_login
from cypher.api.schemas import BlockOut, BlockRequest
from cypher.respond.client import ResponderClient

router = APIRouter(prefix="/api/blocks", tags=["blocks"])


@router.get("", response_model=list[BlockOut])
def list_blocks(request: Request, _user: str = Depends(require_login)):
    db = request.app.state.db
    rows = db.active_blocks()
    return [
        BlockOut(
            id=r["id"], timestamp=r["timestamp"], src_ip=r["src_ip"], action=r["action"],
            reason=r["reason"], expires_at=r["expires_at"], backend=r["backend"], actor=r["actor"],
        )
        for r in rows
    ]


@router.post("/block")
def manual_block(body: BlockRequest, request: Request, user: str = Depends(require_login)):
    settings = request.app.state.settings
    client = ResponderClient.from_settings(settings)
    try:
        result = client.block(body.ip, reason=body.reason, actor=user)
    except OSError as exc:
        raise HTTPException(503, f"Responder daemon unreachable: {exc}") from exc
    return result


@router.post("/unblock")
def manual_unblock(body: BlockRequest, request: Request, user: str = Depends(require_login)):
    settings = request.app.state.settings
    client = ResponderClient.from_settings(settings)
    try:
        result = client.unblock(body.ip, reason=body.reason, actor=user)
    except OSError as exc:
        raise HTTPException(503, f"Responder daemon unreachable: {exc}") from exc
    return result
