from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from cypher.api.auth import require_login
from cypher.api.schemas import EventOut

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=list[EventOut])
def list_events(
    request: Request,
    limit: int = Query(default=100, le=1000),
    _user: str = Depends(require_login),
):
    db = request.app.state.db
    rows = db.recent_events(limit=limit)
    return [
        EventOut(
            id=r["id"], timestamp=r["timestamp"], source=r["source"], service=r["service"],
            event_type=r["event_type"], src_ip=r["src_ip"], user=r["user"],
            http_status=r["http_status"], path=r["path"], message=r["message"],
        )
        for r in rows
    ]
