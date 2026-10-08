from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query, Request

from cypher.api.auth import require_login
from cypher.api.schemas import AlertOut

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    request: Request,
    limit: int = Query(default=100, le=1000),
    _user: str = Depends(require_login),
):
    db = request.app.state.db
    rows = db.recent_alerts(limit=limit)
    return [
        AlertOut(
            id=r["id"], timestamp=r["timestamp"], src_ip=r["src_ip"], score=r["score"],
            severity=r["severity"], rule_hits=json.loads(r["rule_hits_json"] or "[]"),
            ml_score=r["ml_score"], mitre_techniques=json.loads(r["mitre_techniques_json"] or "[]"),
            explanation=r["explanation"] or "",
        )
        for r in rows
    ]
