"""WebSocket endpoint that pushes new alerts to connected dashboard
clients as they're written to the database, instead of making the
browser poll.

Implementation: a lightweight poll-and-diff against the DB every second
rather than a pub/sub bus — this is a single-admin local tool, so the
simplicity is worth more than the (nonexistent) scale this would need to
matter for.
"""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()


@router.websocket("/ws/live")
async def live_feed(websocket: WebSocket):
    await websocket.accept()
    db = websocket.app.state.db
    last_seen_id: str | None = None
    try:
        while True:
            rows = db.recent_alerts(limit=5)
            new_rows = []
            for r in rows:
                if r["id"] == last_seen_id:
                    break
                new_rows.append(r)
            if new_rows:
                last_seen_id = rows[0]["id"]
                for r in reversed(new_rows):
                    await websocket.send_text(json.dumps({
                        "id": r["id"], "timestamp": r["timestamp"], "src_ip": r["src_ip"],
                        "score": r["score"], "severity": r["severity"],
                        "explanation": r["explanation"],
                    }))
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass
