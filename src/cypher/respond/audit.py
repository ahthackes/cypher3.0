"""Thin wrapper so respond/* modules don't import cypher.storage.db
directly — keeps the root-privileged responder's dependency surface
small and makes it obvious, at a glance, that every action it takes is
logged.
"""
from __future__ import annotations

from cypher.storage.db import Database


class AuditLogger:
    def __init__(self, db: Database):
        self._db = db

    def log(self, actor: str, action: str, detail: str = "") -> None:
        self._db.audit(actor=actor, action=action, detail=detail)
