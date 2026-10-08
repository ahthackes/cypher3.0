"""SQLite storage layer, in WAL mode for safe concurrent read/write between
the ingestion process and the API process.

Every write goes through here — no other module opens the database file
directly. This keeps the schema and locking behavior in one place.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from cypher.models import Alert, Block, Event

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def _init_schema(self) -> None:
        with open(_SCHEMA_PATH) as f:
            self.conn.executescript(f.read())
        self.conn.commit()

    # -- events --------------------------------------------------------

    def insert_event(self, event: Event) -> None:
        self.conn.execute(
            """INSERT OR IGNORE INTO events
               (id, timestamp, source, service, event_type, src_ip, user,
                http_status, path, message, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.id, event.timestamp.isoformat(), event.source, event.service,
                event.event_type.value, event.src_ip, event.user, event.http_status,
                event.path, event.message, json.dumps(event.raw),
            ),
        )
        self.conn.commit()

    def recent_events(self, limit: int = 100) -> list[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return cur.fetchall()

    # -- alerts ----------------------------------------------------------

    def insert_alert(self, alert: Alert) -> None:
        self.conn.execute(
            """INSERT OR IGNORE INTO alerts
               (id, timestamp, src_ip, score, severity, rule_hits_json, ml_score,
                mitre_techniques_json, contributing_event_ids, explanation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.id, alert.timestamp.isoformat(), alert.src_ip, alert.score,
                alert.severity.value, json.dumps(alert.rule_hits), alert.ml_score,
                json.dumps(alert.mitre_techniques), json.dumps(alert.contributing_event_ids),
                alert.explanation,
            ),
        )
        self.conn.commit()

    def recent_alerts(self, limit: int = 100) -> list[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return cur.fetchall()

    # -- blocks ------------------------------------------------------------

    def insert_block(self, block: Block) -> None:
        self.conn.execute(
            """INSERT OR IGNORE INTO blocks
               (id, timestamp, src_ip, action, alert_id, reason, ttl_seconds,
                expires_at, backend, actor)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                block.id, block.timestamp.isoformat(), block.src_ip, block.action.value,
                block.alert_id, block.reason, block.ttl_seconds,
                block.expires_at.isoformat() if block.expires_at else None,
                block.backend, block.actor,
            ),
        )
        self.conn.commit()

    def active_blocks(self, now: datetime | None = None) -> list[sqlite3.Row]:
        """IPs that are currently blocked (latest action is BLOCK and unexpired)."""
        cur = self.conn.execute(
            """SELECT b1.* FROM blocks b1
               INNER JOIN (
                   SELECT src_ip, MAX(timestamp) AS max_ts FROM blocks GROUP BY src_ip
               ) b2 ON b1.src_ip = b2.src_ip AND b1.timestamp = b2.max_ts
               WHERE b1.action = 'block'"""
        )
        rows = cur.fetchall()
        now = now or datetime.now()
        active = []
        for row in rows:
            if row["expires_at"] is None:
                active.append(row)
                continue
            expires = datetime.fromisoformat(row["expires_at"])
            if expires.tzinfo:
                expires = expires.replace(tzinfo=None)
            if expires > now:
                active.append(row)
        return active

    def expired_blocks(self, now: datetime | None = None) -> list[sqlite3.Row]:
        """IPs whose most recent action is a BLOCK whose TTL has passed — i.e.
        still blocked in the firewall but due to be released. An IP that was
        already unblocked (latest action UNBLOCK) is never returned, which is
        what keeps repeated sweeps from re-unblocking the same address."""
        cur = self.conn.execute(
            """SELECT b1.* FROM blocks b1
               INNER JOIN (
                   SELECT src_ip, MAX(timestamp) AS max_ts FROM blocks GROUP BY src_ip
               ) b2 ON b1.src_ip = b2.src_ip AND b1.timestamp = b2.max_ts
               WHERE b1.action = 'block' AND b1.expires_at IS NOT NULL"""
        )
        now = now or datetime.now()
        expired = []
        for row in cur.fetchall():
            expires = datetime.fromisoformat(row["expires_at"])
            if expires.tzinfo:
                expires = expires.replace(tzinfo=None)
            if expires <= now:
                expired.append(row)
        return expired

    def recent_blocks(self, limit: int = 100) -> list[sqlite3.Row]:
        cur = self.conn.execute(
            "SELECT * FROM blocks ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return cur.fetchall()

    def blocks_in_last_hour(self) -> int:
        cur = self.conn.execute(
            """SELECT COUNT(*) AS n FROM blocks
               WHERE action = 'block' AND timestamp > datetime('now', '-1 hour')"""
        )
        return cur.fetchone()["n"]

    # -- audit log -----------------------------------------------------

    def audit(self, actor: str, action: str, detail: str = "") -> None:
        import uuid
        self.conn.execute(
            "INSERT INTO audit_log (id, timestamp, actor, action, detail) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), datetime.now().isoformat(), actor, action, detail),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
