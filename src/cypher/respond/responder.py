"""The responder: a small daemon that runs with elevated privileges
(root via deploy/systemd/cypher-responder.service on Linux, an
Administrator-level service/scheduled task via deploy/windows/ on
Windows) and is the ONLY process in the whole system that executes
firewall commands.

Everything else — ingestion, detection, the API, the dashboard — runs
unprivileged and talks to this daemon over a loopback TCP socket
(127.0.0.1:respond.ipc_port) with a tiny JSON-lines protocol:

    request:  {"token": "...", "action": "block", "ip": "1.2.3.4", "reason": "...", "alert_id": "..."}
    response: {"ok": true, "action": "block", "message": "blocked 1.2.3.4 via nftables"}

A loopback TCP socket (rather than a Unix domain socket) is what makes
this one piece of code work unchanged on both Linux and Windows —
Windows has no Unix-socket equivalent that's simple to use from Python.
The tradeoff is that any local process can open a TCP connection to
127.0.0.1:ipc_port, so the `token` field (see respond/ipc_token.py)
stands in for the Unix-socket group-permission check: a request missing
or mismatching the token is rejected before `ResponderService` ever sees
it. Every request that gets that far still passes through
respond/safety.py — the responder does NOT trust that the caller already
applied the safety checks; it always re-checks itself.
"""
from __future__ import annotations

import json
import logging
import socketserver
import threading
from datetime import datetime, timedelta
from pathlib import Path

from cypher.models import Block, BlockAction
from cypher.respond.audit import AuditLogger
from cypher.respond.backends import get_backend
from cypher.respond.ipc_token import get_or_create_token
from cypher.respond.safety import evaluate, load_allowlist
from cypher.settings import Settings
from cypher.storage.db import Database

logger = logging.getLogger("cypher.respond.responder")


class ResponderService:
    """The core logic, separated from the socket-server plumbing so it
    can be unit-tested by calling handle_request() directly."""

    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db
        self.backend = get_backend(settings.respond.backend)
        self.audit = AuditLogger(db)
        self.allowlist = load_allowlist(settings.respond.allowlist_file)
        # One request handler thread per connection plus the expiry sweeper all
        # share one SQLite connection and one firewall; serialise them.
        self._lock = threading.RLock()

    def handle_request(self, request: dict) -> dict:
        with self._lock:
            return self._dispatch(request)

    def _dispatch(self, request: dict) -> dict:
        action = request.get("action")
        ip = request.get("ip", "")
        reason = request.get("reason", "")
        alert_id = request.get("alert_id")
        actor = request.get("actor", "system")

        if action == "block":
            return self._handle_block(ip, reason, alert_id, actor)
        if action == "unblock":
            return self._handle_unblock(ip, reason, actor)
        if action == "status":
            return {"ok": True, "active_blocks": [dict(r) for r in self.db.active_blocks()]}
        return {"ok": False, "message": f"unknown action '{action}'"}

    def _handle_block(self, ip: str, reason: str, alert_id: str | None, actor: str) -> dict:
        # An attacker keeps producing events (and alerts) while blocked, or
        # right before the block lands. Re-issuing the firewall command each
        # time would stack duplicate rules (iptables, Windows Firewall) and
        # burn the hourly rate limit, so already-blocked IPs are a no-op.
        if any(row["src_ip"] == ip for row in self.db.active_blocks()):
            return {"ok": True, "action": "already_blocked",
                    "message": f"{ip} is already blocked"}

        decision = evaluate(
            ip,
            is_dry_run=self.settings.is_dry_run,
            allowlist_networks=self.allowlist,
            blocks_in_last_hour=self.db.blocks_in_last_hour(),
            max_blocks_per_hour=self.settings.respond.max_blocks_per_hour,
        )

        if not decision.allowed:
            self._record_block(ip, decision.action, reason=decision.reason,
                                alert_id=alert_id, actor=actor, ttl=None)
            self.audit.log(actor, f"block_{decision.action.value}", f"{ip}: {decision.reason}")
            return {"ok": True, "action": decision.action.value, "message": decision.reason}

        success, message = self.backend.block(ip)
        if not success:
            self.audit.log(actor, "block_failed", f"{ip}: {message}")
            return {"ok": False, "action": "block_failed", "message": message}

        ttl = self.settings.respond.block_ttl_seconds
        self._record_block(ip, BlockAction.BLOCK, reason=reason, alert_id=alert_id,
                            actor=actor, ttl=ttl)
        self.audit.log(actor, "block", f"{ip}: {reason} (backend={self.backend.name})")
        return {"ok": True, "action": "block", "message": message}

    def _handle_unblock(self, ip: str, reason: str, actor: str) -> dict:
        success, message = self.backend.unblock(ip)
        block = Block(
            src_ip=ip, action=BlockAction.UNBLOCK, reason=reason,
            backend=self.backend.name, actor=actor,
        )
        self.db.insert_block(block)
        self.audit.log(actor, "unblock", f"{ip}: {reason}")
        return {"ok": success, "action": "unblock", "message": message}

    def _record_block(self, ip, action, *, reason, alert_id, actor, ttl) -> None:
        expires_at = datetime.now() + timedelta(seconds=ttl) if ttl else None
        block = Block(
            src_ip=ip, action=action, reason=reason, alert_id=alert_id,
            ttl_seconds=ttl, expires_at=expires_at, backend=self.backend.name, actor=actor,
        )
        self.db.insert_block(block)

    def expire_stale_blocks(self, now: datetime | None = None) -> int:
        """Release every IP whose block TTL has passed; returns how many.
        Idempotent: once released an IP's latest action is UNBLOCK, so it is
        not returned by Database.expired_blocks() again."""
        with self._lock:
            released = 0
            for row in self.db.expired_blocks(now):
                self._handle_unblock(row["src_ip"], "ttl expired", "system")
                released += 1
            return released


def _expiry_loop(service: "ResponderService", interval: float, stop: threading.Event) -> None:
    while not stop.wait(interval):
        try:
            n = service.expire_stale_blocks()
            if n:
                logger.info("Released %d expired block(s)", n)
        except Exception:  # noqa: BLE001 - a failed sweep must not kill the sweeper
            logger.exception("Error while expiring blocks")


class _RequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        service: ResponderService = self.server.service  # type: ignore[attr-defined]
        expected_token: str = self.server.token  # type: ignore[attr-defined]
        line = self.rfile.readline()
        if not line:
            return
        try:
            request = json.loads(line.decode("utf-8"))
            if request.get("token") != expected_token:
                logger.warning("Rejected responder request with missing/invalid token")
                response = {"ok": False, "message": "invalid or missing token"}
            else:
                request.pop("token", None)
                response = service.handle_request(request)
        except Exception as exc:  # noqa: BLE001 — never let a bad request kill the daemon
            logger.exception("Error handling responder request")
            response = {"ok": False, "message": str(exc)}
        self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))


class _LoopbackTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def run_responder(settings: Settings, db: Database) -> None:
    """Starts the loopback TCP server. Blocks forever — run this as the
    entry point of the cypher-responder service (systemd on Linux, a
    Windows service/scheduled task on Windows — see deploy/)."""
    token = get_or_create_token(settings.respond.ipc_token_file)

    server = _LoopbackTCPServer((settings.respond.ipc_host, settings.respond.ipc_port), _RequestHandler)
    service = ResponderService(settings, db)
    server.service = service  # type: ignore[attr-defined]
    server.token = token  # type: ignore[attr-defined]

    stop_sweeper = threading.Event()
    threading.Thread(
        target=_expiry_loop,
        args=(service, settings.respond.expiry_check_seconds, stop_sweeper),
        daemon=True, name="cypher-block-expiry",
    ).start()

    logger.info("Responder listening on %s:%d (mode=%s, backend=%s)",
                settings.respond.ipc_host, settings.respond.ipc_port,
                settings.general.mode, settings.respond.backend)
    try:
        server.serve_forever()
    finally:
        stop_sweeper.set()
        server.server_close()
