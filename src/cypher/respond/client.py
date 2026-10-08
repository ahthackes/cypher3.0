"""Client used by the unprivileged API and detection processes to send
block/unblock/status requests to the privileged responder daemon over
its loopback TCP socket. This is the ONLY way the rest of the system
may influence the firewall.

Works identically on Linux and Windows. Every request carries the
shared-secret token from respond.ipc_token_file (see ipc_token.py); the
unprivileged process needs read access to that file, which is what
replaces the Unix-socket "must be in the cypher group" check.
"""
from __future__ import annotations

import json
import socket
from pathlib import Path


class ResponderClient:
    def __init__(self, host: str, port: int, token_file: str, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.token_file = Path(token_file)
        self.timeout = timeout

    @classmethod
    def from_settings(cls, settings) -> "ResponderClient":
        r = settings.respond
        return cls(r.ipc_host, r.ipc_port, r.ipc_token_file)

    def _token(self) -> str:
        # Read fresh each call so a token rotated while we run is picked up.
        return self.token_file.read_text().strip()

    def _send(self, request: dict) -> dict:
        request = {**request, "token": self._token()}
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
            data = sock.makefile().readline()
            return json.loads(data)

    def block(self, ip: str, reason: str, alert_id: str | None = None, actor: str = "system") -> dict:
        return self._send({
            "action": "block", "ip": ip, "reason": reason,
            "alert_id": alert_id, "actor": actor,
        })

    def unblock(self, ip: str, reason: str = "manual override", actor: str = "admin") -> dict:
        return self._send({"action": "unblock", "ip": ip, "reason": reason, "actor": actor})

    def status(self) -> dict:
        return self._send({"action": "status"})
