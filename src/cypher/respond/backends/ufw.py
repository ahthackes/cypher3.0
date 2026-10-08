"""ufw backend — thinnest wrapper, good for demos and lab VMs where ufw
is already the system's firewall front-end.
"""
from __future__ import annotations

import subprocess
from collections.abc import Callable

from cypher.respond.backends.base import FirewallBackend

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess]


def _default_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=5)


class UfwBackend(FirewallBackend):
    name = "ufw"

    def __init__(self, runner: CommandRunner = _default_runner):
        self._run = runner

    def block(self, ip: str) -> tuple[bool, str]:
        result = self._run(["ufw", "deny", "from", ip])
        if result.returncode == 0:
            return True, f"blocked {ip} via ufw"
        return False, result.stderr or "unknown ufw error"

    def unblock(self, ip: str) -> tuple[bool, str]:
        result = self._run(["ufw", "delete", "deny", "from", ip])
        if result.returncode == 0:
            return True, f"unblocked {ip} via ufw"
        return False, result.stderr or "unknown ufw error"

    def list_blocked(self) -> list[str]:
        result = self._run(["ufw", "status"])
        if result.returncode != 0:
            return []
        ips = []
        for line in result.stdout.splitlines():
            if "DENY" in line and "from" in line:
                ips.append(line.split()[-1])
        return ips
