"""iptables backend, for systems without nftables. Uses a dedicated
CYPHER chain jumped to from INPUT, so rules are easy to find and flush
without touching any other iptables rules on the box.
"""
from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable

from cypher.respond.backends.base import FirewallBackend

logger = logging.getLogger("cypher.respond.backends.iptables")

_CHAIN = "CYPHER"
CommandRunner = Callable[[list[str]], subprocess.CompletedProcess]


def _default_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=5)


class IptablesBackend(FirewallBackend):
    name = "iptables"

    def __init__(self, runner: CommandRunner = _default_runner):
        self._run = runner

    def ensure_setup(self) -> None:
        # Create the chain (ignore "already exists"); link it from INPUT (ignore duplicate).
        self._run(["iptables", "-N", _CHAIN])
        result = self._run(["iptables", "-C", "INPUT", "-j", _CHAIN])
        if result.returncode != 0:
            self._run(["iptables", "-I", "INPUT", "-j", _CHAIN])

    def block(self, ip: str) -> tuple[bool, str]:
        self.ensure_setup()
        result = self._run(["iptables", "-A", _CHAIN, "-s", ip, "-j", "DROP"])
        if result.returncode == 0:
            return True, f"blocked {ip} via iptables"
        return False, result.stderr or "unknown iptables error"

    def unblock(self, ip: str) -> tuple[bool, str]:
        result = self._run(["iptables", "-D", _CHAIN, "-s", ip, "-j", "DROP"])
        if result.returncode == 0:
            return True, f"unblocked {ip} via iptables"
        return False, result.stderr or "unknown iptables error"

    def list_blocked(self) -> list[str]:
        result = self._run(["iptables", "-S", _CHAIN])
        if result.returncode != 0:
            return []
        ips = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if "-s" in parts:
                ips.append(parts[parts.index("-s") + 1].split("/")[0])
        return ips
