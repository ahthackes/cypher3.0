"""nftables backend — maintains a dedicated "cypher" table/set so our
rules never collide with the rest of the system's firewall config.

Requires: the nftables package installed, and the process running this
(the root-level responder, never the API) to have CAP_NET_ADMIN.

Design: we manage one named set, `cypher_blocklist`, and a single rule
that drops anything in it. Adding/removing an IP is then just a set
element add/delete — cheap and doesn't require touching rule ordering.
"""
from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable

from cypher.respond.backends.base import FirewallBackend

logger = logging.getLogger("cypher.respond.backends.nftables")

_TABLE = "inet cypher_filter"
_SET_NAME = "cypher_blocklist"

_SETUP_COMMANDS = [
    ["nft", "add", "table", "inet", "cypher_filter"],
    ["nft", "add", "set", "inet", "cypher_filter", _SET_NAME, "{ type ipv4_addr; }"],
    ["nft", "add", "chain", "inet", "cypher_filter", "input",
     "{ type filter hook input priority 0; }"],
    ["nft", "add", "rule", "inet", "cypher_filter", "input",
     "ip", "saddr", f"@{_SET_NAME}", "drop"],
]

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess]


def _default_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=5)


class NftablesBackend(FirewallBackend):
    name = "nftables"

    def __init__(self, runner: CommandRunner = _default_runner):
        self._run = runner

    def ensure_setup(self) -> None:
        for cmd in _SETUP_COMMANDS:
            result = self._run(cmd)
            # "File exists" errors are expected on every call after the first —
            # the table/set/chain already exists. Anything else is logged.
            if result.returncode != 0 and "File exists" not in (result.stderr or ""):
                logger.warning("nft setup command %s: %s", cmd, result.stderr)

    def block(self, ip: str) -> tuple[bool, str]:
        self.ensure_setup()
        result = self._run(
            ["nft", "add", "element", "inet", "cypher_filter", _SET_NAME, "{", ip, "}"]
        )
        if result.returncode == 0:
            return True, f"blocked {ip} via nftables"
        return False, result.stderr or "unknown nft error"

    def unblock(self, ip: str) -> tuple[bool, str]:
        result = self._run(
            ["nft", "delete", "element", "inet", "cypher_filter", _SET_NAME, "{", ip, "}"]
        )
        if result.returncode == 0:
            return True, f"unblocked {ip} via nftables"
        return False, result.stderr or "unknown nft error"

    def list_blocked(self) -> list[str]:
        result = self._run(["nft", "-j", "list", "set", "inet", "cypher_filter", _SET_NAME])
        if result.returncode != 0:
            return []
        import json
        try:
            data = json.loads(result.stdout)
        except (ValueError, TypeError):
            return []
        ips: list[str] = []
        for item in data.get("nftables", []):
            elem = item.get("set", {}).get("elem", [])
            for e in elem:
                ips.append(e if isinstance(e, str) else e.get("elem", {}).get("val", ""))
        return [ip for ip in ips if ip]
