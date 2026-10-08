"""Windows Firewall backend, via `netsh advfirewall`.

One inbound block rule per IP, named "Cypher Block <ip>" — the fixed
name prefix is how we find and remove only our own rules without ever
touching the rest of the machine's firewall configuration, the same
isolation goal as the dedicated nftables table / iptables chain on
Linux.

Requires the process running this (the responder) to be elevated
(Run as Administrator / a service running as LocalSystem). The command
is always passed to subprocess as an argument list, never a shell
string, and the IP is validated with `ipaddress` first, so a malformed
value can't be used to inject extra netsh arguments.
"""
from __future__ import annotations

import ipaddress
import subprocess
from collections.abc import Callable

from cypher.respond.backends.base import FirewallBackend

_RULE_PREFIX = "Cypher Block "

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess]


def _default_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=10)


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class WindowsFirewallBackend(FirewallBackend):
    name = "windows_firewall"

    def __init__(self, runner: CommandRunner = _default_runner):
        self._run = runner

    def block(self, ip: str) -> tuple[bool, str]:
        if not _valid_ip(ip):
            return False, f"refusing to block invalid IP {ip!r}"
        result = self._run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_RULE_PREFIX}{ip}", "dir=in", "action=block", f"remoteip={ip}",
        ])
        if result.returncode == 0:
            return True, f"blocked {ip} via Windows Firewall"
        return False, (result.stdout or result.stderr or "unknown netsh error").strip()

    def unblock(self, ip: str) -> tuple[bool, str]:
        if not _valid_ip(ip):
            return False, f"refusing to unblock invalid IP {ip!r}"
        result = self._run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={_RULE_PREFIX}{ip}",
        ])
        if result.returncode == 0:
            return True, f"unblocked {ip} via Windows Firewall"
        return False, (result.stdout or result.stderr or "unknown netsh error").strip()

    def list_blocked(self) -> list[str]:
        result = self._run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])
        if result.returncode != 0:
            return []
        ips: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.lower().startswith("rule name:"):
                name = line.split(":", 1)[1].strip()
                if name.startswith(_RULE_PREFIX):
                    candidate = name[len(_RULE_PREFIX):]
                    if _valid_ip(candidate):
                        ips.append(candidate)
        return ips
