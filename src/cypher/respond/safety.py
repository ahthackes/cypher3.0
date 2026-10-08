"""The safety gate every block request must pass through before it
reaches a firewall backend.

This is deliberately the most conservative module in the codebase — its
only job is to say no. Three independent checks, all of which must pass:

1. Allowlist — never block an IP in config/allowlist.toml, no matter the
   score. This is what stops you from locking yourself out of your own VM.
2. Dry run — if general.mode != "active", log what WOULD happen and stop.
3. Rate limit — no more than respond.max_blocks_per_hour real blocks,
   so a misconfigured rule or a feedback loop can't fire hundreds of
   iptables/nftables rules in minutes.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

import toml

from cypher.models import BlockAction


@dataclass
class SafetyDecision:
    allowed: bool
    action: BlockAction
    reason: str


def load_allowlist(path: str | Path) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    p = Path(path)
    if not p.exists():
        return []
    data = toml.load(p)
    cidrs = data.get("allowlist", {}).get("cidrs", [])
    networks = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


def is_allowlisted(ip: str, networks: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable IP -> refuse to act on it, fail safe
    return any(addr in net for net in networks)


def evaluate(
    ip: str,
    *,
    is_dry_run: bool,
    allowlist_networks: list,
    blocks_in_last_hour: int,
    max_blocks_per_hour: int,
) -> SafetyDecision:
    """Run all three checks in order and return the first failure, or an
    approval to proceed."""
    if is_allowlisted(ip, allowlist_networks):
        return SafetyDecision(False, BlockAction.ALLOWLISTED, f"{ip} is in the allowlist")

    if blocks_in_last_hour >= max_blocks_per_hour:
        return SafetyDecision(
            False, BlockAction.RATE_LIMITED,
            f"{blocks_in_last_hour} blocks already this hour (limit {max_blocks_per_hour})",
        )

    if is_dry_run:
        return SafetyDecision(
            False, BlockAction.DRY_RUN_SKIPPED,
            f"dry_run mode — would have blocked {ip}",
        )

    return SafetyDecision(True, BlockAction.BLOCK, "passed all safety checks")
