"""Common interface every firewall backend implements.

Backends only ever run commands that were already approved by
respond/safety.py — a backend itself performs no allowlist or rate-limit
checks, it just executes (or, in dry-run wrappers, logs) the OS command.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class FirewallBackend(ABC):
    name: str = "base"

    @abstractmethod
    def block(self, ip: str) -> tuple[bool, str]:
        """Block an IP. Returns (success, message)."""
        raise NotImplementedError

    @abstractmethod
    def unblock(self, ip: str) -> tuple[bool, str]:
        """Remove a block for an IP. Returns (success, message)."""
        raise NotImplementedError

    @abstractmethod
    def list_blocked(self) -> list[str]:
        """Return IPs currently blocked according to the backend itself
        (used to reconcile against our own DB state)."""
        raise NotImplementedError
