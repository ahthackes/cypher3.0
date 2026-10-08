"""A sliding-window counter keyed by an arbitrary string (usually src_ip).

Both the rule engine ("5 failed logins in 5 minutes") and the ML feature
pipeline ("requests per minute per IP") need the same primitive: how many
matching events has this key produced in the last N seconds? This class
is the single implementation both depend on, so behavior stays consistent.

Implementation: a dict of key -> deque of timestamps. O(1) amortized
insert, and old entries are pruned lazily on read rather than by a
background sweep, which keeps this safe to call from the hot path.
"""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta


class SlidingWindowCounter:
    def __init__(self):
        self._events: dict[str, deque[datetime]] = defaultdict(deque)

    def add(self, key: str, timestamp: datetime) -> None:
        self._events[key].append(timestamp)

    def count(self, key: str, window_seconds: int, now: datetime | None = None) -> int:
        """Return how many events for `key` fall within the last window_seconds."""
        now = now or datetime.now(tz=self._events_tz(key))
        cutoff = now - timedelta(seconds=window_seconds)
        dq = self._events.get(key)
        if not dq:
            return 0
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def _events_tz(self, key: str):
        dq = self._events.get(key)
        if dq:
            return dq[0].tzinfo
        return None

    def active_keys(self) -> list[str]:
        return [k for k, dq in self._events.items() if dq]

    def prune_all(self, window_seconds: int, now: datetime | None = None) -> None:
        """Drop stale entries for every key — call periodically to bound memory."""
        for key in list(self._events.keys()):
            self.count(key, window_seconds, now)
            if not self._events[key]:
                del self._events[key]
