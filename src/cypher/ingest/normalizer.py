"""Final cleanup pass applied to every Event before it enters the queue.

Parsers focus on extraction; this module enforces the invariants the rest
of the pipeline relies on — valid IPs, non-empty messages, sane timestamps.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

from cypher.models import Event

_MAX_CLOCK_SKEW = timedelta(minutes=10)


def normalize(event: Event) -> Event | None:
    """Return a cleaned Event, or None if the event should be dropped."""
    if event.src_ip:
        event.src_ip = _validate_ip(event.src_ip)

    if not _sane_timestamp(event.timestamp):
        event.timestamp = datetime.now(timezone.utc)

    if not event.message:
        return None

    return event


def _validate_ip(ip_str: str) -> str | None:
    # Strip IPv6-mapped-IPv4 prefix some tools emit, e.g. "::ffff:10.0.0.5"
    candidate = ip_str.replace("::ffff:", "") if ip_str.startswith("::ffff:") else ip_str
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return None


def _sane_timestamp(ts: datetime) -> bool:
    now = datetime.now(ts.tzinfo) if ts.tzinfo else datetime.now()
    return abs(now - ts) < timedelta(days=3650)  # reject obviously broken parses
