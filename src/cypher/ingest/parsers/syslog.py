"""Parses generic /var/log/syslog lines into low-priority system Events.

Most syslog lines aren't security-relevant; this parser only keeps ones
that mention kernel firewall drops, service crashes, or other events
useful as weak signals for the ML feature pipeline. Everything else is
dropped (returns None) so we don't flood storage with noise.
"""
from __future__ import annotations

import re
from datetime import datetime

from cypher.ingest.parsers.base import BaseParser
from cypher.ingest.parsers.auth import _SYSLOG_PREFIX, _parse_syslog_timestamp
from cypher.models import Event, EventType

_KEYWORDS_OF_INTEREST = (
    "oom-killer",
    "segfault",
    "kernel: [UFW BLOCK]",
    "kernel: [nft",
    "systemd",
)


class SyslogParser(BaseParser):
    name = "syslog"

    def parse_line(self, line: str) -> Event | None:
        line = line.rstrip("\n")
        if not line:
            return None

        m = _SYSLOG_PREFIX.match(line)
        if not m:
            return None

        msg = m.group("msg")
        if not any(k in line for k in _KEYWORDS_OF_INTEREST):
            return None

        try:
            ts = _parse_syslog_timestamp(m.group("month"), m.group("day"), m.group("time"))
        except ValueError:
            ts = datetime.now()

        return Event(
            timestamp=ts,
            source="syslog",
            service=m.group("service").lower(),
            event_type=EventType.SYSTEM,
            message=line,
            raw={"matched_keyword": next(k for k in _KEYWORDS_OF_INTEREST if k in line)},
        )
