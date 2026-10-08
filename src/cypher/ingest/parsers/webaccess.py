"""Parses nginx/Apache combined-format access log lines into Events.

Combined log format:
    IP - user [DD/Mon/YYYY:HH:MM:SS +ZZZZ] "METHOD /path HTTP/1.1" status size "referer" "agent"
"""
from __future__ import annotations

import re
from datetime import datetime

from cypher.ingest.parsers.base import BaseParser
from cypher.models import Event, EventType

_COMBINED_LOG = re.compile(
    r'^(?P<ip>[\d.:a-fA-F]+)\s+\S+\s+\S+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

_TS_FORMAT = "%d/%b/%Y:%H:%M:%S"


def _parse_ts(raw: str) -> datetime:
    # raw looks like "10/Oct/2026:13:55:36 +0000" — strip the timezone offset.
    core = raw.split(" ")[0]
    try:
        return datetime.strptime(core, _TS_FORMAT)
    except ValueError:
        return datetime.now()


class WebAccessParser(BaseParser):
    name = "webaccess"

    def parse_line(self, line: str) -> Event | None:
        line = line.rstrip("\n")
        if not line:
            return None

        m = _COMBINED_LOG.match(line)
        if not m:
            return None

        status = int(m.group("status"))
        if status in (401, 403):
            event_type = EventType.HTTP_DENIED
        elif status == 404:
            event_type = EventType.HTTP_NOTFOUND
        else:
            event_type = EventType.HTTP_REQUEST

        return Event(
            timestamp=_parse_ts(m.group("ts")),
            source="nginx-access",
            service="nginx",
            event_type=event_type,
            src_ip=m.group("ip"),
            http_status=status,
            path=m.group("path"),
            message=line,
            raw={
                "method": m.group("method"),
                "agent": m.group("agent") or "",
            },
        )
