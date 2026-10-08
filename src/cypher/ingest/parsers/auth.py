"""Parses Linux auth.log lines (sshd, sudo, su) into Events.

Handles the standard syslog-style prefix:
    "Mon DD HH:MM:SS hostname service[pid]: message"
and extracts IPs, usernames, and outcomes from the message body with
per-service regexes. Unrecognized lines return None rather than raising,
so a malformed or unexpected line never crashes the tailer.
"""
from __future__ import annotations

import re
from datetime import datetime

from cypher.ingest.parsers.base import BaseParser
from cypher.models import Event, EventType

_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>[\w.\-/]+?)(\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

_SSH_FAILED_PASSWORD = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
_SSH_ACCEPTED = re.compile(
    r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
_SSH_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
_SUDO_FAILURE = re.compile(
    r"pam_unix\(sudo:auth\): authentication failure.*ruser=(?P<user>\S+)?"
)
_SUDO_NOT_IN_SUDOERS = re.compile(
    r"(?P<user>\S+) is not in the sudoers file"
)
_SUDO_SUCCESS = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*TTY=.*COMMAND="
)


def _parse_syslog_timestamp(month: str, day: str, time_str: str, year: int | None = None) -> datetime:
    year = year or datetime.now().year
    dt = datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
    return dt


class AuthLogParser(BaseParser):
    name = "auth"

    def parse_line(self, line: str) -> Event | None:
        line = line.rstrip("\n")
        if not line:
            return None

        m = _SYSLOG_PREFIX.match(line)
        if not m:
            return None

        service = m.group("service").lower()
        msg = m.group("msg")
        try:
            ts = _parse_syslog_timestamp(m.group("month"), m.group("day"), m.group("time"))
        except ValueError:
            ts = datetime.now()

        if "sshd" in service:
            return self._parse_sshd(msg, ts, line)
        if service in ("sudo", "su"):
            return self._parse_sudo(msg, ts, line, service)
        return None

    def _parse_sshd(self, msg: str, ts: datetime, raw_line: str) -> Event | None:
        if (m := _SSH_FAILED_PASSWORD.search(msg)):
            return Event(
                timestamp=ts,
                source="auth.log",
                service="sshd",
                event_type=EventType.AUTH_FAILURE,
                src_ip=m.group("ip"),
                user=m.group("user"),
                message=raw_line,
            )
        if (m := _SSH_INVALID_USER.search(msg)):
            return Event(
                timestamp=ts,
                source="auth.log",
                service="sshd",
                event_type=EventType.AUTH_FAILURE,
                src_ip=m.group("ip"),
                user=m.group("user"),
                message=raw_line,
                raw={"invalid_user": True},
            )
        if (m := _SSH_ACCEPTED.search(msg)):
            return Event(
                timestamp=ts,
                source="auth.log",
                service="sshd",
                event_type=EventType.AUTH_SUCCESS,
                src_ip=m.group("ip"),
                user=m.group("user"),
                message=raw_line,
            )
        return None

    def _parse_sudo(self, msg: str, ts: datetime, raw_line: str, service: str) -> Event | None:
        if (m := _SUDO_NOT_IN_SUDOERS.search(msg)):
            return Event(
                timestamp=ts,
                source="auth.log",
                service=service,
                event_type=EventType.PRIV_ESCALATION_FAILURE,
                user=m.group("user"),
                message=raw_line,
                raw={"not_in_sudoers": True},
            )
        if _SUDO_FAILURE.search(msg):
            m = _SUDO_FAILURE.search(msg)
            user = m.group("user") if m else None
            return Event(
                timestamp=ts,
                source="auth.log",
                service=service,
                event_type=EventType.PRIV_ESCALATION_FAILURE,
                user=user,
                message=raw_line,
            )
        if (m := _SUDO_SUCCESS.search(msg)):
            return Event(
                timestamp=ts,
                source="auth.log",
                service=service,
                event_type=EventType.PRIV_ESCALATION_SUCCESS,
                user=m.group("user"),
                message=raw_line,
            )
        return None
