"""Parses Windows Security Event Log records (rendered as XML) into Events.

Unlike the Linux parsers, the "line" here is one complete event XML
document, as produced by `Get-WinEvent ... | % ToXml()`, `wevtutil qe
Security /f:xml`, or pywin32's EvtRender. Keeping the parser a pure
function of that XML string (no Windows API calls inside it) is what
lets it be unit-tested on any OS with fixture files.

Event IDs handled, and how they map onto Cypher's cross-platform
EventType vocabulary:

  4625  failed logon              -> AUTH_FAILURE   (service "rdp" if LogonType 10, else "windows_logon")
  4624  successful logon          -> AUTH_SUCCESS
  4740  account locked out        -> AUTH_FAILURE   (raw["lockout"] = True)
  4672  special privileges        -> PRIV_ESCALATION_SUCCESS, only for ordinary
                                     user accounts (SYSTEM / service / machine
                                     accounts log this constantly and are noise)
  4732  member added to local group -> PRIV_ESCALATION_SUCCESS, only when the
                                     group is Administrators

Anything else returns None. Windows has no `sudo`, so "privilege
escalation" here means the nearest real equivalents: sensitive-privilege
logons and additions to the local Administrators group.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime

from cypher.ingest.parsers.base import BaseParser
from cypher.models import Event, EventType

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_IGNORED_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-"}
_RDP_LOGON_TYPE = "10"


def _parse_system_time(raw: str) -> datetime:
    # e.g. "2026-10-08T13:55:01.1234567Z" — Windows emits 7 fractional
    # digits, Python's fromisoformat wants at most 6 (and no trailing Z
    # on older versions), so trim and normalise.
    raw = raw.rstrip("Z")
    if "." in raw:
        base, frac = raw.split(".", 1)
        raw = f"{base}.{frac[:6]}"
    dt = datetime.fromisoformat(raw + "+00:00")
    # Convert to naive local time to match what the Linux parsers produce,
    # so mixed-source windows/vectorizer math never compares aware vs naive.
    return dt.astimezone().replace(tzinfo=None)


def _event_data(root: ET.Element) -> dict[str, str]:
    data: dict[str, str] = {}
    for d in root.findall("e:EventData/e:Data", _NS):
        name = d.get("Name")
        if name:
            data[name] = (d.text or "").strip()
    return data


def _clean_ip(value: str | None) -> str | None:
    if not value or value in ("-", "::1", "127.0.0.1"):
        return None
    return value


class WindowsSecurityParser(BaseParser):
    name = "windows_security"

    def parse_line(self, line: str) -> Event | None:
        xml_text = line.strip()
        if not xml_text:
            return None
        # Event Log XML never legitimately contains a DTD. Refuse any that
        # does, rather than hand attacker-influenced text to an XML parser
        # that might expand entities.
        if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
            return None
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None

        event_id_el = root.find("e:System/e:EventID", _NS)
        if event_id_el is None or not event_id_el.text:
            return None
        event_id = event_id_el.text.strip()

        time_el = root.find("e:System/e:TimeCreated", _NS)
        try:
            ts = _parse_system_time(time_el.get("SystemTime")) if time_el is not None else datetime.now()
        except (ValueError, TypeError):
            ts = datetime.now()

        data = _event_data(root)

        if event_id == "4625":
            return self._failed_logon(data, ts)
        if event_id == "4624":
            return self._successful_logon(data, ts)
        if event_id == "4740":
            return self._lockout(data, ts)
        if event_id == "4672":
            return self._special_privileges(data, ts)
        if event_id == "4732":
            return self._admin_group_add(data, ts)
        return None

    @staticmethod
    def _failed_logon(data: dict, ts: datetime) -> Event:
        logon_type = data.get("LogonType", "")
        service = "rdp" if logon_type == _RDP_LOGON_TYPE else "windows_logon"
        user = data.get("TargetUserName") or None
        ip = _clean_ip(data.get("IpAddress"))
        return Event(
            timestamp=ts, source="windows-security", service=service,
            event_type=EventType.AUTH_FAILURE, src_ip=ip, user=user,
            message=f"Windows Security 4625: failed logon for '{user}' from {ip or 'local'} (LogonType {logon_type})",
            raw={"event_id": 4625, "logon_type": logon_type,
                 "status": data.get("Status", ""), "sub_status": data.get("SubStatus", "")},
        )

    @staticmethod
    def _successful_logon(data: dict, ts: datetime) -> Event:
        logon_type = data.get("LogonType", "")
        service = "rdp" if logon_type == _RDP_LOGON_TYPE else "windows_logon"
        user = data.get("TargetUserName") or None
        ip = _clean_ip(data.get("IpAddress"))
        return Event(
            timestamp=ts, source="windows-security", service=service,
            event_type=EventType.AUTH_SUCCESS, src_ip=ip, user=user,
            message=f"Windows Security 4624: successful logon for '{user}' from {ip or 'local'} (LogonType {logon_type})",
            raw={"event_id": 4624, "logon_type": logon_type},
        )

    @staticmethod
    def _lockout(data: dict, ts: datetime) -> Event:
        user = data.get("TargetUserName") or None
        return Event(
            timestamp=ts, source="windows-security", service="windows_logon",
            event_type=EventType.AUTH_FAILURE, user=user,
            message=f"Windows Security 4740: account '{user}' was locked out",
            raw={"event_id": 4740, "lockout": True,
                 "caller_computer": data.get("TargetDomainName", "")},
        )

    @staticmethod
    def _special_privileges(data: dict, ts: datetime) -> Event | None:
        user = data.get("SubjectUserName") or ""
        if user.upper() in _IGNORED_ACCOUNTS or user.endswith("$"):
            return None
        return Event(
            timestamp=ts, source="windows-security", service="windows_privilege",
            event_type=EventType.PRIV_ESCALATION_SUCCESS, user=user,
            message=f"Windows Security 4672: special privileges assigned to '{user}'",
            raw={"event_id": 4672, "privileges": data.get("PrivilegeList", "")},
        )

    @staticmethod
    def _admin_group_add(data: dict, ts: datetime) -> Event | None:
        group = data.get("TargetUserName") or ""
        if group.lower() != "administrators":
            return None
        added = data.get("MemberSid") or data.get("MemberName") or "unknown"
        actor = data.get("SubjectUserName") or None
        return Event(
            timestamp=ts, source="windows-security", service="windows_privilege",
            event_type=EventType.PRIV_ESCALATION_SUCCESS, user=actor,
            message=f"Windows Security 4732: {added} added to local Administrators group by '{actor}'",
            raw={"event_id": 4732, "admin_group_add": True, "member": added},
        )
