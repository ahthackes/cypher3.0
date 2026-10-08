#!/usr/bin/env python3
"""Writes a synthetic Windows Security Event Log export (event XML, one
<Event> after another) for demos and testing — the Windows counterpart of
simulate_attacks.sh. It writes a FILE only; no real logon is attempted
and no Event Log is touched.

Contents: a few ordinary logons, an RDP brute-force burst from a
TEST-NET-3 address (203.0.113.77, RFC 5737 — not a real host), an
account lockout, and someone being added to the local Administrators
group.

Usage:
    python scripts/generate_windows_demo.py --out data/raw/windows_attack_demo.xml
    cypher --config config/cypher.windows.toml replay data/raw/windows_attack_demo.xml --source-type windows_security_log
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
ATTACKER = "203.0.113.77"


def make_event(event_id: int, record_id: int, ts: datetime, data: dict[str, str]) -> str:
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}0Z"
    items = "".join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in data.items())
    return (
        f'<Event xmlns="{NS}"><System>'
        f'<Provider Name="Microsoft-Windows-Security-Auditing"/>'
        f"<EventID>{event_id}</EventID><TimeCreated SystemTime=\"{stamp}\"/>"
        f"<EventRecordID>{record_id}</EventRecordID>"
        f"<Channel>Security</Channel><Computer>WIN-LAB</Computer></System>"
        f"<EventData>{items}</EventData></Event>"
    )


def build(start: datetime) -> list[str]:
    events: list[str] = []
    rid = 1000
    ts = start

    def add(event_id: int, data: dict[str, str], step: float = 2.0) -> None:
        nonlocal rid, ts
        ts += timedelta(seconds=step)
        rid += 1
        events.append(make_event(event_id, rid, ts, data))

    # Ordinary activity
    for _ in range(3):
        add(4624, {"TargetUserName": "ahtsham", "LogonType": "2", "IpAddress": "-"}, step=30)
    add(4672, {"SubjectUserName": "ahtsham", "PrivilegeList": "SeDebugPrivilege"}, step=5)

    # RDP brute force: 15 failures in ~30 seconds
    for _ in range(15):
        add(4625, {"TargetUserName": "administrator", "LogonType": "10",
                   "IpAddress": ATTACKER, "Status": "0xc000006d", "SubStatus": "0xc000006a"})

    # Lockout and a privilege change
    add(4740, {"TargetUserName": "administrator", "TargetDomainName": "WIN-LAB"}, step=5)
    add(4732, {"TargetUserName": "Administrators", "MemberSid": "S-1-5-21-1111-2222-3333-1005",
               "SubjectUserName": "backdoor_user"}, step=10)
    return events


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/raw/windows_attack_demo.xml")
    args = ap.parse_args()
    events = build(datetime.now(timezone.utc) - timedelta(minutes=10))
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(events) + "\n")
    print(f"Wrote {len(events)} synthetic Windows Security events to {args.out}")
