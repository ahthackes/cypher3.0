"""Builders for synthetic Windows Security Event Log XML, shaped like
`Get-WinEvent ... | ForEach-Object ToXml()` output."""
from xml.sax.saxutils import escape

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def winevent(event_id: int, data: dict[str, str], record_id: int = 1,
             system_time: str = "2026-10-08T13:55:01.1234567Z") -> str:
    items = "".join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in data.items())
    return (
        f'<Event xmlns="{NS}"><System>'
        f'<Provider Name="Microsoft-Windows-Security-Auditing"/>'
        f'<EventID>{event_id}</EventID>'
        f'<TimeCreated SystemTime="{system_time}"/>'
        f'<EventRecordID>{record_id}</EventRecordID>'
        f'<Channel>Security</Channel><Computer>WIN-LAB</Computer></System>'
        f'<EventData>{items}</EventData></Event>'
    )
