"""Follows a Windows Event Log channel (normally "Security") in real
time and yields each new event as an XML string — the Windows
counterpart of ingest/tailer.py's FileTailer, with the same
`poll_once()` / `follow()` / `close()` shape so pipeline.py can treat
both interchangeably.

Uses pywin32's modern Evt* API (EvtQuery / EvtNext / EvtRender), which
renders events as XML with *named* fields. The older ReadEventLog API
only gives positional "string inserts", which would make field
extraction fragile across Windows versions.

How "new events only" works: on first poll we ask the log for its
newest EventRecordID and remember it, returning nothing (we don't
replay history, same as FileTailer seeking to end-of-file). Every later
poll queries for records with an ID greater than the last one seen. The
XPath filter also restricts the query to the five Event IDs
WindowsSecurityParser understands, so the (very chatty) Security log
isn't dragged through Python event by event.

Requires: Windows, `pip install pywin32` (installed automatically on
Windows via a platform marker in pyproject.toml), and a process allowed
to read the Security log (Administrator, or a member of "Event Log
Readers").

TESTING NOTE: the real pywin32 calls can only run on Windows. The `api`
constructor argument lets tests substitute a fake with the same
interface, which is how the record-ID bookkeeping and filtering logic
is covered on any OS (tests/unit/test_windows_tailer.py). The first run
against a real Security log still has to happen in a Windows VM —
docs/dev-guide.md has the steps.
"""
from __future__ import annotations

import logging
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator

from cypher.platform_utils import IS_WINDOWS

try:  # pragma: no cover - only importable on Windows with pywin32 installed
    import win32evtlog as _win32evtlog
except ImportError:  # Linux/macOS, or Windows without pywin32
    _win32evtlog = None

logger = logging.getLogger("cypher.ingest.win_tailer")

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_ERROR_NO_MORE_ITEMS = 259
_WATCHED_EVENT_IDS = (4624, 4625, 4672, 4732, 4740)
_BATCH_SIZE = 100


def _id_filter() -> str:
    return " or ".join(f"EventID={i}" for i in _WATCHED_EVENT_IDS)


def _record_id(xml_text: str) -> int | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    el = root.find("e:System/e:EventRecordID", _NS)
    if el is None or not el.text:
        return None
    try:
        return int(el.text)
    except ValueError:
        return None


class WindowsEventLogTailer:
    def __init__(self, channel: str = "Security", poll_interval: float = 1.0, api=None):
        self.channel = channel
        self.poll_interval = poll_interval
        self._api = api if api is not None else _win32evtlog
        if self._api is None:
            raise RuntimeError(
                "Reading the Windows Event Log needs Windows and the pywin32 package "
                "(pip install pywin32). On Linux, use the file-based sources "
                "(auth_log / syslog / web_access_log) instead."
                if not IS_WINDOWS else
                "pywin32 is not installed: pip install pywin32"
            )
        self._last_record_id: int | None = None

    # -- internals ---------------------------------------------------

    def _query(self, xpath: str, reverse: bool = False):
        direction = self._api.EvtQueryReverseDirection if reverse else self._api.EvtQueryForwardDirection
        return self._api.EvtQuery(self.channel, self._api.EvtQueryChannelPath | direction, xpath, None)

    def _next_batch(self, query, count: int) -> list:
        try:
            return list(self._api.EvtNext(query, count))
        except Exception as exc:  # noqa: BLE001 - pywintypes.error, not importable off-Windows
            if getattr(exc, "winerror", None) == _ERROR_NO_MORE_ITEMS:
                return []
            raise

    def _newest_record_id(self) -> int:
        query = self._query(f"*[System[{_id_filter()}]]", reverse=True)
        batch = self._next_batch(query, 1)
        if not batch:
            return 0
        xml_text = self._api.EvtRender(batch[0], self._api.EvtRenderEventXml)
        return _record_id(xml_text) or 0

    # -- public interface (mirrors FileTailer) ------------------------

    def poll_once(self) -> list[str]:
        if self._last_record_id is None:
            self._last_record_id = self._newest_record_id()
            logger.info("Tailing %s log from record %d", self.channel, self._last_record_id)
            return []

        xpath = f"*[System[({_id_filter()}) and EventRecordID > {self._last_record_id}]]"
        query = self._query(xpath)
        results: list[str] = []
        while True:
            batch = self._next_batch(query, _BATCH_SIZE)
            if not batch:
                break
            for handle in batch:
                xml_text = self._api.EvtRender(handle, self._api.EvtRenderEventXml)
                results.append(xml_text)
                rid = _record_id(xml_text)
                if rid is not None and rid > self._last_record_id:
                    self._last_record_id = rid
        return results

    def follow(self, stop_flag: Callable[[], bool] = lambda: False) -> Iterator[str]:
        while not stop_flag():
            for xml_text in self.poll_once():
                yield xml_text
            time.sleep(self.poll_interval)

    def close(self) -> None:
        pass  # Evt handles are released when garbage collected
