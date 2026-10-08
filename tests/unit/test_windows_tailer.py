import re

import pytest

from cypher.ingest.win_tailer import WindowsEventLogTailer
from tests.fixtures.winevt_samples import winevent


class _NoMoreItems(Exception):
    winerror = 259


class FakeEvtApi:
    """Stands in for pywin32's win32evtlog, with the same call shapes."""
    EvtQueryChannelPath = 1
    EvtQueryForwardDirection = 0x100
    EvtQueryReverseDirection = 0x200
    EvtRenderEventXml = 1

    def __init__(self):
        self.records: list[tuple[int, str]] = []   # (record_id, xml)
        self.raise_when_exhausted = False
        self.xpaths: list[str] = []

    def add(self, record_id: int, event_id: int = 4625):
        self.records.append((record_id, winevent(event_id, {"TargetUserName": "a"}, record_id=record_id)))

    def EvtQuery(self, channel, flags, xpath, session):
        self.xpaths.append(xpath)
        m = re.search(r"EventRecordID > (\d+)", xpath)
        floor = int(m.group(1)) if m else 0
        matching = [r for r in self.records if r[0] > floor]
        if flags & self.EvtQueryReverseDirection:
            matching.reverse()
        return {"pending": matching}

    def EvtNext(self, query, count):
        if not query["pending"]:
            if self.raise_when_exhausted:
                raise _NoMoreItems()
            return ()
        batch, query["pending"] = query["pending"][:count], query["pending"][count:]
        return tuple(batch)

    def EvtRender(self, handle, flags):
        return handle[1]


def test_first_poll_returns_nothing_and_does_not_replay_history():
    api = FakeEvtApi()
    api.add(10); api.add(11)
    t = WindowsEventLogTailer(api=api)
    assert t.poll_once() == []
    assert t._last_record_id == 11


def test_later_polls_return_only_new_events_once():
    api = FakeEvtApi()
    api.add(10)
    t = WindowsEventLogTailer(api=api)
    t.poll_once()
    api.add(11); api.add(12)
    first = t.poll_once()
    assert len(first) == 2
    assert t.poll_once() == []          # nothing new -> nothing returned again
    api.add(13)
    assert len(t.poll_once()) == 1


def test_query_is_restricted_to_watched_event_ids():
    api = FakeEvtApi()
    t = WindowsEventLogTailer(api=api)
    t.poll_once(); api.add(1); t.poll_once()
    xpath = api.xpaths[-1]
    for event_id in (4624, 4625, 4672, 4732, 4740):
        assert f"EventID={event_id}" in xpath


def test_win32_no_more_items_error_is_treated_as_end_of_results():
    api = FakeEvtApi()
    api.raise_when_exhausted = True
    api.add(5)
    t = WindowsEventLogTailer(api=api)
    t.poll_once()
    api.add(6)
    assert len(t.poll_once()) == 1


def test_empty_log_starts_from_zero():
    api = FakeEvtApi()
    t = WindowsEventLogTailer(api=api)
    assert t.poll_once() == []
    assert t._last_record_id == 0
    api.add(1)
    assert len(t.poll_once()) == 1


def test_clear_error_when_pywin32_unavailable():
    # This test environment is Linux without pywin32; on a Windows box with
    # pywin32 installed, skip since construction would legitimately succeed.
    from cypher.ingest import win_tailer
    if win_tailer._win32evtlog is not None:
        pytest.skip("pywin32 is available here")
    with pytest.raises(RuntimeError, match="pywin32|Windows"):
        WindowsEventLogTailer()
