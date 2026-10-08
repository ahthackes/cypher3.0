"""A thin in-process queue connecting the ingestion tailers to the
detection pipeline.

Single-process by design (see docs/architecture.md for why: the
fault-tolerance requirement is met by process separation between
ingest+detect, the responder, and the API — not by queuing across
processes, which would add an external broker dependency this project's
"100% offline, low overhead" requirements don't justify).
"""
from __future__ import annotations

import queue

from cypher.models import Event


class EventBus:
    def __init__(self, maxsize: int = 10000):
        self._q: queue.Queue[Event] = queue.Queue(maxsize=maxsize)

    def publish(self, event: Event) -> None:
        try:
            self._q.put_nowait(event)
        except queue.Full:
            # Backpressure: drop the oldest rather than blocking the tailer
            # thread, so a detection stall never stalls log ingestion.
            try:
                self._q.get_nowait()
            except queue.Empty:
                pass
            self._q.put_nowait(event)

    def consume(self, timeout: float = 1.0) -> Event | None:
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def qsize(self) -> int:
        return self._q.qsize()
