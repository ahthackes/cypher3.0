"""Follows log files in real time, like `tail -F`, and feeds each new
line to the right parser.

Rotation handling: on every poll we check the file's inode. If it changed
(logrotate replaced the file), we reopen from the start of the new file
rather than trying to keep reading the old, now-renamed file handle.
This is the part most naive log-tailer implementations get wrong.
"""
from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path

logger = logging.getLogger("cypher.ingest.tailer")


class FileTailer:
    """Tails a single file, yielding new lines as they're written.

    Not tied to `watchdog` directly so it's easy to unit-test with plain
    files; the ingestion service wires this to a watchdog-driven poll loop
    for production use (see docs/architecture.md).
    """

    def __init__(self, path: str | Path, poll_interval: float = 0.5, from_end: bool = True):
        self.path = Path(path)
        self.poll_interval = poll_interval
        self._fh = None
        self._inode: int | None = None
        self._from_end = from_end

    def _open(self) -> None:
        self._fh = open(self.path, "r", errors="replace")
        if self._from_end:
            self._fh.seek(0, os.SEEK_END)
        self._inode = os.fstat(self._fh.fileno()).st_ino
        self._from_end = False  # only skip to end on the very first open

    def _rotated(self) -> bool:
        try:
            current_inode = os.stat(self.path).st_ino
        except FileNotFoundError:
            return False
        return self._inode is not None and current_inode != self._inode

    def poll_once(self) -> list[str]:
        """Read whatever new complete lines are available right now."""
        if self._fh is None:
            if not self.path.exists():
                return []
            self._open()

        if self._rotated():
            logger.info("Detected rotation of %s, reopening", self.path)
            self._fh.close()
            self._fh = None
            self._open()

        lines = self._fh.readlines()
        return lines

    def follow(self, stop_flag: Callable[[], bool] = lambda: False) -> Iterator[str]:
        """Blocking generator: yields new lines forever until stop_flag() is True."""
        while not stop_flag():
            for line in self.poll_once():
                yield line
            time.sleep(self.poll_interval)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
