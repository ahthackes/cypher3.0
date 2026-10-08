"""Common interface every log parser implements.

A parser turns one raw log line into zero or one Event. Returning None
means the line was recognized but not security-relevant (parsers should
not raise on unrecognized lines — just return None).
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from cypher.models import Event


class BaseParser(ABC):
    name: str = "base"

    @abstractmethod
    def parse_line(self, line: str) -> Event | None:
        """Parse one raw log line into an Event, or None if not relevant."""
        raise NotImplementedError
