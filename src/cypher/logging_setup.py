"""Central logging setup. Every entry point (ingestion, responder, API,
CLI) calls configure_logging() once at startup so log formatting and
levels are consistent across the whole system.
"""
from __future__ import annotations

import logging
import sys


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        stream=sys.stdout,
    )
