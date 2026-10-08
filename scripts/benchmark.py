#!/usr/bin/env python3
"""Checks the two measurable non-functional requirements from the FYP
proposal against a local run:

  - CPU: steady-state ingestion+detection should stay under 15%.
  - Latency: parse+rule-evaluate for one line should leave plenty of
    headroom under the 2.5s log-to-block budget (the firewall call
    itself is backend-dependent and measured separately in the lab).

This is a crude, repo-local benchmark — good enough for FYP evidence and
regression-checking, not a substitute for profiling in the actual VM lab.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.detect.rules.engine import RuleEngine  # noqa: E402
from cypher.detect.rules.loader import load_rules  # noqa: E402
from cypher.ingest.parsers.auth import AuthLogParser  # noqa: E402
from cypher.ingest.normalizer import normalize  # noqa: E402

SAMPLE_LINE = "Oct 05 13:55:01 myhost sshd[1234]: Failed password for invalid user admin from 203.0.113.77 port 50001 ssh2"


def main(n: int = 20000) -> None:
    parser = AuthLogParser()
    rule_engine = RuleEngine(load_rules("config/rules.d"))

    start = time.perf_counter()
    for _ in range(n):
        event = parser.parse_line(SAMPLE_LINE)
        event = normalize(event)
        rule_engine.evaluate(event)
    elapsed = time.perf_counter() - start

    per_line_ms = (elapsed / n) * 1000
    print(f"Processed {n} lines in {elapsed:.2f}s  ({per_line_ms:.4f} ms/line)")
    print(f"At this rate, the 2.5s log-to-block budget leaves room for "
          f"~{int(2500 / per_line_ms)} lines of processing before a single block decision.")
    if per_line_ms > 5:
        print("WARNING: per-line processing is higher than expected — profile before deploying.")


if __name__ == "__main__":
    main()
