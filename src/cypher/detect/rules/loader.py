"""Loads every *.toml file in config/rules.d/ into a flat list of Rules.

Each TOML file may contain multiple [[rule]] tables. A malformed rule
(missing required fields) is skipped with a logged warning rather than
crashing startup — one bad rule file shouldn't take down detection.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import toml

logger = logging.getLogger("cypher.detect.rules.loader")


@dataclass
class Rule:
    id: str
    description: str = ""
    event_type: str | None = None
    service: str | None = None
    count_threshold: int | None = None      # if set, requires N matching events in window
    window_seconds: int | None = None
    match_field: str | None = None          # e.g. "message", "path"
    match_contains: str | None = None
    match_regex: str | None = None
    score: float = 50.0


def load_rules(rules_dir: str | Path) -> list[Rule]:
    rules: list[Rule] = []
    directory = Path(rules_dir)
    if not directory.exists():
        logger.warning("Rules directory %s does not exist", directory)
        return rules

    for toml_file in sorted(directory.glob("*.toml")):
        try:
            data = toml.load(toml_file)
        except Exception as exc:  # noqa: BLE001 — one bad file must not stop the rest
            logger.error("Failed to parse %s: %s", toml_file, exc)
            continue

        for raw_rule in data.get("rule", []):
            try:
                rules.append(Rule(**raw_rule))
            except TypeError as exc:
                logger.warning("Skipping malformed rule in %s: %s", toml_file, exc)

    return rules
