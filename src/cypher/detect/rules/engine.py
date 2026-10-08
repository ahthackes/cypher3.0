"""Evaluates incoming Events against the loaded rule set.

Two kinds of rules:
1. Threshold rules (count_threshold + window_seconds): fire when a key
   (src_ip, or src_ip+user for priv-escalation rules) has produced N
   matching events within the window.
2. Single-shot pattern rules (match_contains / match_regex): fire the
   instant one event matches, no counting needed.

Returns a RuleHit per firing rule; the fusion stage combines these with
the ML score. Rules run before ML so cheap, deterministic detections
never wait on the (much more expensive) ML path.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from cypher.detect.rules.loader import Rule
from cypher.features.windows import SlidingWindowCounter
from cypher.models import Event


@dataclass
class RuleHit:
    rule_id: str
    score: float
    description: str
    src_ip: str | None


class RuleEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self._counters: dict[str, SlidingWindowCounter] = {
            r.id: SlidingWindowCounter() for r in rules if r.count_threshold
        }

    def evaluate(self, event: Event) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for rule in self.rules:
            if not self._type_and_service_match(rule, event):
                continue

            if rule.match_contains or rule.match_regex:
                if self._pattern_matches(rule, event):
                    hits.append(RuleHit(rule.id, rule.score, rule.description, event.src_ip))
                continue

            if rule.count_threshold and rule.window_seconds:
                key = event.src_ip or event.user or "unknown"
                counter = self._counters[rule.id]
                counter.add(key, event.timestamp)
                if counter.count(key, rule.window_seconds, now=event.timestamp) >= rule.count_threshold:
                    hits.append(RuleHit(rule.id, rule.score, rule.description, event.src_ip))
        return hits

    @staticmethod
    def _type_and_service_match(rule: Rule, event: Event) -> bool:
        if rule.event_type and rule.event_type != event.event_type.value:
            return False
        if rule.service and rule.service != event.service:
            return False
        return True

    @staticmethod
    def _pattern_matches(rule: Rule, event: Event) -> bool:
        field_value = getattr(event, rule.match_field, None) if rule.match_field else event.message
        field_value = field_value or ""
        if rule.match_contains and rule.match_contains.lower() in field_value.lower():
            return True
        if rule.match_regex and re.search(rule.match_regex, field_value):
            return True
        return False
