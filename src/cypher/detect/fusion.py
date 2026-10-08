"""Fuses rule-engine hits and ML scores into one 0-100 anomaly score.

Approach: take the MAX of the highest rule score and the weighted-average
ML score, rather than a pure weighted sum. Rationale: a single high-
confidence rule hit (e.g. "not in sudoers file", score 85) shouldn't get
diluted by an ML score of 0 just because the ML model hasn't seen enough
data yet — but when both signals agree, the score should reflect that
agreement, not just cap at the rule's own score.
"""
from __future__ import annotations

from dataclasses import dataclass

from cypher.detect.rules.engine import RuleHit


@dataclass
class FusionResult:
    score: float
    rule_hits: list[str]
    ml_score: float | None


def fuse(
    rule_hits: list[RuleHit],
    ml_score: float | None,
    weight_rules: float = 0.5,
    weight_ml: float = 0.5,
) -> FusionResult:
    rule_score = max((h.score for h in rule_hits), default=0.0)

    if ml_score is None:
        fused = rule_score
    elif not rule_hits:
        fused = ml_score
    else:
        weighted_avg = weight_rules * rule_score + weight_ml * ml_score
        fused = max(rule_score, weighted_avg)

    return FusionResult(
        score=min(fused, 100.0),
        rule_hits=[h.rule_id for h in rule_hits],
        ml_score=ml_score,
    )
