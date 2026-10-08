"""Maps a fused 0-100 score to a Severity, and decides whether that
severity should trigger the active-defense pipeline.

Kept as a tiny, separate module (rather than folded into fusion.py) so
the escalation policy — what score means "block this IP" — can be tuned
or unit-tested independently of how the score itself was computed.
"""
from __future__ import annotations

from cypher.models import Severity
from cypher.settings import ThresholdSettings


def severity_for_score(score: float, thresholds: ThresholdSettings) -> Severity:
    if score >= thresholds.critical:
        return Severity.CRITICAL
    if score >= thresholds.high:
        return Severity.HIGH
    if score >= thresholds.medium:
        return Severity.MEDIUM
    if score >= thresholds.low:
        return Severity.LOW
    return Severity.INFO


def should_auto_block(severity: Severity) -> bool:
    """Only CRITICAL severity triggers automatic firewall action.

    HIGH and below are surfaced on the dashboard for a human to review —
    this is a deliberate conservative default to avoid self-inflicted
    outages; it can be loosened per-deployment once false-positive rates
    are measured (see docs/ml-evaluation.md).
    """
    return severity == Severity.CRITICAL
