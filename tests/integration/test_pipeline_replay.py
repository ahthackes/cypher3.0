"""End-to-end tests that don't need root, a real filesystem log, or a
running responder daemon — they exercise parse -> normalize -> rules ->
fusion -> policy directly, and the ML train/score round-trip, which is
what `cypher replay` and `cypher train` do under the hood.
"""
from datetime import datetime, timedelta

import numpy as np

from cypher.detect.fusion import fuse
from cypher.detect.ml.isolation_forest import IsolationForestScorer
from cypher.detect.policy import severity_for_score, should_auto_block
from cypher.detect.rules.engine import RuleEngine
from cypher.detect.rules.loader import load_rules
from cypher.ingest.normalizer import normalize
from cypher.ingest.parsers.auth import AuthLogParser
from cypher.models import Severity
from cypher.settings import ThresholdSettings


def test_bruteforce_log_triggers_critical_alert():
    parser = AuthLogParser()
    rules = load_rules("config/rules.d")
    engine = RuleEngine(rules)
    thresholds = ThresholdSettings(low=30, medium=60, high=80, critical=95)

    start = datetime(2026, 1, 1, 12, 0, 0)
    final_hits = []
    for i in range(12):
        line = (f"{(start + timedelta(seconds=i*3)).strftime('%b %d %H:%M:%S')} "
                f"myhost sshd[{1000+i}]: Failed password for invalid user admin "
                f"from 203.0.113.77 port 5000{i} ssh2")
        event = parser.parse_line(line)
        event = normalize(event)
        assert event is not None
        final_hits = engine.evaluate(event)

    result = fuse(final_hits, ml_score=None)
    severity = severity_for_score(result.score, thresholds)

    assert severity == Severity.CRITICAL
    assert should_auto_block(severity) is True


def test_isolation_forest_flags_outlier_after_training():
    rng = np.random.default_rng(42)
    normal = rng.normal(loc=0.0, scale=1.0, size=(200, 5))
    outlier = np.array([[50.0, 50.0, 50.0, 50.0, 50.0]])

    scorer = IsolationForestScorer(contamination=0.02)
    scorer.fit(normal)

    normal_score = scorer.score(normal[0])
    outlier_score = scorer.score(outlier[0])

    assert outlier_score > normal_score


def test_rule_engine_ignores_benign_login_traffic():
    parser = AuthLogParser()
    rules = load_rules("config/rules.d")
    engine = RuleEngine(rules)

    start = datetime(2026, 1, 1, 12, 0, 0)
    all_hits = []
    for i in range(5):
        line = (f"{(start + timedelta(minutes=i*10)).strftime('%b %d %H:%M:%S')} "
                f"myhost sshd[{2000+i}]: Accepted password for deploy "
                f"from 192.168.1.10 port 4100{i} ssh2")
        event = parser.parse_line(line)
        event = normalize(event)
        all_hits.extend(engine.evaluate(event))

    assert all_hits == []
