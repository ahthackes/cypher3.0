from cypher.detect.fusion import fuse
from cypher.detect.policy import severity_for_score, should_auto_block
from cypher.detect.rules.engine import RuleHit
from cypher.models import Severity
from cypher.settings import ThresholdSettings


def test_fuse_no_rules_uses_ml_score():
    result = fuse([], ml_score=42.0)
    assert result.score == 42.0


def test_fuse_no_ml_uses_rule_score():
    hit = RuleHit("some_rule", 70.0, "desc", "1.2.3.4")
    result = fuse([hit], ml_score=None)
    assert result.score == 70.0


def test_fuse_takes_max_of_rule_and_weighted_average():
    hit = RuleHit("some_rule", 90.0, "desc", "1.2.3.4")
    result = fuse([hit], ml_score=10.0, weight_rules=0.5, weight_ml=0.5)
    # weighted avg = 50, but rule score alone (90) is higher -> should win
    assert result.score == 90.0


def test_fuse_caps_at_100():
    hit = RuleHit("some_rule", 100.0, "desc", "1.2.3.4")
    result = fuse([hit], ml_score=100.0)
    assert result.score == 100.0


def test_severity_thresholds():
    t = ThresholdSettings(low=30, medium=60, high=80, critical=95)
    assert severity_for_score(10, t) == Severity.INFO
    assert severity_for_score(30, t) == Severity.LOW
    assert severity_for_score(65, t) == Severity.MEDIUM
    assert severity_for_score(85, t) == Severity.HIGH
    assert severity_for_score(99, t) == Severity.CRITICAL


def test_only_critical_triggers_auto_block():
    assert should_auto_block(Severity.CRITICAL) is True
    assert should_auto_block(Severity.HIGH) is False
    assert should_auto_block(Severity.LOW) is False
