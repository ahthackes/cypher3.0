"""Windows end-to-end (minus the live Event Log API, which needs Windows):
synthetic Security-log XML -> parser -> normalizer -> rules -> fusion ->
policy, plus a guard that the shipped rules can actually reach the
severity that triggers auto-block on BOTH platforms."""
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cypher.detect.fusion import fuse
from cypher.detect.mitre import techniques_for_rule_hits
from cypher.detect.policy import severity_for_score, should_auto_block
from cypher.detect.rules.engine import RuleEngine
from cypher.detect.rules.loader import load_rules
from cypher.ingest.normalizer import normalize
from cypher.ingest.parsers.windows_security import WindowsSecurityParser
from cypher.models import Severity
from cypher.settings import ThresholdSettings, load_settings

ROOT = Path(__file__).resolve().parents[2]


def _load_demo_module():
    spec = importlib.util.spec_from_file_location("gen_win", ROOT / "scripts" / "generate_windows_demo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(events_xml):
    parser = WindowsSecurityParser()
    engine = RuleEngine(load_rules(ROOT / "config" / "rules.d"))
    results = []
    for xml in events_xml:
        event = parser.parse_line(xml)
        if event is None:
            continue
        event = normalize(event)
        results.append((event, engine.evaluate(event)))
    return results


def test_rdp_bruteforce_reaches_critical_and_would_auto_block():
    demo = _load_demo_module()
    thresholds = ThresholdSettings(low=30, medium=60, high=80, critical=95)
    results = _run(demo.build(datetime.now(timezone.utc) - timedelta(minutes=5)))

    attacker_hits = [h for ev, hits in results if ev.src_ip == demo.ATTACKER for h in hits]
    assert any(h.rule_id == "rdp_bruteforce_burst" for h in attacker_hits)

    final = fuse(attacker_hits[-3:], ml_score=None)
    severity = severity_for_score(final.score, thresholds)
    assert severity == Severity.CRITICAL
    assert should_auto_block(severity) is True


def test_admin_group_addition_raises_a_high_alert():
    demo = _load_demo_module()
    results = _run(demo.build(datetime.now(timezone.utc) - timedelta(minutes=5)))
    admin_hits = [h for ev, hits in results if ev.raw.get("admin_group_add") for h in hits]
    assert [h.rule_id for h in admin_hits] == ["windows_admin_group_add"]
    assert techniques_for_rule_hits(["windows_admin_group_add"]) == ["T1098", "T1078.003"]


def test_ordinary_windows_activity_raises_nothing():
    demo = _load_demo_module()
    start = datetime.now(timezone.utc)
    benign = [
        demo.make_event(4624, 1, start, {"TargetUserName": "ahtsham", "LogonType": "2", "IpAddress": "-"}),
        demo.make_event(4672, 2, start, {"SubjectUserName": "SYSTEM"}),
        demo.make_event(4672, 3, start, {"SubjectUserName": "ahtsham"}),
    ]
    assert all(hits == [] for _, hits in _run(benign))


def test_every_shipped_rule_has_a_mitre_mapping():
    rules = load_rules(ROOT / "config" / "rules.d")
    missing = [r.id for r in rules if not techniques_for_rule_hits([r.id])]
    assert missing == []


def test_a_high_confidence_burst_rule_can_reach_critical_on_every_platform():
    """Regression guard: rules once topped out at 90, below the 95 CRITICAL
    cut-off, which silently disabled auto-block with the shipped config."""
    for cfg in ("cypher.toml", "cypher.windows.toml"):
        settings = load_settings(ROOT / "config" / cfg)
        critical = settings.detect.thresholds.critical
        top = max(r.score for r in load_rules(ROOT / settings.detect.rules_dir.lstrip("./")))
        assert top >= critical, f"{cfg}: no rule can reach CRITICAL ({top} < {critical})"
