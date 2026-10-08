from datetime import datetime, timedelta

from cypher.detect.rules.engine import RuleEngine
from cypher.detect.rules.loader import load_rules
from cypher.models import Event, EventType


def make_ssh_failure(ip: str, ts: datetime) -> Event:
    return Event(
        timestamp=ts, source="auth.log", service="sshd",
        event_type=EventType.AUTH_FAILURE, src_ip=ip,
        message=f"Failed password for admin from {ip} port 50000 ssh2",
    )


def test_loads_shipped_rules():
    rules = load_rules("config/rules.d")
    ids = {r.id for r in rules}
    assert "ssh_bruteforce_5m" in ids
    assert "sudo_not_in_sudoers" in ids
    assert "web_sqli_pattern" in ids


def test_ssh_bruteforce_fires_at_threshold():
    rules = load_rules("config/rules.d")
    engine = RuleEngine(rules)
    now = datetime(2026, 1, 1, 12, 0, 0)

    all_hits = []
    for i in range(5):
        event = make_ssh_failure("203.0.113.9", now + timedelta(seconds=i * 10))
        all_hits.extend(engine.evaluate(event))

    assert any(h.rule_id == "ssh_bruteforce_5m" for h in all_hits)


def test_ssh_bruteforce_does_not_fire_below_threshold():
    rules = load_rules("config/rules.d")
    engine = RuleEngine(rules)
    now = datetime(2026, 1, 1, 12, 0, 0)

    all_hits = []
    for i in range(3):
        event = make_ssh_failure("203.0.113.10", now + timedelta(seconds=i * 10))
        all_hits.extend(engine.evaluate(event))

    assert not any(h.rule_id == "ssh_bruteforce_5m" for h in all_hits)


def test_sudo_not_in_sudoers_single_shot():
    rules = load_rules("config/rules.d")
    engine = RuleEngine(rules)
    event = Event(
        service="sudo", event_type=EventType.PRIV_ESCALATION_FAILURE,
        message="baduser is not in the sudoers file.  This incident will be reported.",
    )
    hits = engine.evaluate(event)
    assert any(h.rule_id == "sudo_not_in_sudoers" for h in hits)


def test_web_sqli_pattern_matches_path():
    rules = load_rules("config/rules.d")
    engine = RuleEngine(rules)
    event = Event(
        service="nginx", event_type=EventType.HTTP_REQUEST,
        path="/products?id=1 UNION SELECT username,password FROM users--",
        message="irrelevant",
    )
    hits = engine.evaluate(event)
    assert any(h.rule_id == "web_sqli_pattern" for h in hits)
