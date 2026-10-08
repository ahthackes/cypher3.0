from cypher.models import BlockAction
from cypher.respond.safety import evaluate, load_allowlist


def test_allowlisted_ip_is_never_blocked():
    networks = load_allowlist("config/allowlist.toml")
    decision = evaluate(
        "127.0.0.1", is_dry_run=False, allowlist_networks=networks,
        blocks_in_last_hour=0, max_blocks_per_hour=20,
    )
    assert decision.allowed is False
    assert decision.action == BlockAction.ALLOWLISTED


def test_dry_run_blocks_nothing_for_real():
    decision = evaluate(
        "203.0.113.5", is_dry_run=True, allowlist_networks=[],
        blocks_in_last_hour=0, max_blocks_per_hour=20,
    )
    assert decision.allowed is False
    assert decision.action == BlockAction.DRY_RUN_SKIPPED


def test_rate_limit_stops_excess_blocks():
    decision = evaluate(
        "203.0.113.5", is_dry_run=False, allowlist_networks=[],
        blocks_in_last_hour=20, max_blocks_per_hour=20,
    )
    assert decision.allowed is False
    assert decision.action == BlockAction.RATE_LIMITED


def test_legitimate_block_is_allowed():
    decision = evaluate(
        "203.0.113.5", is_dry_run=False, allowlist_networks=[],
        blocks_in_last_hour=0, max_blocks_per_hour=20,
    )
    assert decision.allowed is True
    assert decision.action == BlockAction.BLOCK


def test_unparseable_ip_fails_safe():
    decision = evaluate(
        "not-an-ip", is_dry_run=False, allowlist_networks=[],
        blocks_in_last_hour=0, max_blocks_per_hour=20,
    )
    assert decision.allowed is False
