from cypher.respond.responder import ResponderService
from cypher.respond.backends.base import FirewallBackend


class FakeBackend(FirewallBackend):
    name = "fake"

    def __init__(self):
        self.blocked: list[str] = []

    def block(self, ip):
        self.blocked.append(ip)
        return True, f"blocked {ip}"

    def unblock(self, ip):
        if ip in self.blocked:
            self.blocked.remove(ip)
        return True, f"unblocked {ip}"

    def list_blocked(self):
        return list(self.blocked)


def _service(settings, db, mode="active"):
    settings.general.mode = mode
    settings.respond.backend = "nftables"  # overridden below
    service = ResponderService(settings, db)
    service.backend = FakeBackend()
    return service


def test_dry_run_mode_does_not_call_backend(settings, tmp_db):
    service = _service(settings, tmp_db, mode="dry_run")
    result = service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "test"})
    assert result["action"] == "dry_run_skipped"
    assert service.backend.blocked == []


def test_active_mode_blocks_via_backend(settings, tmp_db):
    service = _service(settings, tmp_db, mode="active")
    result = service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "test"})
    assert result["action"] == "block"
    assert "203.0.113.5" in service.backend.blocked


def test_allowlisted_ip_never_reaches_backend(settings, tmp_db):
    service = _service(settings, tmp_db, mode="active")
    result = service.handle_request({"action": "block", "ip": "127.0.0.1", "reason": "test"})
    assert result["action"] == "allowlisted"
    assert service.backend.blocked == []


def test_unblock_calls_backend(settings, tmp_db):
    service = _service(settings, tmp_db, mode="active")
    service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "test"})
    result = service.handle_request({"action": "unblock", "ip": "203.0.113.5", "reason": "manual"})
    assert result["ok"] is True
    assert "203.0.113.5" not in service.backend.blocked


def test_unknown_action_returns_error(settings, tmp_db):
    service = _service(settings, tmp_db, mode="active")
    result = service.handle_request({"action": "nonsense"})
    assert result["ok"] is False


def test_already_blocked_ip_is_not_blocked_twice(settings, tmp_db):
    service = _service(settings, tmp_db, mode="active")
    first = service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "test"})
    second = service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "again"})
    assert first["action"] == "block"
    assert second["action"] == "already_blocked"
    assert service.backend.blocked == ["203.0.113.5"]      # firewall touched exactly once
    assert tmp_db.blocks_in_last_hour() == 1               # and the rate limit isn't burned


def test_ip_can_be_blocked_again_after_unblock(settings, tmp_db):
    service = _service(settings, tmp_db, mode="active")
    service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "test"})
    service.handle_request({"action": "unblock", "ip": "203.0.113.5", "reason": "manual"})
    again = service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "back again"})
    assert again["action"] == "block"


def test_expired_blocks_are_released_exactly_once(settings, tmp_db):
    from datetime import datetime, timedelta
    settings.respond.block_ttl_seconds = 60
    service = _service(settings, tmp_db, mode="active")
    service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "test"})
    assert service.backend.blocked == ["203.0.113.5"]

    # Before the TTL: nothing to release.
    assert service.expire_stale_blocks(now=datetime.now()) == 0
    assert service.backend.blocked == ["203.0.113.5"]

    # After the TTL: released from the firewall and from the active list.
    later = datetime.now() + timedelta(seconds=120)
    assert service.expire_stale_blocks(now=later) == 1
    assert service.backend.blocked == []
    assert tmp_db.active_blocks(now=later) == []

    # A second sweep must not "release" the same IP again (the old code did).
    unblock_rows_before = [r for r in tmp_db.recent_blocks(50) if r["action"] == "unblock"]
    assert service.expire_stale_blocks(now=later) == 0
    unblock_rows_after = [r for r in tmp_db.recent_blocks(50) if r["action"] == "unblock"]
    assert len(unblock_rows_after) == len(unblock_rows_before) == 1


def test_manually_unblocked_ip_is_not_unblocked_again_by_the_sweeper(settings, tmp_db):
    from datetime import datetime, timedelta
    settings.respond.block_ttl_seconds = 60
    service = _service(settings, tmp_db, mode="active")
    service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "test"})
    service.handle_request({"action": "unblock", "ip": "203.0.113.5", "reason": "admin"})
    assert service.expire_stale_blocks(now=datetime.now() + timedelta(hours=1)) == 0


def test_sweeper_thread_releases_expired_blocks(settings, tmp_db):
    import threading
    import time
    from cypher.respond.responder import _expiry_loop
    settings.respond.block_ttl_seconds = 1
    service = _service(settings, tmp_db, mode="active")
    service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "test"})
    stop = threading.Event()
    t = threading.Thread(target=_expiry_loop, args=(service, 0.2, stop), daemon=True)
    t.start()
    try:
        deadline = time.time() + 5
        while service.backend.blocked and time.time() < deadline:
            time.sleep(0.1)
        assert service.backend.blocked == []
    finally:
        stop.set()
        t.join(timeout=2)
