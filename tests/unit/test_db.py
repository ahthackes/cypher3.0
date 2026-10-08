from datetime import datetime, timedelta

from cypher.models import Alert, Block, BlockAction, Event, Severity


def test_insert_and_read_event(tmp_db):
    e = Event(src_ip="203.0.113.5", message="test event")
    tmp_db.insert_event(e)
    rows = tmp_db.recent_events(limit=10)
    assert len(rows) == 1
    assert rows[0]["src_ip"] == "203.0.113.5"


def test_insert_and_read_alert(tmp_db):
    a = Alert(src_ip="203.0.113.5", score=90, severity=Severity.CRITICAL)
    tmp_db.insert_alert(a)
    rows = tmp_db.recent_alerts(limit=10)
    assert len(rows) == 1
    assert rows[0]["severity"] == "critical"


def test_active_blocks_excludes_expired(tmp_db):
    expired = Block(
        src_ip="1.1.1.1", action=BlockAction.BLOCK,
        expires_at=datetime.now() - timedelta(hours=1),
    )
    active = Block(
        src_ip="2.2.2.2", action=BlockAction.BLOCK,
        expires_at=datetime.now() + timedelta(hours=1),
    )
    tmp_db.insert_block(expired)
    tmp_db.insert_block(active)

    active_ips = {row["src_ip"] for row in tmp_db.active_blocks()}
    assert "2.2.2.2" in active_ips
    assert "1.1.1.1" not in active_ips


def test_unblock_removes_from_active(tmp_db):
    block = Block(src_ip="3.3.3.3", action=BlockAction.BLOCK, expires_at=None)
    tmp_db.insert_block(block)
    assert "3.3.3.3" in {r["src_ip"] for r in tmp_db.active_blocks()}

    unblock = Block(src_ip="3.3.3.3", action=BlockAction.UNBLOCK)
    tmp_db.insert_block(unblock)
    assert "3.3.3.3" not in {r["src_ip"] for r in tmp_db.active_blocks()}


def test_blocks_in_last_hour_counts_only_block_actions(tmp_db):
    tmp_db.insert_block(Block(src_ip="1.1.1.1", action=BlockAction.BLOCK))
    tmp_db.insert_block(Block(src_ip="1.1.1.1", action=BlockAction.UNBLOCK))
    tmp_db.insert_block(Block(src_ip="2.2.2.2", action=BlockAction.DRY_RUN_SKIPPED))
    assert tmp_db.blocks_in_last_hour() == 1


def test_audit_log_is_append_only_insert(tmp_db):
    tmp_db.audit("system", "block", "1.1.1.1: test")
    cur = tmp_db.conn.execute("SELECT * FROM audit_log")
    rows = cur.fetchall()
    assert len(rows) == 1
    assert rows[0]["action"] == "block"
