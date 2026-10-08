"""Exercises the responder's real loopback-TCP transport + token check —
the exact code path used on both Linux and Windows. A FakeBackend stands
in for the firewall so no privileges are needed."""
import json
import socket
import threading

import pytest

from cypher.respond.backends.base import FirewallBackend
from cypher.respond.client import ResponderClient
from cypher.respond.ipc_token import get_or_create_token
from cypher.respond.responder import ResponderService, _LoopbackTCPServer, _RequestHandler


class FakeBackend(FirewallBackend):
    name = "fake"

    def __init__(self):
        self.blocked: list[str] = []

    def block(self, ip):
        self.blocked.append(ip)
        return True, f"blocked {ip}"

    def unblock(self, ip):
        self.blocked = [i for i in self.blocked if i != ip]
        return True, f"unblocked {ip}"

    def list_blocked(self):
        return list(self.blocked)


@pytest.fixture
def running_responder(settings, tmp_db):
    settings.general.mode = "active"
    service = ResponderService(settings, tmp_db)
    service.backend = FakeBackend()
    token = get_or_create_token(settings.respond.ipc_token_file)

    server = _LoopbackTCPServer(("127.0.0.1", 0), _RequestHandler)  # port 0 = any free port
    server.service = service
    server.token = token
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield service, port, settings
    server.shutdown()
    server.server_close()


def _client(port, settings):
    return ResponderClient("127.0.0.1", port, settings.respond.ipc_token_file)


def test_block_round_trip_over_tcp(running_responder):
    service, port, settings = running_responder
    result = _client(port, settings).block("203.0.113.5", reason="test")
    assert result["ok"] is True
    assert result["action"] == "block"
    assert service.backend.blocked == ["203.0.113.5"]


def test_status_and_unblock_round_trip(running_responder):
    service, port, settings = running_responder
    c = _client(port, settings)
    c.block("203.0.113.5", reason="test")
    assert [b["src_ip"] for b in c.status()["active_blocks"]] == ["203.0.113.5"]
    assert c.unblock("203.0.113.5")["ok"] is True
    assert service.backend.blocked == []


def _raw_request(port, payload: dict) -> dict:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall((json.dumps(payload) + "\n").encode())
        return json.loads(s.makefile().readline())


def test_request_without_token_is_rejected(running_responder):
    service, port, _ = running_responder
    resp = _raw_request(port, {"action": "block", "ip": "203.0.113.5"})
    assert resp["ok"] is False
    assert "token" in resp["message"]
    assert service.backend.blocked == []


def test_request_with_wrong_token_is_rejected(running_responder):
    service, port, _ = running_responder
    resp = _raw_request(port, {"token": "guess", "action": "block", "ip": "203.0.113.5"})
    assert resp["ok"] is False
    assert service.backend.blocked == []


def test_malformed_json_does_not_kill_the_server(running_responder):
    service, port, settings = running_responder
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(b"this is not json\n")
        assert json.loads(s.makefile().readline())["ok"] is False
    # server still serves a valid request afterwards
    assert _client(port, settings).block("203.0.113.9", reason="after garbage")["ok"] is True


def test_allowlist_still_enforced_through_the_socket(running_responder):
    service, port, settings = running_responder
    result = _client(port, settings).block("127.0.0.1", reason="should refuse")
    assert result["action"] == "allowlisted"
    assert service.backend.blocked == []


def test_token_is_created_once_and_reused(tmp_path):
    path = tmp_path / "nested" / "responder.token"
    first = get_or_create_token(path)
    assert len(first) == 64
    assert get_or_create_token(path) == first


def test_token_file_is_never_world_readable_on_posix(tmp_path):
    import os
    import stat
    if os.name == "nt":
        pytest.skip("POSIX permission bits don't apply on Windows")
    path = tmp_path / "t.token"
    get_or_create_token(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode & 0o007 == 0, f"token readable by others: {oct(mode)}"
    assert mode & 0o600 == 0o600          # owner can read and write
    assert mode & 0o020 == 0              # group can never write


def test_token_is_group_readable_when_cypher_group_exists(tmp_path, monkeypatch):
    """With a `cypher` group present the file becomes 0640 and is handed to
    that group. We simulate the group using one the test user belongs to."""
    import grp
    import os
    import stat
    if os.name == "nt":
        pytest.skip("POSIX only")
    from cypher.respond import ipc_token
    my_group = grp.getgrgid(os.getgid()).gr_name
    monkeypatch.setattr(ipc_token, "_SHARED_GROUP", my_group)
    path = tmp_path / "t.token"
    get_or_create_token(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert path.stat().st_gid == os.getgid()
