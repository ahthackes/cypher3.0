import subprocess

from cypher.respond.backends import get_backend
from cypher.respond.backends.windows_firewall import WindowsFirewallBackend


class Recorder:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.calls: list[list[str]] = []
        self._rc, self._out, self._err = returncode, stdout, stderr

    def __call__(self, cmd):
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, self._rc, self._out, self._err)


def test_block_builds_expected_netsh_command():
    r = Recorder()
    ok, _ = WindowsFirewallBackend(runner=r).block("203.0.113.5")
    assert ok
    assert r.calls == [[
        "netsh", "advfirewall", "firewall", "add", "rule",
        "name=Cypher Block 203.0.113.5", "dir=in", "action=block", "remoteip=203.0.113.5",
    ]]


def test_unblock_deletes_only_our_named_rule():
    r = Recorder()
    ok, _ = WindowsFirewallBackend(runner=r).unblock("203.0.113.5")
    assert ok
    assert r.calls == [[
        "netsh", "advfirewall", "firewall", "delete", "rule", "name=Cypher Block 203.0.113.5",
    ]]


def test_invalid_ip_never_reaches_netsh():
    r = Recorder()
    backend = WindowsFirewallBackend(runner=r)
    for bad in ("not-an-ip", "1.2.3.4 remoteip=0.0.0.0/0", "", "1.2.3.4; calc"):
        ok, _ = backend.block(bad)
        assert ok is False
        ok, _ = backend.unblock(bad)
        assert ok is False
    assert r.calls == []


def test_failure_message_is_surfaced():
    r = Recorder(returncode=1, stdout="The requested operation requires elevation.")
    ok, msg = WindowsFirewallBackend(runner=r).block("203.0.113.5")
    assert ok is False
    assert "elevation" in msg


def test_list_blocked_reads_only_cypher_rules():
    out = (
        "Rule Name:                            Cypher Block 203.0.113.5\n"
        "----------------------------------------------------------------------\n"
        "Rule Name:                            Remote Desktop - User Mode (TCP-In)\n"
        "Rule Name:                            Cypher Block 198.51.100.7\n"
        "Rule Name:                            Cypher Block not-an-ip\n"
    )
    ips = WindowsFirewallBackend(runner=Recorder(stdout=out)).list_blocked()
    assert ips == ["203.0.113.5", "198.51.100.7"]


def test_registered_in_backend_registry():
    assert get_backend("windows_firewall").name == "windows_firewall"
