from cypher.ingest.normalizer import normalize
from cypher.ingest.parsers.windows_security import WindowsSecurityParser
from cypher.models import EventType
from tests.fixtures.winevt_samples import winevent

parser = WindowsSecurityParser()


def test_failed_rdp_logon():
    xml = winevent(4625, {"TargetUserName": "administrator", "LogonType": "10",
                          "IpAddress": "203.0.113.5", "Status": "0xc000006d"})
    e = parser.parse_line(xml)
    assert e is not None
    assert e.event_type == EventType.AUTH_FAILURE
    assert e.service == "rdp"
    assert e.src_ip == "203.0.113.5"
    assert e.user == "administrator"
    assert e.raw["event_id"] == 4625


def test_failed_network_logon_is_not_rdp():
    xml = winevent(4625, {"TargetUserName": "bob", "LogonType": "3", "IpAddress": "198.51.100.9"})
    e = parser.parse_line(xml)
    assert e.service == "windows_logon"


def test_successful_logon():
    xml = winevent(4624, {"TargetUserName": "ahtsham", "LogonType": "2", "IpAddress": "-"})
    e = parser.parse_line(xml)
    assert e.event_type == EventType.AUTH_SUCCESS
    assert e.src_ip is None  # "-" means no remote address


def test_loopback_address_is_treated_as_local():
    xml = winevent(4625, {"TargetUserName": "x", "LogonType": "3", "IpAddress": "127.0.0.1"})
    assert parser.parse_line(xml).src_ip is None


def test_account_lockout():
    xml = winevent(4740, {"TargetUserName": "administrator", "TargetDomainName": "WIN-LAB"})
    e = parser.parse_line(xml)
    assert e.event_type == EventType.AUTH_FAILURE
    assert e.raw["lockout"] is True
    assert "locked out" in e.message


def test_special_privileges_ignores_system_and_machine_accounts():
    for noisy in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "WIN-LAB$"):
        assert parser.parse_line(winevent(4672, {"SubjectUserName": noisy})) is None
    e = parser.parse_line(winevent(4672, {"SubjectUserName": "ahtsham",
                                          "PrivilegeList": "SeDebugPrivilege"}))
    assert e.event_type == EventType.PRIV_ESCALATION_SUCCESS


def test_admin_group_addition_only_for_administrators():
    admin = winevent(4732, {"TargetUserName": "Administrators",
                            "MemberSid": "S-1-5-21-1-2-3-1005", "SubjectUserName": "mallory"})
    e = parser.parse_line(admin)
    assert e.event_type == EventType.PRIV_ESCALATION_SUCCESS
    assert "Administrators group" in e.message
    assert e.raw["admin_group_add"] is True

    other = winevent(4732, {"TargetUserName": "Backup Operators", "MemberSid": "S-1-5-21-9"})
    assert parser.parse_line(other) is None


def test_unhandled_event_id_returns_none():
    assert parser.parse_line(winevent(4634, {"TargetUserName": "x"})) is None


def test_garbage_and_empty_input_never_raises():
    for bad in ("", "   ", "not xml", "<Event>", "<Event xmlns='x'></Event>"):
        assert parser.parse_line(bad) is None


def test_doctype_and_entities_are_rejected():
    evil = ('<!DOCTYPE foo [<!ENTITY x "boom">]>'
            + winevent(4625, {"TargetUserName": "&x;", "LogonType": "10"}))
    assert parser.parse_line(evil) is None


def test_timestamp_with_seven_fractional_digits_parses():
    xml = winevent(4624, {"TargetUserName": "a", "LogonType": "2"},
                   system_time="2026-10-08T13:55:01.9999999Z")
    assert parser.parse_line(xml).timestamp.year == 2026


def test_output_survives_normalizer():
    xml = winevent(4625, {"TargetUserName": "a", "LogonType": "10", "IpAddress": "203.0.113.5"})
    assert normalize(parser.parse_line(xml)) is not None
