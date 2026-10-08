from cypher.ingest.parsers.auth import AuthLogParser
from cypher.ingest.parsers.syslog import SyslogParser
from cypher.ingest.parsers.webaccess import WebAccessParser
from cypher.models import EventType


def test_ssh_failed_password():
    line = "Oct 05 13:55:01 myhost sshd[1234]: Failed password for admin from 203.0.113.5 port 50001 ssh2"
    event = AuthLogParser().parse_line(line)
    assert event is not None
    assert event.event_type == EventType.AUTH_FAILURE
    assert event.src_ip == "203.0.113.5"
    assert event.user == "admin"
    assert event.service == "sshd"


def test_ssh_invalid_user():
    line = "Oct 05 13:55:01 myhost sshd[1234]: Invalid user backup123 from 203.0.113.6"
    event = AuthLogParser().parse_line(line)
    assert event is not None
    assert event.event_type == EventType.AUTH_FAILURE
    assert event.raw.get("invalid_user") is True


def test_ssh_accepted():
    line = "Oct 05 13:55:01 myhost sshd[1234]: Accepted password for deploy from 192.168.1.10 port 41001 ssh2"
    event = AuthLogParser().parse_line(line)
    assert event is not None
    assert event.event_type == EventType.AUTH_SUCCESS


def test_sudo_not_in_sudoers():
    line = "Oct 05 13:55:01 myhost sudo: baduser is not in the sudoers file.  This incident will be reported."
    event = AuthLogParser().parse_line(line)
    assert event is not None
    assert event.event_type == EventType.PRIV_ESCALATION_FAILURE
    assert event.user == "baduser"


def test_auth_parser_ignores_unrelated_lines():
    line = "Oct 05 13:55:01 myhost CRON[123]: (root) CMD (some cron job)"
    assert AuthLogParser().parse_line(line) is None


def test_auth_parser_handles_garbage_gracefully():
    assert AuthLogParser().parse_line("not a log line at all") is None
    assert AuthLogParser().parse_line("") is None


def test_syslog_parser_filters_noise():
    noise = "Oct 05 13:55:01 myhost some-random-service[1]: nothing interesting happened"
    assert SyslogParser().parse_line(noise) is None

    signal = "Oct 05 13:55:01 myhost kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.9"
    event = SyslogParser().parse_line(signal)
    assert event is not None
    assert event.event_type == EventType.SYSTEM


def test_webaccess_parser_classifies_status_codes():
    denied = '203.0.113.7 - - [05/Oct/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 401 512 "-" "curl/8.0"'
    event = WebAccessParser().parse_line(denied)
    assert event is not None
    assert event.event_type == EventType.HTTP_DENIED
    assert event.src_ip == "203.0.113.7"
    assert event.http_status == 401

    notfound = '203.0.113.7 - - [05/Oct/2026:13:55:37 +0000] "GET /wp-login.php HTTP/1.1" 404 128 "-" "curl/8.0"'
    event = WebAccessParser().parse_line(notfound)
    assert event.event_type == EventType.HTTP_NOTFOUND

    ok = '203.0.113.7 - - [05/Oct/2026:13:55:38 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    event = WebAccessParser().parse_line(ok)
    assert event.event_type == EventType.HTTP_REQUEST
