# Part 1 — Ingestion: tailing, parsing, normalizing

## Files covered

`src/cypher/ingest/tailer.py`, `src/cypher/ingest/parsers/base.py`,
`src/cypher/ingest/parsers/auth.py`, `src/cypher/ingest/parsers/syslog.py`,
`src/cypher/ingest/parsers/webaccess.py`, `src/cypher/ingest/parsers/__init__.py`,
`src/cypher/ingest/normalizer.py`

## Purpose

Turns raw, unstructured text from three Linux log sources into
structured `Event` objects the rest of the pipeline can work with, in
real time, while surviving log rotation — this directly implements
FR-1 from `docs/SRS.md`.

## How it works

**`tailer.py`'s `FileTailer`** implements a `tail -F`-equivalent: it
opens the file, seeks to the end on first open (so it only sees new
lines, not the entire historical file), and on every poll compares the
file's current inode to the one it has open. If they differ — meaning
`logrotate` replaced the file — it reopens from the start of the new
file rather than continuing to read from the now-orphaned old file
handle. This is the detail most naive tailer implementations get wrong
and is specifically called out in the proposal's architecture section.
`follow()` is a blocking generator used by the live pipeline;
`poll_once()` is the non-blocking building block, used directly in
tests without needing a background thread.

**Parsers** (`auth.py`, `syslog.py`, `webaccess.py`) all implement
`BaseParser.parse_line(line) -> Event | None`. The contract is
important: a parser must never raise on a line it doesn't understand —
it returns `None` instead, so one malformed or unexpected log line can
never crash the ingestion process. `auth.py` is the most complex: it
first matches the standard syslog prefix (timestamp, host, service,
pid), then dispatches to sshd- or sudo/su-specific regexes to extract
IP, user, and outcome (failed password, invalid user, accepted,
privilege-escalation failure/success). `webaccess.py` parses the
nginx/Apache "combined" log format and classifies by HTTP status code
(401/403 → `HTTP_DENIED`, 404 → `HTTP_NOTFOUND`, else `HTTP_REQUEST`).
`syslog.py` is deliberately narrow — it only keeps lines matching a
short keyword list (OOM killer, segfaults, firewall drops), dropping
everything else, so routine syslog noise doesn't flood storage.

**`normalizer.py`** is the last cleanup pass before an event enters the
queue: it validates the IP address (rejecting or stripping malformed
ones, including the `::ffff:`-prefixed IPv4-mapped-IPv6 form some tools
emit), rejects empty messages, and sanity-checks the timestamp.

## Security considerations

- Parsers are regex-based rather than `eval`/format-string based, so a
  maliciously crafted log line (e.g. an attacker including shell
  metacharacters in a username to try to break parsing) can't execute
  code — at worst it fails to match and is dropped.
- IP validation in `normalizer.py` means a spoofed or malformed "IP"
  string can never reach the rule engine's per-IP counters or the
  firewall backends downstream.

## Testing

`tests/unit/test_parsers.py` (8 tests) covers each parser's main
message shapes plus explicit garbage-input and unrelated-line cases.
`tests/unit/test_normalizer.py` (4 tests) covers valid IPs, the
IPv6-mapped-IPv4 stripping case, invalid IPs, and empty messages.
`FileTailer` is exercised indirectly through the pipeline integration
path; a dedicated rotation test is a good addition once real log
rotation can be exercised in the VM lab (see `docs/dev-guide.md`).
