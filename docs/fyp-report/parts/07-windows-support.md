# Part 7 — Windows support (cross-platform)

## Files covered

New: `src/cypher/platform_utils.py`, `src/cypher/ingest/parsers/windows_security.py`,
`src/cypher/ingest/win_tailer.py`, `src/cypher/respond/backends/windows_firewall.py`,
`src/cypher/respond/ipc_token.py`, `config/cypher.windows.toml`,
`config/rules.d/windows_logon.toml`, `scripts/generate_windows_demo.py`,
`deploy/windows/{install,uninstall,run-ingest,run-responder,run-api}.ps1`,
`deploy/windows/README.md`.
Changed: `respond/responder.py`, `respond/client.py`, `settings.py`, `pipeline.py`,
`__main__.py`, `detect/mitre.py`, `storage/db.py`, `api/app.py`, `pyproject.toml`.

## Purpose

Make Cypher run on Windows from the same codebase (NFR-5), instead of forking a second
project. The design question was *what actually differs between the two OSes*; the answer
is three things — where logs come from, what a log record looks like, and how to block an
IP — plus how privileged services are run. Everything else (rules, ML, fusion, severity,
MITRE mapping, SQLite, safety gate, API, dashboard) is shared and unchanged.

## Design

**Log source.** Linux logs are text files tailed line by line. Windows has no text auth
log: logon events live in the Security Event Log, a binary store read through an API.
`WindowsEventLogTailer` exposes the same `poll_once()/follow()/close()` shape as
`FileTailer`, so `pipeline.py` treats them alike and only chooses between them by source
key. It uses pywin32's modern `EvtQuery/EvtNext/EvtRender` calls, which render events as
XML with *named* fields (the older `ReadEventLog` only yields positional strings, which
shift between Windows versions). It remembers the last `EventRecordID` and queries only
newer records, filtered in the XPath to the five event IDs the parser understands, so the
very chatty Security log is not dragged through Python.

**Parsing.** `WindowsSecurityParser` is a pure function of one event's XML (no Windows API
calls), which is what allows full testing on Linux with synthetic XML. Mapping to the shared
`EventType` vocabulary: 4625 failed logon → `AUTH_FAILURE` (service `rdp` if LogonType 10,
else `windows_logon`); 4624 → `AUTH_SUCCESS`; 4740 lockout → `AUTH_FAILURE`; 4672 special
privileges → `PRIV_ESCALATION_SUCCESS` (ignoring SYSTEM/service/machine accounts, which
fire constantly); 4732 member added to a local group → `PRIV_ESCALATION_SUCCESS` only for
*Administrators*. Windows has no `sudo`, so these are the nearest real equivalents. XML
containing a DTD/entity declaration is rejected outright — Event Log XML never legitimately
has one, so there is no reason to hand it to an entity-expanding parser.

**Rules.** `windows_logon.toml` mirrors the SSH rules for RDP (5 failures/5 min = 70,
10 failures/60 s = 95), adds password-spray and lockout rules, and flags additions to the
Administrators group (85). Each has a MITRE ATT&CK mapping (e.g. T1110.001 + T1021.001 for
RDP brute force); a test fails if any shipped rule lacks one.

**Blocking.** `WindowsFirewallBackend` runs `netsh advfirewall firewall add rule
name="Cypher Block <ip>" dir=in action=block remoteip=<ip>`. The fixed name prefix lets
Cypher find and remove only its own rules (same isolation goal as the dedicated nftables
table). The command is an argument *list*, never a shell string, and the IP is validated
with `ipaddress` first; a test feeds it injection attempts (`"1.2.3.4 remoteip=0.0.0.0/0"`,
`"1.2.3.4; calc"`) and asserts nothing reaches `netsh`.

**Responder IPC — the one real redesign.** The Linux design used a Unix domain socket
protected by group permissions. Windows has no equivalent that is simple from Python. The
responder now listens on **loopback TCP** (`127.0.0.1:8765`) and every request carries a
random 256-bit token. This single mechanism works identically on both OSes and is tested
with real socket round trips. The cost is a weaker boundary than a group-permissioned Unix
socket: any local user *can connect*, so the token file's access control is now what protects
the firewall (Linux: root + `cypher` group, mode 0640; Windows: ACL granting SYSTEM,
Administrators and the API's LOCAL SERVICE account read-only). Requests with a missing or
wrong token are rejected before any logic runs, and valid ones are still re-checked by the
safety gate. See `docs/threat-model.md`.

**Service setup.** Three scheduled tasks created by `install.ps1`: Responder (SYSTEM — only
one that edits firewall rules), Ingest (SYSTEM — reading the Security log requires it), API
(LOCAL SERVICE, a low-privilege built-in account), mirroring the Linux privilege split. Secrets
for the API live in `data\api.env`, ACL'd to the accounts that need them; the password is passed
to the hasher on stdin so it never appears in a process listing.

## Problems found while building this (and fixed)

Building the second platform exposed defects that the Linux-only version had hidden, which is
itself useful evidence for the evaluation chapter:

1. **Auto-block could never trigger.** The highest rule score was 90 but CRITICAL starts at
   95, so with the shipped rules and ML disabled nothing could ever be blocked automatically
   — FR-5 was effectively off. Found because the Windows replay printed "0 would trigger
   auto-block". Fixed (high-confidence burst rules now score 95) and locked in with a test that
   asserts, for *both* configs, that some rule can reach the CRITICAL threshold; the test was
   verified to fail when the bug is reintroduced. The earlier Linux integration test had asserted
   `severity in (HIGH, CRITICAL)`, which is loose enough to have hidden this — now `== CRITICAL`.
2. **Blocks never expired.** `expire_stale_blocks()` existed but nothing called it, and its query
   would have re-issued an unblock for the same old row on every sweep. Fixed: a correct
   "latest action is an expired BLOCK" query, an idempotent sweep, a lock (several request threads
   share one SQLite connection and one firewall), and a background sweeper thread.
3. **Repeated blocks of the same IP.** An attacker keeps generating alerts, each asking the
   firewall to block the same address again — duplicate rules on iptables and Windows Firewall, and
   a burned hourly rate limit. The responder now treats an already-blocked IP as a no-op.
4. **IPC token unreadable on Linux.** The responder (root) created the token `0600`, so the
   unprivileged API/ingest processes could never read it; every call would have failed in a real
   deployment. The tests ran as a single user, which could not reveal it. Fixed with a `cypher`
   group and mode 0640 (with a test using a real group).
5. **Dashboard showed Linux settings on Windows.** `create_app()` always loaded
   `config/cypher.toml`. Now selectable via `CYPHER_CONFIG`.
6. **Backslash paths in the Windows config** silently failed to resolve (and need escaping in TOML).
   Windows Python accepts forward slashes, so one style now works everywhere.

## Testing

Automated (all pass on Linux, no Windows needed): `test_windows_parser.py` (12: each event ID, noise
filtering, garbage input, DTD rejection, 7-digit timestamps), `test_windows_firewall_backend.py` (6:
exact `netsh` commands, injection refusal, error surfacing, parsing the rule list),
`test_windows_tailer.py` (6: a fake Evt API checks first-poll-no-replay, only-new-events-once, the
event-ID filter, Windows' "no more items" error, empty log), `test_ipc.py` (9: real TCP round trip,
missing/wrong token rejected, malformed JSON doesn't kill the server, allowlist enforced through the
socket, token file permissions), `test_windows_pipeline.py` (5: synthetic RDP brute force reaches
CRITICAL and would auto-block, admin-group alert, benign traffic silent, MITRE coverage, the
reachability guard), plus new cases in `test_responder.py` (dedup, expiry, sweeper) and `test_api.py`.

## What is NOT verified (be explicit about this in the report)

- `win_tailer.py` against a **real** Security log. Its logic is tested with a fake API; the real
  pywin32 calls have never run. It is the least-verified file in the project.
- The PowerShell scripts in `deploy/windows/` have never been executed (no PowerShell was available
  where they were written), including the icacls permission model and scheduled-task registration.
- Real `netsh` behaviour (rule creation, elevation, localised output on non-English Windows —
  `list_blocked` parses the English "Rule Name:" label).
- That the Windows event fields behave as documented for every logon type (e.g. RDP with Network Level
  Authentication is logged as LogonType 3, not 10, on some configurations, so such attempts would be
  counted under `windows_logon`, whose threshold is higher).

`docs/dev-guide.md` has a nine-step Windows first-run checklist covering each of these.
