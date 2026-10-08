# Part 4 — Active defense

## Files covered

`src/cypher/respond/safety.py`, `src/cypher/respond/backends/base.py`,
`src/cypher/respond/backends/nftables.py`,
`src/cypher/respond/backends/iptables.py`,
`src/cypher/respond/backends/ufw.py`,
`src/cypher/respond/backends/__init__.py`,
`src/cypher/respond/responder.py`, `src/cypher/respond/run_responder.py`,
`src/cypher/respond/client.py`, `src/cypher/respond/audit.py`

## Purpose

Implements FR-5 (autonomous blocking on critical anomaly score) safely.
This is the most safety-critical code in the project — it's the one
part of the system that can, if wrong, lock the administrator out of
their own machine — so it gets the most defensive design and the
heaviest documentation-in-code.

## How it works

**`safety.py`** is the gate every block request must pass, regardless
of caller. Three independent checks, all must pass: (1) **allowlist** —
never block an IP in `config/allowlist.toml`, loaded fresh from the
TOML file and checked with Python's `ipaddress` module against CIDR
ranges; an unparseable IP fails safe (treated as allowlisted, refusing
to act on it) rather than failing open; (2) **dry run** — if
`general.mode != "active"`, log what would happen and stop, implemented
as a simple string comparison with no way to bypass except editing the
config file itself; (3) **rate limit** — no more than
`max_blocks_per_hour` real blocks, queried from the database's actual
block history rather than an in-memory counter (so it survives a
process restart). `evaluate()` returns a `SafetyDecision` with which
check (if any) failed and why — this feeds directly into the audit log
and the alert's own explanation, so every decision is traceable.

**The three backends** (`nftables.py`, `iptables.py`, `ufw.py`) all
implement the same `FirewallBackend` interface
(`block`/`unblock`/`list_blocked`). Each uses a dedicated
table/chain/rule-set (`cypher_filter`/`cypher_blocklist` for nftables, a
`CYPHER` chain jumped from `INPUT` for iptables) so Cypher's rules are
isolated from — and can't accidentally clobber — any other firewall
rules already on the box. Every backend accepts an injectable
`CommandRunner` function in its constructor (defaulting to
`subprocess.run`), which is what makes `tests/unit/test_responder.py`
able to test the full block/unblock/allowlist/rate-limit logic without
actually needing `nft`, `iptables`, or root privileges in the test
environment.

**`responder.py`** is the root-privileged daemon design: `handle_request()`
is the core logic (block/unblock/status), kept separate from the
socket-server plumbing (`_RequestHandler`, `_UnixSocketServer`) so it
can be unit-tested by calling it directly, which is exactly what
`tests/unit/test_responder.py` does. Critically: **the responder
re-runs the safety check itself** for every block request — it does
not trust that the caller (the detection pipeline, or the API) already
checked. This matters because the responder's socket is the trust boundary;
anything that can write to that socket should be treated as an
untrusted caller whose *intent* might be legitimate but whose *request*
still needs independent validation. `expire_stale_blocks()` releases
every IP whose latest action is a block past its TTL, run every
`respond.expiry_check_seconds` by a background thread (a lock serialises it
against request handling). An IP that is already blocked is a no-op rather
than a second firewall rule. See Part 7 for the defects found in the first
version of this logic.

**`run_responder.py`** is the systemd-facing entry point — a thin
`main()` that loads settings, opens the database, and calls
`run_responder()`. Kept separate from the main `cypher` CLI
(`__main__.py`) specifically so the process that runs as root imports
as little of the rest of the codebase as possible, per its own
docstring.

**`client.py`'s `ResponderClient`** is what the unprivileged detection
pipeline and API use to talk to the responder — a small JSON-lines
protocol over a loopback TCP socket, each request carrying a shared-secret token (see Part 7) (`{"action": "block", "ip": ..., ...}` →
`{"ok": true, ...}`). This is the ONLY code path in the entire
unprivileged side of the system that can influence the firewall.

**`audit.py`** is a thin wrapper around the database's append-only
`audit_log` table, used so the responder's own code doesn't need to
import the full `Database` class's surface area directly in its hot
path — every action it takes (block, unblock, dry-run-skip, rate-limit,
allowlist-skip) is logged here with who/what/why.

## Security considerations (see also `docs/threat-model.md`)

- Privilege separation: the responder is the only process with
  `CAP_NET_ADMIN`; everything else, including the API that accepts
  manual block requests from the dashboard, is unprivileged.
- Defense in depth: even if a bug somehow let an unsafe request reach
  the responder's socket, the responder re-checks allowlist/dry-run/
  rate-limit itself rather than trusting the caller.
- Fail-safe defaults: unparseable IP → treated as allowlisted (refuse
  to act); dry-run is the shipped default; the allowlist ships
  pre-populated with loopback and private ranges.

## Testing

`tests/unit/test_safety.py` (5 tests) covers all three gate checks plus
the fail-safe-on-unparseable-IP case. `tests/unit/test_responder.py`
(5 tests) uses a `FakeBackend` to test the full responder logic —
dry-run skip, active-mode block, allowlist skip, unblock, and unknown
action handling — without needing root or real firewall tools. The
nftables/iptables/ufw backends' actual OS command construction is
exercised by inspecting the `CommandRunner` call arguments in the
backend modules' design (injectable runner); a full test against real
`nft`/`iptables`/`ufw` binaries needs your own VM lab, per
`docs/dev-guide.md`'s lab-testing section.
