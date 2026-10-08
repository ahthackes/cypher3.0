# Threat model

This document covers two things: what Cypher is designed to defend
against, and — just as important for a tool with root-level firewall
access — what could go wrong with Cypher itself.

## What Cypher defends against

- SSH brute-force and credential-stuffing attempts (`ssh_bruteforce_*`
  rules + the ML outlier path)
- Privilege-escalation abuse: sudo attempts by users not in sudoers, or
  repeated sudo auth failures
- Web reconnaissance and exploitation: 401/403 bursts, 404 path
  scanning, SQL-injection patterns in request paths

## What Cypher does NOT defend against

- Attacks that don't appear in the three log sources it reads (no
  application-level audit log, no EDR-style process/syscall monitoring)
- A sufficiently slow, low-and-slow brute force that stays under every
  rule's count threshold and doesn't look anomalous to the ML model —
  this is a real limitation of threshold- and window-based detection and
  should be stated plainly in the FYP evaluation, not hidden
- Attacks against services Cypher isn't configured to watch
- An attacker who has already achieved root on the box — at that point
  they can disable Cypher itself

## Cypher's own attack surface, and how it's mitigated

| Risk | Mitigation |
|---|---|
| A bug in the unprivileged API/dashboard leads to RCE | The API never runs as root and has no `CAP_NET_ADMIN` — see `architecture.md`'s three-process split. Compromising it does not, by itself, grant firewall control. |
| A malicious or malformed log line crashes the parser | Every parser returns `None` on anything it doesn't recognize rather than raising; `normalizer.py` validates IPs and timestamps before anything downstream sees them. |
| Auto-block locks the admin out of their own VM | `respond/safety.py`'s allowlist check runs before every block, independent of score; ships with `127.0.0.1`, `::1`, and private ranges pre-populated — **edit `config/allowlist.toml` for your own management IP before switching to `active` mode.** |
| A feedback loop or misconfigured rule causes a block storm | `respond/safety.py` enforces `max_blocks_per_hour`, independent of the allowlist check. |
| An attacker spoofs their source IP to get a legitimate IP blocked (a denial-of-service against someone else) | This is a real, unsolved limitation of any IP-based auto-block system. Mitigation: start in `dry_run` mode, review the alert feed for false positives, and only promote to `active` once you trust the rule/ML tuning for your environment — see `ml-evaluation.md`. |
| The responder's socket is reachable by any local process | The responder listens on loopback TCP (`127.0.0.1:8765`), which works the same on Linux and Windows but — unlike a Unix socket with group permissions — can be *connected to* by any local user. So every request must carry a random 256-bit token (`respond/ipc_token.py`) stored in a file only the right accounts can read: root + the `cypher` group (mode 0640) on Linux; SYSTEM, Administrators and the API's LOCAL SERVICE account (read-only) via ACL on Windows. A request with a missing or wrong token is rejected before it reaches any logic, and valid requests are *still* re-checked against the safety gate. **Residual risk:** anyone who can read the token file can ask the responder to block (non-allowlisted) IPs, so protecting that file is protecting the firewall. |
| Dashboard credentials leak | Single local admin account, bcrypt-hashed password stored only as an env var (never in a config file or the repo), signed+expiring session cookie — see `api/auth.py`. |

## Dry-run as the default, not an afterthought

`general.mode = "dry_run"` in `config/cypher.toml` is the shipped
default. In this mode, every block decision is evaluated and logged
(you can see exactly what Cypher *would* have done, including which
rule or ML score triggered it) but no firewall command is ever run. This
is deliberate: a security tool that can lock you out of your own
machine should prove itself trustworthy on your own logs before it's
given the ability to act.
