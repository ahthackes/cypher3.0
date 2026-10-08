# Architecture

## Why three processes, not one

The original proposal describes Cypher as a single program. In practice
it needs root to touch the firewall, but a web dashboard with a login
form should never run as root — if the dashboard has a bug, an attacker
who exploits it should not thereby get a root shell. So Cypher is split
into three processes, each with the minimum privilege it needs:

| Process | Runs as | Can do |
|---|---|---|
| **ingest + detect** (`cypher start`) | unprivileged `cypher` user, read access to `/var/log` | tail logs, parse, run rules + ML, write to SQLite |
| **responder** (`cypher.respond.run_responder`) | root, `CAP_NET_ADMIN` | the ONLY process that runs `nft`/`iptables`/`ufw` |
| **API** (`uvicorn cypher.api.app:create_app`) | unprivileged `cypher` user | serves the dashboard, reads SQLite, asks the responder (never the firewall directly) to block/unblock |

This also gives you the fault-tolerance the proposal's non-functional
requirements ask for: if the API or the ML model crashes, log ingestion
keeps running untouched, because it's a different process.

## One codebase, two operating systems

Cypher runs on Linux and Windows from the same source tree. Only three things are
platform-specific, and each sits behind an interface so the rest of the system
(rules, ML, storage, safety gate, API, dashboard) is identical on both:

| Concern | Interface | Linux | Windows |
|---|---|---|---|
| Reading logs | `tailer.follow()` yielding raw records; a `BaseParser` per source | `FileTailer` on `auth.log` etc. (`ingest/tailer.py`) | `WindowsEventLogTailer` on the Security channel (`ingest/win_tailer.py`) |
| Understanding a record | `BaseParser.parse_line() -> Event` | `AuthLogParser`, `SyslogParser`, `WebAccessParser` | `WindowsSecurityParser` (event XML; IDs 4624/4625/4672/4732/4740) |
| Blocking an IP | `FirewallBackend.block/unblock/list_blocked` | `nftables`, `iptables`, `ufw` | `windows_firewall` (`netsh advfirewall`, rules named `Cypher Block <ip>`) |

Parsers map OS-specific records onto the shared `EventType` vocabulary
(`AUTH_FAILURE`, `PRIV_ESCALATION_SUCCESS`, ...), so a rule like "10 failed logons in
60 s from one IP" is written once per *service name* (`sshd` or `rdp`) and everything
downstream — fusion, severity, MITRE mapping, the responder — doesn't know or care
which OS produced the event. Windows has no `sudo`; the nearest real equivalents
(adding someone to the local Administrators group, sensitive privileges for an
ordinary account) are mapped to `PRIV_ESCALATION_SUCCESS`.

Which sources run is decided by config alone: a source set to `""` is disabled, so
`config/cypher.toml` (Linux) and `config/cypher.windows.toml` (Windows) are the only
difference between the two deployments.

### Process separation on each OS

| Process | Linux | Windows |
|---|---|---|
| responder (only one that edits the firewall) | root, systemd | SYSTEM, scheduled task |
| ingest + detect | `cypher` user, systemd | SYSTEM (needed to read the Security log), scheduled task |
| API / dashboard | `cypher` user, systemd | LOCAL SERVICE (low privilege), scheduled task |

### Responder IPC (changed from the first design)

The first version used a Unix domain socket guarded by group permissions. That does
not exist on Windows, so the responder now listens on **loopback TCP**
(`127.0.0.1:8765`) with a **shared-secret token** on every request. This one mechanism
works unchanged on both OSes and is covered by real round-trip tests. The trade-off is
documented in `docs/threat-model.md`: loopback TCP can be connected to by any local
user, so the token file's permissions are now what protects the firewall.

## End-to-end flow

See the flow diagram shared earlier in this project's planning
conversation (log sources → ingestion → rule engine + ML engine → score
fusion → severity policy → event store / active defense / dashboard
API). The code mirrors that diagram directly:

1. `ingest/tailer.py` watches each configured log file, handling
   rotation by inode comparison.
2. `ingest/parsers/*.py` turn a raw line into an `Event`
   (`cypher/models.py`).
3. `ingest/normalizer.py` validates/cleans the event.
4. `bus.py` queues it for the detection loop (`pipeline.py`).
5. `detect/rules/engine.py` checks it against `config/rules.d/*.toml`,
   using `features/windows.py` for "N times in M seconds" rules.
6. `detect/ml/isolation_forest.py` (and, if enabled,
   `detect/ml/autoencoder.py`) score it using
   `features/vectorizer.py`'s feature vector.
7. `detect/fusion.py` combines both into one 0-100 score.
8. `detect/policy.py` maps that score to a severity and decides whether
   it's CRITICAL enough to auto-block.
9. The alert is written to SQLite (`storage/db.py`). If auto-block
   applies, `respond/client.py` asks the responder daemon to act — which
   re-checks `respond/safety.py` itself before doing anything.
10. The dashboard (`web/index.html`) polls/streams `api/routes/*.py` and
    `api/ws.py` to show all of this live.

## What's implemented vs. planned

**Implemented and tested** (see `tests/`, 49 passing):
ingestion + parsing (auth.log, syslog, nginx access log), the rule
engine, feature extraction, Isolation Forest training/scoring, score
fusion + severity policy, MITRE technique mapping, the safety gate
(allowlist/dry-run/rate-limit), all three firewall backends (nftables,
iptables, ufw) with mockable command runners, the responder daemon's
logic, SQLite storage with an append-only audit log, the FastAPI
dashboard backend with session auth, and the dashboard UI itself.

**Deliberately simplified from the original proposal, with reasoning**
(see the planning conversation and `docs/ml-evaluation.md`):
- The autoencoder is a PCA-based reconstruction-error model, not
  TensorFlow/Keras — same interface, swappable later, far lighter on
  the "i5, 8GB RAM, <15% CPU" hardware budget. **Disabled by default.**
- Log templating (`features/templating.py`) is regex-based rather than
  a full Drain3 tree — adequate for the three log families this project
  targets.
- GeoIP (`geo/geoip.py`) and the MITRE ATT&CK JSON lookup degrade
  gracefully to "no data" if you haven't downloaded the (license-
  restricted, so not bundled) database files yourself.

**Not yet validated on real machines** — the Linux tailer's log rotation, the real
`nft`/`iptables`/`ufw` calls, and, on Windows, the live Event Log reader
(`ingest/win_tailer.py`), the real `netsh` calls, and the PowerShell installer in
`deploy/windows/`. All of these have automated tests of their logic (using fakes for
the OS calls), but none has run against a real kernel or Event Log yet. The `.deb`
package is still a placeholder. `docs/dev-guide.md` has the checklist for each OS.
