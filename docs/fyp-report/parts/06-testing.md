# Part 6 — Test suite

## Files covered

`tests/conftest.py`, `tests/unit/*.py`, `tests/integration/*.py`

## Summary

100 automated tests, all passing, run in about 10 seconds with no network
access (only loopback sockets), no root privileges and no Windows machine required.

| File | Tests | What it proves |
|---|---|---|
| `test_parsers.py` | 8 | Each log parser extracts the right fields from real-shaped log lines, and never raises on garbage input |
| `test_normalizer.py` | 4 | IP validation, IPv6-mapped-IPv4 stripping, empty-message rejection |
| `test_windows.py` | 3 | Sliding-window counting is correct and keys don't interfere |
| `test_rule_engine.py` | 5 | The *actual shipped* `config/rules.d/*.toml` files load and fire correctly at/below threshold |
| `test_fusion_policy.py` | 7 | Score fusion math, capping, and severity threshold boundaries |
| `test_safety.py` | 5 | Allowlist, dry-run, rate-limit, and fail-safe-on-bad-IP all independently block an unsafe action |
| `test_windows_parser.py` | 12 | Windows Security event XML → shared `Event` model, noise filtering, DTD rejection (Part 7) |
| `test_windows_firewall_backend.py` | 6 | Exact `netsh` commands, IP-injection refusal |
| `test_windows_tailer.py` | 6 | Record-ID bookkeeping with a fake Windows Event API |
| `test_ipc.py` | 9 | Real loopback-TCP round trips, token auth, token file permissions |
| `test_windows_pipeline.py` (integration) | 5 | Windows attack replay reaches CRITICAL; rules can reach the auto-block threshold on both OSes |
| `test_responder.py` | 10 (was 5; adds dedup, TTL expiry, sweeper) | The responder's full decision logic, using a fake firewall backend |
| `test_db.py` | 6 | SQLite storage: events, alerts, active-vs-expired blocks, audit log |
| `test_features.py` | 4 | Log templating stability and feature vector shape/behavior |
| `test_api.py` | 8 | Auth (401 unauthenticated, wrong password, correct login/logout), protected routes, dashboard + vendored assets served |
| `test_pipeline_replay.py` (integration) | 3 | Full parse→rules→fusion→policy chain on a realistic brute-force log; Isolation Forest correctly scores an obvious outlier higher after training; benign traffic produces zero rule hits |

## Design choices worth noting in the report

- **Tests use the real shipped config**, not fixtures that duplicate it
  (`test_rule_engine.py` and `test_safety.py` load
  `config/rules.d/` and `config/allowlist.toml` directly). This means a
  typo in the actual configuration breaks the test suite, which is a
  stronger guarantee than testing a parallel copy of the config would
  give.
- **Privileged operations are tested via dependency injection, not
  mocking at the subprocess level.** The firewall backends accept an
  injectable `CommandRunner`; the responder tests swap in a
  `FakeBackend` entirely. This tests the actual decision logic
  (safety checks, which backend method gets called, in what order)
  without needing root or real firewall tools in CI.
- **The API tests exercise the real app factory and real SQLite file**,
  not a mocked database — `test_api.py`'s fixture seeds the exact
  SQLite file `create_app()` will open, so these tests catch real
  wiring bugs (an early version of this fixture pointed at the wrong
  file and the test correctly failed, catching the mistake — see this
  file's git history / the development conversation for that example).

## What's not yet covered (honest gap, for the report)

- `FileTailer`'s log-rotation handling is implemented but not yet
  unit-tested against an actual `logrotate`-style file replacement —
  needs either a more elaborate test harness or validation in the VM
  lab (`docs/dev-guide.md`).
- The nftables/iptables/ufw backends' exact command-line construction
  is reviewed by reading the code, not asserted against captured
  `CommandRunner` call arguments in a dedicated test — a reasonable
  next addition.
- CI (`.github/workflows/ci.yml`) runs `pytest -v` on every push but has
  not yet actually executed on GitHub Actions infrastructure, since the
  repository hasn't been pushed there yet.
