# Developer guide

## Running tests

```bash
pip install -e ".[dev]"
pytest -v                    # all 49 tests
pytest tests/unit             # fast, no I/O beyond tmp SQLite files
pytest tests/integration      # pipeline + ML round-trip
pytest --cov=cypher           # coverage report
```

All tests run against real code paths (no network, no root needed) —
`tests/unit/test_responder.py` swaps in a fake firewall backend so the
responder's safety logic is tested without needing `nft`/`iptables`
installed; `tests/unit/test_safety.py` and `test_rule_engine.py` load
the actual shipped `config/` files rather than fixtures, so a config
typo breaks the test suite, not just production.

## Adding a new rule

Add a `[[rule]]` block to any `.toml` file in `config/rules.d/` (or a
new file — anything matching `*.toml` is picked up). See
`detect/rules/loader.py` for the full `Rule` schema. No code change or
restart-of-the-whole-system needed, just a restart of `cypher start`.

## Adding a new log source / parser

1. Add a parser class in `ingest/parsers/` implementing `BaseParser`
   (`parse_line(line) -> Event | None`) — see `ingest/parsers/auth.py`
   for the pattern.
2. Register it in `ingest/parsers/__init__.py`'s `PARSERS_BY_SOURCE`.
3. Add the log path to `[sources]` in `cypher.toml`.
4. Write unit tests following `tests/unit/test_parsers.py`'s pattern:
   one test per message shape, plus a "garbage input doesn't crash"
   test.

## Lab testing (needs two VMs — your own, never someone else's)

1. **Target VM**: Ubuntu/Debian, Cypher installed per
   `user-guide.md`, `general.mode = "dry_run"`.
2. **Attacker VM**: Kali or any distro with `hydra`, `nmap`, `nikto`.
   Both VMs on a host-only/NAT network you control.
3. From the attacker VM:
   ```bash
   hydra -l testuser -P wordlist.txt ssh://<target-ip>
   nmap -sV <target-ip>
   nikto -h http://<target-ip>
   ```
4. On the target, watch `cypher status` / the dashboard. Confirm the
   expected rules fire (`ssh_bruteforce_burst`, `web_404_scan`, etc.)
   and that the fused score and severity match what you'd expect.
5. Once satisfied, flip to `active` mode (see `user-guide.md` §7) and
   repeat — confirm the attacker IP actually gets dropped
   (`nft list set inet cypher_filter cypher_blocklist` or the
   equivalent for your backend) and that it expires after
   `block_ttl_seconds`.
6. Record actual log-to-block latency with a timestamp on both ends —
   this is the number that goes in the FYP report against the ≤2.5s
   requirement, not the synthetic benchmark alone.

## Windows first-run checklist (needs a Windows VM)

The parser, rules, firewall command construction and IPC are tested on any OS. These
steps cover what only a real Windows machine can prove — run them in order in a throwaway
VM, in `dry_run` mode, and note any failure in the FYP report (it is a finding, not a failure of the project):

1. `deploy\windows\install.ps1` completes without errors; `Get-ScheduledTask 'Cypher*'` lists three tasks.
2. `auditpol /get /category:"Logon/Logoff"` shows Logon success+failure enabled.
3. As Administrator: `pip show pywin32`, then
   `python -c "from cypher.ingest.win_tailer import WindowsEventLogTailer as T; t=T(); print(t.poll_once()); print(t._last_record_id)"`
   — expect `[]` and a non-zero record id. If this raises, `win_tailer.py` needs fixing: that is the least-verified file in the project.
4. Fail a logon on purpose (wrong password at the lock screen, or `runas /user:nobody cmd`), wait ~2 s, poll again — you should get one XML record containing `<EventID>4625</EventID>`.
5. Feed that record to the parser: confirm `src_ip`, `user` and `service` ("rdp" only for LogonType 10) are what you expect.
6. From a second VM, fail RDP logins 10+ times in a minute. Confirm `rdp_bruteforce_burst` fires on the dashboard (http://127.0.0.1:8000) and the alert is CRITICAL.
7. Add the second VM's IP to *neither* the allowlist nor dry-run exemptions, set `mode = "active"`, restart the responder + ingest tasks, repeat step 6. Confirm `netsh advfirewall firewall show rule name="Cypher Block <ip>"` lists the rule and RDP from that VM is now refused.
8. Wait for `block_ttl_seconds` (lower it to 120 for the test) and confirm the rule is removed (the responder sweeps for expired blocks every `respond.expiry_check_seconds`, default 30 s, so allow up to that long after the TTL).
9. `deploy\windows\uninstall.ps1` removes the tasks and all `Cypher Block *` rules.

## Code style

`ruff` is configured via `pyproject.toml`'s dev dependencies. Run
`ruff check src tests` before committing; `.pre-commit-config.yaml` runs
it automatically if you `pip install pre-commit && pre-commit install`.

## Report-as-you-go

Per the project's working agreement: every new file or significant
change should get a short entry in `docs/fyp-report/parts/` (purpose,
how it works, security considerations, how it's tested) as it's built,
not reconstructed at the end. See `docs/fyp-report/README.md`.
