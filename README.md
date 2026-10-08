# Cypher 2.0

Offline, privacy-preserving log anomaly detection and active defense for
**Linux and Windows** (one codebase). Built for the BS Cyber Security final year project at Riphah
International University, Faisalabad.

Cypher watches `auth.log`, `syslog`, and your web server's access log on Linux, or the
Security event log on Windows (logon failures, RDP brute force, new local admins),
scores activity with a combination of hand-written rules and machine
learning (Isolation Forest, always on; a lightweight PCA-based
reconstruction model, optional), and can automatically block the worst
offenders through your firewall — all without sending a single byte off
the machine.

**Status:** core pipeline (ingestion, rules, ML, storage, active
defense, dashboard) is implemented and tested (49 tests passing). See
`docs/architecture.md` for what's built vs. planned, and
`docs/fyp-report/` for the running project report.

## Quickstart (5 minutes, no root needed)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Generate a demo attack log and a demo "normal traffic" log, replay both:
bash scripts/simulate_attacks.sh
python scripts/generate_normal_traffic.py
cypher replay data/raw/auth_attack_demo.log --source-type auth_log
cypher replay data/raw/auth_normal.log --source-type auth_log

# Train the ML model on the normal traffic:
cypher train

# See what was detected:
cypher status

# Set up the dashboard login, then run it:
python scripts/set_admin_password.py
export CYPHER_ADMIN_PASSWORD_HASH='<paste the hash it printed>'
export CYPHER_SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
uvicorn cypher.api.app:create_app --factory --reload
# open http://127.0.0.1:8000
```

That's the whole system minus the parts that need root (the responder)
and a real log source (the tailer) — both of those need a Linux VM; see
`docs/user-guide.md` for the full lab setup.

## Windows

Same install, different config and service setup — see `deploy/windows/README.md`.
Quick demo on any OS (no Windows needed, it replays synthetic Event Log XML):

```bash
python scripts/generate_windows_demo.py
cypher --config config/cypher.windows.toml replay data/raw/windows_attack_demo.xml --source-type windows_security_log
cypher --config config/cypher.windows.toml status
```

## Running the tests

```bash
pip install -e ".[dev]"
pytest -v
```

## Project layout

See `docs/architecture.md` for the full breakdown. Short version:

- `src/cypher/ingest/` — tails log files, parses them into Events
- `src/cypher/detect/` — rules engine, ML scoring, fusion, severity policy
- `src/cypher/respond/` — the root-privileged firewall responder and its safety gate
- `src/cypher/api/` — the dashboard's FastAPI backend
- `web/` — the dashboard itself (one self-contained page)
- `config/` — `cypher.toml`, rule definitions, the allowlist
- `tests/` — unit + integration tests
- `scripts/` — demo data generators, admin setup, benchmarking
- `deploy/` — systemd units, Docker, packaging notes
- `docs/` — architecture, SRS, threat model, and the FYP report

## Safety defaults

Cypher ships in `general.mode = "dry_run"` — it will decide what it
*would* block and log that decision, but never touches your firewall,
until you deliberately switch to `"active"` in `config/cypher.toml`
after reviewing `config/allowlist.toml` for your own IP ranges. See
`docs/threat-model.md` for the full reasoning.

## License

MIT — see `LICENSE`.
