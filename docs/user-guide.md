# User guide

## 1. Try it without root (any machine)

Follow the Quickstart in the main `README.md`. This exercises every part
of the pipeline except the real-time file tailer (which needs a real
growing log file) and the responder (which needs root) — `cypher replay`
and the dashboard cover everything else.

## 2. Full install on a Linux VM

(Windows: see `deploy/windows/README.md` — same codebase, different log source,
firewall backend and service setup.)

```bash
git clone <your repo> cypher && cd cypher
bash scripts/install.sh
```

This creates a venv, installs Cypher, creates the `cypher` group and
shared `data/` directory (the responder IPC token lives there), and prints the remaining manual steps
(systemd units need you to edit the paths inside them first — they
assume `/opt/cypher`).

## 3. Configure

- `config/cypher.toml` — log paths, thresholds, firewall backend, mode.
  **Leave `general.mode = "dry_run"` until you've reviewed the alert
  feed on your own traffic.**
- `config/allowlist.toml` — **edit this before ever switching to
  `active` mode.** Add your SSH management IP and your VM's gateway.
- `config/rules.d/*.toml` — add your own rules here; any `.toml` file in
  this directory is picked up automatically.

## 4. Set up the dashboard login

```bash
python scripts/set_admin_password.py
```

Export the two printed/generated values as environment variables (or
put them in the `cypher-api.service` systemd unit) before starting the
API — see `deploy/systemd/cypher-api.service`.

## 5. Train the ML model

Needs at least 20 historical events in the database. Easiest path:

```bash
python scripts/generate_normal_traffic.py
cypher replay data/raw/auth_normal.log --source-type auth_log
cypher train
```

For a real deployment, let `cypher start` run against your real
`auth.log` for a few days first, so the model learns your actual usage
patterns, then run `cypher train`.

## 6. Run it

**Development/demo (foreground, one terminal each):**
```bash
cypher start                                            # ingestion + detection
sudo python -m cypher.respond.run_responder              # responder (needs root)
uvicorn cypher.api.app:create_app --factory              # dashboard API
```

**Production (systemd):**
```bash
sudo cp deploy/systemd/*.service /etc/systemd/system/
# edit the paths and env vars inside each unit first
sudo systemctl daemon-reload
sudo systemctl enable --now cypher-responder cypher-ingest cypher-api
```

Open `http://127.0.0.1:8000` and sign in.

## 7. Going from dry-run to active

1. Let Cypher run in `dry_run` for at least a few days.
2. Review `cypher status` / the dashboard's alert feed for false
   positives.
3. Confirm `config/allowlist.toml` covers every IP you'd be upset to
   lose access from.
4. Set `general.mode = "active"` in `cypher.toml` and restart the
   responder and ingest services.
5. Watch the dashboard closely for the first day.
