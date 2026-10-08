#!/usr/bin/env bash
# Local install for a Debian/Ubuntu VM. Run from the repo root.
# Does NOT enable active defense by default — general.mode stays "dry_run"
# in config/cypher.toml until you change it yourself, after reviewing
# config/allowlist.toml for your environment.
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
  echo "Run this as your normal user, not root. It will use sudo where needed." >&2
  exit 1
fi

echo "==> Creating venv"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"

echo "==> Creating data directories"
mkdir -p data/raw data/processed data/models data/geo data/mitre

echo "==> Creating the 'cypher' group and sharing the data directory with it"
sudo groupadd -f cypher
# The responder (root) writes data/responder.token; the unprivileged ingest and
# API processes (user cypher) must read it and write the SQLite database, so
# the data directory is group-owned by `cypher`, group-writable, and setgid so
# new files inherit the group.
sudo chgrp -R cypher data
sudo chmod -R g+rwX data
sudo chmod g+s data
echo "    Add yourself to the group so you can run the CLI/API unprivileged:"
echo "    sudo usermod -aG cypher \$USER   (log out/in to take effect)"

echo "==> Installing systemd unit files (edit paths inside them first!)"
echo "    sudo cp deploy/systemd/*.service /etc/systemd/system/"
echo "    sudo systemctl daemon-reload"

echo
echo "Install complete. Next steps:"
echo "  1. Review config/cypher.toml and config/allowlist.toml"
echo "  2. python scripts/set_admin_password.py   # set the dashboard password"
echo "  3. python scripts/generate_normal_traffic.py && cypher replay data/raw/auth_normal.log"
echo "  4. cypher train"
echo "  5. cypher start   (foreground, for testing — use systemd for real deployment)"
