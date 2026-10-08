#!/usr/bin/env bash
# Generates a synthetic attack log you can feed through `cypher replay`
# for a demo. This writes a FILE — it does not touch any real network
# interface or send any real traffic. For an actual live-fire test
# against your own lab VM, see docs/dev-guide.md ("Lab testing") instead,
# and only ever point real attack tools at infrastructure you own.
set -euo pipefail

OUT="${1:-data/raw/auth_attack_demo.log}"
ATTACKER_IP="203.0.113.77"   # TEST-NET-3, RFC 5737 — not a real routable address
HOST="myhost"
NOW=$(date +"%b %d %H:%M:%S")

mkdir -p "$(dirname "$OUT")"
: > "$OUT"

echo "# Benign baseline" >&2
for i in $(seq 1 5); do
  echo "$(date +"%b %d %H:%M:%S") $HOST sshd[$((1000+i))]: Accepted password for deploy from 192.168.1.10 port 4100$i ssh2" >> "$OUT"
done

echo "# SSH brute-force burst from $ATTACKER_IP" >&2
for i in $(seq 1 15); do
  echo "$(date +"%b %d %H:%M:%S") $HOST sshd[$((2000+i))]: Failed password for invalid user admin from $ATTACKER_IP port 5000$i ssh2" >> "$OUT"
done

echo "# Sudo abuse attempt" >&2
echo "$(date +"%b %d %H:%M:%S") $HOST sudo: baduser : user NOT in sudoers ; TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash" >> "$OUT"
echo "$(date +"%b %d %H:%M:%S") $HOST sudo: baduser is not in the sudoers file.  This incident will be reported." >> "$OUT"

echo "Wrote demo attack log to $OUT"
echo "Try: cypher replay $OUT --source-type auth_log"
