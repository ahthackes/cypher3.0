#!/usr/bin/env python3
"""Generates a bcrypt hash of an admin password for the dashboard.

Interactive:
    python scripts/set_admin_password.py
Non-interactive (used by deploy/windows/install.ps1; password on stdin so it
never appears on a command line or in process listings):
    echo "<password>" | python scripts/set_admin_password.py --stdin

Interactive mode prints the export line to run before starting the API:
    export CYPHER_ADMIN_PASSWORD_HASH='$2b$12$....'
    export CYPHER_SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
--stdin mode prints only the bare hash.
"""
import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cypher.api.auth import hash_password  # noqa: E402

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--stdin", action="store_true", help="read the password from stdin; print only the hash")
    args = ap.parse_args()

    if args.stdin:
        pw = sys.stdin.readline().rstrip("\r\n")
        if len(pw) < 8:
            print("Password must be at least 8 characters.", file=sys.stderr)
            sys.exit(1)
        print(hash_password(pw))
        sys.exit(0)

    pw = getpass.getpass("New admin password: ")
    confirm = getpass.getpass("Confirm: ")
    if pw != confirm:
        print("Passwords did not match.", file=sys.stderr)
        sys.exit(1)
    print("\nAdd this to your environment before starting the API:\n")
    print(f"export CYPHER_ADMIN_PASSWORD_HASH='{hash_password(pw)}'")
