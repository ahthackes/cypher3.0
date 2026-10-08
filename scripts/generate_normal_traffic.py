#!/usr/bin/env python3
"""Generates a synthetic auth.log file of "normal" SSH activity, for
training the ML models before you have real historical data, and for
demos. Mixes in a realistic spread of successful logins and the
occasional benign failure (a mistyped password), from a small, stable
set of "regular" IPs.

Usage:
    python scripts/generate_normal_traffic.py --n 2000 --out data/raw/auth_normal.log
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta

USERS = ["ahtsham", "deploy", "backup", "monitoring"]
REGULAR_IPS = ["192.168.1.10", "192.168.1.11", "10.0.0.5", "10.0.0.6"]


def generate(n: int, start: datetime) -> list[str]:
    lines = []
    ts = start
    for _ in range(n):
        ts += timedelta(seconds=random.randint(20, 400))
        user = random.choice(USERS)
        ip = random.choice(REGULAR_IPS)
        pid = random.randint(1000, 9999)
        stamp = ts.strftime("%b %d %H:%M:%S")
        if random.random() < 0.95:
            lines.append(f"{stamp} myhost sshd[{pid}]: Accepted password for {user} from {ip} port {random.randint(30000,60000)} ssh2")
        else:
            lines.append(f"{stamp} myhost sshd[{pid}]: Failed password for {user} from {ip} port {random.randint(30000,60000)} ssh2")
    return lines


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--out", default="data/raw/auth_normal.log")
    args = ap.parse_args()

    lines = generate(args.n, datetime.now() - timedelta(days=14))
    with open(args.out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} synthetic normal-traffic lines to {args.out}")
