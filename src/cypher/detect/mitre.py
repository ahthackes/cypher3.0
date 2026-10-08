"""Maps rule IDs to MITRE ATT&CK technique IDs for display on the
dashboard and in the final report.

Uses a small static lookup rather than the full downloaded ATT&CK JSON
for the mapping itself — data/mitre/enterprise-attack.json is kept
around so the dashboard can show each technique's full name and
description offline, but the rule -> technique-ID mapping needs to be
curated by hand anyway (an automatic match would be unreliable), so it
lives here as plain, auditable code.
"""
from __future__ import annotations

RULE_TO_MITRE: dict[str, list[str]] = {
    "ssh_bruteforce_5m": ["T1110.001"],          # Brute Force: Password Guessing
    "ssh_bruteforce_burst": ["T1110.001"],
    "ssh_invalid_user": ["T1110.001", "T1087"],  # + Account Discovery
    "sudo_failure_repeated": ["T1548.003"],       # Abuse Elevation Control Mechanism: Sudo
    "sudo_not_in_sudoers": ["T1548.003", "T1078"], # + Valid Accounts (misuse attempt)
    "web_401_burst": ["T1110"],
    "web_404_scan": ["T1595.002"],                 # Active Scanning: Vulnerability Scanning
    "web_sqli_pattern": ["T1190"],                 # Exploit Public-Facing Application
    # Windows
    "rdp_bruteforce_5m": ["T1110.001", "T1021.001"],     # Password Guessing + Remote Desktop Protocol
    "rdp_bruteforce_burst": ["T1110.001", "T1021.001"],
    "windows_network_logon_spray": ["T1110.003"],        # Brute Force: Password Spraying
    "windows_account_lockout": ["T1110"],
    "windows_admin_group_add": ["T1098", "T1078.003"],   # Account Manipulation + Local Accounts
}


def techniques_for_rule_hits(rule_ids: list[str]) -> list[str]:
    seen: list[str] = []
    for rid in rule_ids:
        for technique in RULE_TO_MITRE.get(rid, []):
            if technique not in seen:
                seen.append(technique)
    return seen
