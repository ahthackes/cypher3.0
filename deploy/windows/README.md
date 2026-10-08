# Cypher on Windows

Same codebase as Linux; Windows differs in three places:

| | Linux | Windows |
|---|---|---|
| Log source | `/var/log/auth.log`, syslog, nginx | Windows **Security** event log (`windows_security_log = "Security"`) |
| Firewall | nftables / iptables / ufw | Windows Firewall via `netsh advfirewall` (`backend = "windows_firewall"`) |
| Service manager | systemd units | Scheduled tasks (SYSTEM / LOCAL SERVICE), created by `install.ps1` |

Config file: `config/cypher.windows.toml` (forward slashes work in paths on Windows;
avoid backslashes, which TOML treats as escapes).

## Status — read this first

The detection pipeline (parser, rules, ML, storage, responder logic, Windows Firewall
command construction, token IPC) is covered by automated tests that run on any OS,
including a replay of synthetic Windows event XML. **The PowerShell scripts in this
folder and the live Event Log reader have NOT yet been run on a real Windows machine**
— they were written without access to one. Treat the first run in a Windows VM as the
real test, using the checklist in `docs/dev-guide.md`, and expect to fix small things.

## Prerequisites

- Windows 10/11 or Server 2016+, Python 3.10+ on PATH
- An elevated PowerShell (Run as Administrator)
- The repo in a folder **outside** your user profile, e.g. `C:\Cypher`

## 1. Turn on the logging Cypher reads

Windows does not record failed logons unless auditing is on. In an elevated prompt:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable
```

(Account lockout events 4740 come from the domain controller for domain accounts; on a
standalone PC lockouts are logged locally when a lockout policy is set.)

## 2. Install

```powershell
cd C:\Cypher
powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1 -StartNow
```

It creates the venv, locks down `data\`, asks for a dashboard password, and registers
three tasks: **Cypher Responder** (SYSTEM — the only one that edits firewall rules),
**Cypher Ingest** (SYSTEM — can read the Security log), **Cypher API** (LOCAL SERVICE,
low privilege). Dashboard: http://127.0.0.1:8000, user `admin`.

## 3. Try it without an attack

```powershell
.\.venv\Scripts\Activate.ps1
python scripts\generate_windows_demo.py
cypher --config config\cypher.windows.toml replay data\raw\windows_attack_demo.xml --source-type windows_security_log
cypher --config config\cypher.windows.toml status
```

## 4. Going active

Same rule as Linux: stay in `dry_run` until you've watched the alerts for a few days,
and put every IP you'd hate to lose (your own RDP source!) in `config\allowlist.toml`
**first**. Then set `mode = "active"` in `config\cypher.windows.toml` and restart the
"Cypher Responder" and "Cypher Ingest" tasks. Cypher names every rule it creates
`Cypher Block <ip>`, and the responder removes them when the TTL expires.

## Removing it

```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\uninstall.ps1
```

Deletes the tasks and every `Cypher Block *` firewall rule.

## What's different about "privilege escalation" on Windows

There is no `sudo`. Cypher watches the nearest real equivalents: event 4732 (someone
added to the local **Administrators** group) and 4672 (sensitive privileges assigned to
an ordinary user account; SYSTEM and machine accounts are ignored because they fire
constantly).
