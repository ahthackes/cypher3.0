# Launched by the "Cypher Ingest" scheduled task (as SYSTEM, which can read
# the Security event log). Reads events, runs detection, writes alerts.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root
& "$Root\.venv\Scripts\cypher.exe" --config config/cypher.windows.toml start
