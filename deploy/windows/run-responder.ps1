# Launched by the "Cypher Responder" scheduled task (as SYSTEM).
# The ONLY Cypher process that changes Windows Firewall rules.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root
& "$Root\.venv\Scripts\python.exe" -m cypher.respond.run_responder --config config/cypher.windows.toml
