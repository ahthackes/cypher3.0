#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs Cypher on Windows: venv, data directory permissions, dashboard
  credentials, and three scheduled tasks (responder, ingest, API).

.DESCRIPTION
  Run from an elevated PowerShell, from anywhere inside the repo:
      powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1

  Install the repo somewhere like C:\Cypher, NOT under your user profile:
  the API runs as LOCAL SERVICE, which cannot read C:\Users\<you>\...

  Cypher stays in "dry_run" mode (config\cypher.windows.toml) until you change
  it. Nothing here touches the firewall by itself.

.PARAMETER StartNow
  Start the three tasks immediately instead of waiting for the next boot.
#>
param([switch]$StartNow)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root
$Py = "$Root\.venv\Scripts\python.exe"

if ($Root.StartsWith($env:USERPROFILE, [StringComparison]::OrdinalIgnoreCase)) {
    Write-Warning "The repo is under your user profile. The API task runs as LOCAL SERVICE and will not be able to read it. Move the folder to e.g. C:\Cypher and run this again."
    throw "Unsupported install location"
}

Write-Host "==> Creating virtual environment and installing Cypher"
if (-not (Test-Path ".venv")) { python -m venv .venv }
& $Py -m pip install --upgrade pip
& $Py -m pip install -e .
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

Write-Host "==> Creating data directories"
foreach ($d in "data", "data\raw", "data\processed", "data\models", "data\geo", "data\mitre") {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

Write-Host "==> Letting the low-privilege API account read the code"
icacls $Root /grant "NT AUTHORITY\LOCAL SERVICE:(OI)(CI)RX" | Out-Null

Write-Host "==> Locking down the data directory (SYSTEM, Administrators, LOCAL SERVICE only)"
# Inheritance removed so ordinary users cannot read the database or secrets.
icacls data /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "NT AUTHORITY\LOCAL SERVICE:(OI)(CI)M" | Out-Null

Write-Host "==> Creating the responder IPC token (API gets read-only access to it)"
& $Py -c "from cypher.respond.ipc_token import get_or_create_token; get_or_create_token('data/responder.token')"
icacls data\responder.token /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" "NT AUTHORITY\LOCAL SERVICE:R" | Out-Null

Write-Host "==> Dashboard credentials"
$secure = Read-Host "Choose a dashboard admin password (min 8 characters)" -AsSecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
$hash = ($plain | & $Py scripts\set_admin_password.py --stdin)
if ($LASTEXITCODE -ne 0) { throw "Could not hash the password (is it at least 8 characters?)" }
$secret = (& $Py -c "import secrets; print(secrets.token_hex(32))")
Set-Content -Path data\api.env -Encoding ascii -Value @(
    "CYPHER_ADMIN_PASSWORD_HASH=$($hash.Trim())",
    "CYPHER_SESSION_SECRET=$($secret.Trim())",
    "CYPHER_CONFIG=config/cypher.windows.toml"
)
icacls data\api.env /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" "NT AUTHORITY\LOCAL SERVICE:R" | Out-Null

Write-Host "==> Registering scheduled tasks"
function Register-CypherTask([string]$Name, [string]$Script, [string]$UserId, [string]$RunLevel) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSScriptRoot\$Script`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType ServiceAccount -RunLevel $RunLevel
    $settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
    Register-ScheduledTask -TaskName $Name -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
}
Register-CypherTask "Cypher Responder" "run-responder.ps1" "SYSTEM" "Highest"
Register-CypherTask "Cypher Ingest"    "run-ingest.ps1"    "SYSTEM" "Highest"
Register-CypherTask "Cypher API"       "run-api.ps1"       "NT AUTHORITY\LOCAL SERVICE" "Limited"

if ($StartNow) {
    foreach ($n in "Cypher Responder", "Cypher Ingest", "Cypher API") { Start-ScheduledTask -TaskName $n }
    Write-Host "Started. Dashboard: http://127.0.0.1:8000  (user: admin)"
} else {
    Write-Host "Registered. Start now with:  Start-ScheduledTask 'Cypher Responder','Cypher Ingest','Cypher API'  (or reboot)"
}

Write-Host ""
Write-Host "NEXT STEPS" -ForegroundColor Yellow
Write-Host "  1. Edit config\allowlist.toml: add the IP you manage this PC from (e.g. your RDP source)."
Write-Host "  2. Enable Security auditing for logon events (see deploy\windows\README.md) - without it there is nothing to read."
Write-Host "  3. Leave mode = 'dry_run' until you've reviewed the alerts on the dashboard."
