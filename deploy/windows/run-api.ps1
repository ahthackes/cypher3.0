# Launched by the "Cypher API" scheduled task (as LOCAL SERVICE, a low-privilege
# built-in account). Loads secrets from data\api.env, then serves the dashboard
# on 127.0.0.1:8000 only.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root

$envFile = Join-Path $Root "data\api.env"
if (-not (Test-Path $envFile)) { throw "Missing $envFile - run deploy\windows\install.ps1 first." }
foreach ($line in Get-Content $envFile) {
    $i = $line.IndexOf("=")
    if ($i -gt 0) {
        # Split at the FIRST '=' only: bcrypt hashes contain '$' and may contain '='.
        [Environment]::SetEnvironmentVariable($line.Substring(0, $i), $line.Substring($i + 1), "Process")
    }
}

& "$Root\.venv\Scripts\python.exe" -m uvicorn cypher.api.app:create_app --factory --host 127.0.0.1 --port 8000
