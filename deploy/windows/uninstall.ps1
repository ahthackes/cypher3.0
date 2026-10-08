#Requires -RunAsAdministrator
# Removes the scheduled tasks and every firewall rule Cypher created.
# Leaves the repo, venv and data\ in place (delete the folder yourself if wanted).
$ErrorActionPreference = "Continue"
foreach ($n in "Cypher Responder", "Cypher Ingest", "Cypher API") {
    Stop-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction SilentlyContinue
}
Remove-NetFirewallRule -DisplayName "Cypher Block *" -ErrorAction SilentlyContinue
Write-Host "Cypher tasks and 'Cypher Block *' firewall rules removed."
