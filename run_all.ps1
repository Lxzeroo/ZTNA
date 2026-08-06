# PyZTNA -- launch every service in its own PowerShell window.
# Run from the project root:  .\run_all.ps1
#
# Opens 4 windows: Identity Provider, Gateway, docs-app, finance-app.
# Close the windows (or Ctrl+C in each) to stop the corresponding service.

$root = $PSScriptRoot
$venvActivate = Join-Path $root ".venv\Scripts\Activate.ps1"

Write-Host "Starting PyZTNA services from $root ..." -ForegroundColor Cyan

if (-not (Test-Path $venvActivate)) {
    Write-Host ""
    Write-Host "WARNING: no .venv found at $venvActivate" -ForegroundColor Yellow
    Write-Host "Run these first, then re-run .\run_all.ps1:" -ForegroundColor Yellow
    Write-Host "  python -m venv .venv"
    Write-Host "  .\.venv\Scripts\Activate.ps1"
    Write-Host "  pip install -r requirements.txt"
    Write-Host ""
}

function Start-Service-Window($moduleCmd) {
    $activatePrefix = if (Test-Path $venvActivate) { ". '$venvActivate'; " } else { "" }
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root'; ${activatePrefix}$moduleCmd"
}

Start-Service-Window "python -m idp.idp_server"
Start-Sleep -Seconds 1
Start-Service-Window "python -m resources.docs_app"
Start-Service-Window "python -m resources.finance_app"
Start-Sleep -Seconds 1
Start-Service-Window "python -m gateway.gateway_server"

Write-Host ""
Write-Host "All 4 services launching in separate windows." -ForegroundColor Green
Write-Host "Each runs a startup preflight check first (common/preflight.py); a" -ForegroundColor Green
Write-Host "window that closes immediately failed it -- re-run that one module" -ForegroundColor Green
Write-Host "directly to read the error." -ForegroundColor Green
Write-Host ""
Write-Host "Once they say 'listening on https://...' (or http:// if TLS is unavailable)," -ForegroundColor Green
Write-Host "try the client agent from a terminal with .venv activated:" -ForegroundColor Green
Write-Host "  python -m agent.client_agent --user alice --resource docs-app --demo"
Write-Host "  python -m agent.client_agent --user bob   --resource finance-app --demo"
Write-Host "  python -m agent.client_agent --user carol --resource finance-app --demo --simulate-compromised"
Write-Host ""
Write-Host "NOTE: finance-app requires device attestation, and a newly enrolled" -ForegroundColor Yellow
Write-Host "device now waits for administrator approval (no longer trust-on-first-use)." -ForegroundColor Yellow
Write-Host "The first 'bob' run will report the device as PENDING. Approve it with:" -ForegroundColor Yellow
Write-Host "  python -m tools.manage_devices --list --pending-only"
Write-Host "  python -m tools.manage_devices --approve <device_id>"
Write-Host "then re-run the bob command. That is the control working, not a failure."
Write-Host "See docs/PRODUCTION_READINESS.md section 3." -ForegroundColor Yellow
