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

# Each Start-Process call below opens a BRAND NEW PowerShell process that
# does NOT inherit this window's activated virtual environment. Every
# spawned command therefore re-activates .venv itself (if present) before
# running its service -- otherwise every window fails with
# "ModuleNotFoundError: No module named 'jwt'" (or requests/bcrypt/psutil)
# even if you installed dependencies correctly in the terminal you launched
# run_all.ps1 from.
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
Write-Host "Once they say 'listening on https://...' (or http:// if OpenSSL isn't installed)," -ForegroundColor Green
Write-Host "try the client agent from a terminal with .venv activated:" -ForegroundColor Green
Write-Host "  python -m agent.client_agent --user alice --resource docs-app --demo"
Write-Host "  python -m agent.client_agent --user bob   --resource finance-app --demo"
Write-Host "  python -m agent.client_agent --user carol --resource finance-app --demo --simulate-compromised"
