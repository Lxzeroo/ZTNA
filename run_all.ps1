# PyZTNA -- launch every service in its own PowerShell window.
# Run from the project root:  .\run_all.ps1
#
# Opens 4 windows: Identity Provider, Gateway, docs-app, finance-app.
# Close the windows (or Ctrl+C in each) to stop the corresponding service.

$root = $PSScriptRoot

Write-Host "Starting PyZTNA services from $root ..." -ForegroundColor Cyan

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root'; python -m idp.idp_server"
Start-Sleep -Seconds 1
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root'; python -m resources.docs_app"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root'; python -m resources.finance_app"
Start-Sleep -Seconds 1
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root'; python -m gateway.gateway_server"

Write-Host ""
Write-Host "All 4 services launching in separate windows." -ForegroundColor Green
Write-Host "Once they say 'listening on https://...', try the client agent:" -ForegroundColor Green
Write-Host "  python -m agent.client_agent --user alice --resource docs-app --demo"
Write-Host "  python -m agent.client_agent --user bob   --resource finance-app --demo"
Write-Host "  python -m agent.client_agent --user carol --resource finance-app --demo --simulate-compromised"
