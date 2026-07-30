# Running PyZTNA on Windows

This guide assumes Windows 10/11 with administrator access. Total setup
time is about 10 minutes.

## 1. Install prerequisites

1. **Python 3.10+** -- download from https://python.org/downloads and, on
   the installer's first screen, check **"Add python.exe to PATH"**.
2. **OpenSSL for Windows** (enables HTTPS for the demo instead of falling
   back to plain HTTP) -- either:
   - Install **Git for Windows** (https://git-scm.com/download/win), which
     ships an `openssl.exe` on PATH, or
   - Install OpenSSL directly from https://slproweb.com/products/Win32OpenSSL.html
3. Verify both are on PATH by opening **PowerShell** and running:
   ```powershell
   python --version
   openssl version
   ```
   If `openssl version` fails, the services still run correctly over plain
   HTTP -- you'll see a `[warn] openssl not found on PATH` message, which is
   fine for a local demo but should be called out in your report as a
   config requirement for a "real" deployment.

## 2. Get the project and install dependencies

```powershell
cd C:\Users\<you>\Documents
# unzip the PyZTNA project here, or clone your repo
cd PyZTNA

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell blocks the venv activation script with an execution-policy
error, run this once (in an admin PowerShell) and try again:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## 3. Start all four services

Easiest: use the provided launcher, which opens one PowerShell window per
service so you can watch each one's logs live:

```powershell
.\run_all.ps1
```

Or start them manually in four separate terminals (useful if you want to
demo one service crashing / restarting):

```powershell
# Terminal 1
python -m idp.idp_server

# Terminal 2
python -m resources.docs_app

# Terminal 3
python -m resources.finance_app

# Terminal 4 (start last -- it's the gateway, the single entry point)
python -m gateway.gateway_server
```

Each prints `listening on https://127.0.0.1:<port>` (or `http://` if
OpenSSL wasn't found) when ready.

## 4. Run the client agent

In a fifth terminal (with the venv activated):

```powershell
# Intern reaching a low-sensitivity resource -- should be ALLOWED
python -m agent.client_agent --user alice --password Intern#2026 --resource docs-app --demo

# Intern reaching a high-sensitivity resource -- should be DENIED (role)
python -m agent.client_agent --user alice --password Intern#2026 --resource finance-app --demo

# Finance manager, healthy device -- should be ALLOWED
python -m agent.client_agent --user bob --password Manager#2026 --resource finance-app --demo

# Finance manager, but the device reports itself compromised -- DENIED
# despite having the correct role (this is the key ZTNA demo scenario)
python -m agent.client_agent --user carol --password Manager#2026 --resource finance-app --demo --simulate-compromised

# Continuous verification demo -- watch access get revoked mid-session
# when the device posture flips to "compromised" at cycle 3, with no
# server restart:
python -m agent.client_agent --user bob --password Manager#2026 --resource finance-app --demo --watch --interval 8 --compromise-after 3
```

On a real Windows machine (not this Linux dev sandbox), `--demo` is not
required for the device posture score to reflect the real machine -- the
agent's `agent/device_posture.py` checks live Windows Defender status
(`sc query windefend`), BitLocker (`manage-bde -status`), and Windows
Firewall (`netsh advfirewall show allprofiles state`) automatically. You
can drop `--demo` and type the 6-digit code from an authenticator app
instead of having the agent compute it, which is closer to how a real
deployment works -- see step 6.

## 5. Isolate the protected resources with Windows Firewall

The two resource apps (`docs-app` on port 9101, `finance-app` on port
9102) bind to `127.0.0.1` only, so by default nothing outside the machine
can reach them regardless of firewall rules. To make this explicit for
your report -- and to demonstrate it in a multi-VM lab where the gateway
and the resources run on *different* machines -- add inbound-block rules
so only the gateway's address can reach those ports:

```powershell
# Run as Administrator. Replace <GATEWAY_IP> with the gateway machine's
# address if resources run on a separate VM; on a single-machine demo this
# still documents intent even though loopback binding already blocks
# external access.
New-NetFirewallRule -DisplayName "Block-DocsApp-Direct" `
  -Direction Inbound -LocalPort 9101 -Protocol TCP -Action Block `
  -RemoteAddress Any

New-NetFirewallRule -DisplayName "Allow-DocsApp-FromGateway" `
  -Direction Inbound -LocalPort 9101 -Protocol TCP -Action Allow `
  -RemoteAddress <GATEWAY_IP>
```
(Repeat for port 9102 / finance-app.) Capture a screenshot of these rules
and a failed direct `curl http://<resource-ip>:9101/data` for your report
-- it's concrete evidence of network-level least-privilege enforcement,
not just application-level.

## 6. (Optional, more realistic) Wire up a real authenticator app

To demo real MFA instead of `--demo` auto-computing the code:

1. Run this once to get a provisioning URI and QR-friendly secret:
   ```powershell
   python -c "from common.totp import generate_secret, provisioning_uri; s = generate_secret(); print(s); print(provisioning_uri(s, 'alice'))"
   ```
2. Paste the printed secret into `idp/users_db.py` for the `alice` entry's
   `totp_secret`, restart the IdP, and scan/enter the secret into Google
   Authenticator / Microsoft Authenticator / Authy on your phone.
3. Run the agent WITHOUT `--demo` -- it will prompt you to type the 6-digit
   code from your phone.

## 7. Generate the audit dashboard

After running a few scenarios:
```powershell
python -m dashboard.generate_dashboard
start dashboard\dashboard.html
```

## 8. Run the automated test suite

```powershell
python -m unittest tests.test_ztna -v
```
All 19 tests should pass; save the terminal output as evidence for your
report (`docs/TEST_RESULTS.md` in this project already contains a captured
run for reference).

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `ModuleNotFoundError: No module named 'jwt'` | venv not activated, or `pip install -r requirements.txt` not run |
| Services start over `http://` not `https://` | `openssl` isn't on PATH -- install Git for Windows or OpenSSL for Windows |
| `Address already in use` | a previous run's process is still bound to the port -- find it with `netstat -ano \| findstr 9200` and `Stop-Process -Id <PID>` |
| `PowerShell ... cannot be loaded because running scripts is disabled` | run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once |
