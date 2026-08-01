# Running PyZTNA on Windows

This guide assumes Windows 10/11 with administrator access.

## 1. Install prerequisites

1. **Python 3.10+** -- check "Add python.exe to PATH" on install.
2. OpenSSL is **no longer required** as of this hardening revision -- TLS
   certificates (including the internal CA) are generated with the
   `cryptography` package, which is already a required dependency. If you
   still have `openssl` on PATH that's fine, it's simply unused now.

## 2. Get the project and install dependencies

```powershell
cd C:\Users\<you>\Documents
cd PyZTNA

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 3. Start all four services

```powershell
.\run_all.ps1
```

Or manually in four terminals:

```powershell
python -m idp.idp_server
python -m resources.docs_app
python -m resources.finance_app
python -m gateway.gateway_server
```

On first run, each service triggers generation of the internal CA
(`certs/ca/`) and its own leaf certificate if they don't exist yet -- this
happens once and is reused on subsequent runs. `idp` and `gateway` serve
plain TLS (any client with the CA cert can connect); `docs-app` and
`finance-app` additionally **require** a client certificate signed by the
same CA (mutual TLS) -- only the Gateway has one, so this is what actually
enforces "only the Gateway can reach the resources" at the TLS layer, not
just firewall/loopback binding. See `docs/HARDENING.md`.

## 4. Run the client agent

```powershell
python -m agent.client_agent --user alice --password Intern#2026 --resource docs-app --demo
python -m agent.client_agent --user alice --password Intern#2026 --resource finance-app --demo
python -m agent.client_agent --user bob --password Manager#2026 --resource finance-app --demo
python -m agent.client_agent --user carol --password Manager#2026 --resource finance-app --demo --simulate-compromised
python -m agent.client_agent --user bob --password Manager#2026 --resource finance-app --demo --watch --interval 8 --compromise-after 3
```

## 5. Isolate the protected resources with Windows Firewall

Same as before -- see `docs/ARCHITECTURE.md` Section 5. As of this
revision, this is now defense-in-depth rather than the only enforcement:
even a host that gets past the firewall rule still can't complete a TLS
handshake with `docs-app`/`finance-app` without the Gateway's client
certificate.

```powershell
New-NetFirewallRule -DisplayName "Block-DocsApp-Direct" `
  -Direction Inbound -LocalPort 9101 -Protocol TCP -Action Block `
  -RemoteAddress Any

New-NetFirewallRule -DisplayName "Allow-DocsApp-FromGateway" `
  -Direction Inbound -LocalPort 9101 -Protocol TCP -Action Allow `
  -RemoteAddress <GATEWAY_IP>
```

## 6. (Optional) Wire up a real authenticator app

Unchanged -- see `common/totp.py:provisioning_uri`.

## 7. Generate the audit dashboard

```powershell
python -m dashboard.generate_dashboard
start dashboard\dashboard.html
```

To verify the audit log hasn't been tampered with:
```powershell
python -m tools.verify_audit_log
```

## 8. Run the automated test suite

```powershell
python -m unittest tests.test_ztna -v
```

## 9. New in this revision: rate limiting, revocation, LDAP, policy file

- **Login rate limiting**: after `ZTNA_LOGIN_MAX_ATTEMPTS` (default 5)
  failed logins for the same username within `ZTNA_LOGIN_WINDOW_SECONDS`
  (default 300), further attempts are locked out for
  `ZTNA_LOGIN_LOCKOUT_SECONDS` (default 300). Configurable via environment
  variables, see `common/config.py`.
- **Revoking a token or a user's sessions**:
  ```powershell
  python -m tools.revoke_token --jti <token-id>
  python -m tools.revoke_token --user bob
  ```
  The Gateway checks the revocation store on every request, so a revoked
  session is cut off on its very next call, without waiting for TTL expiry.
- **Policy file**: `pdp/policies.json` overrides `common/config.py`'s
  `RESOURCES` policy thresholds at import time; edit it and call
  `pdp.policy_engine.reload_policies()` (or just restart the Gateway) to
  apply changes without touching code.
- **LDAP-backed identity** (optional, untested against a real directory):
  set `ZTNA_AUTH_BACKEND=ldap` plus the `ZTNA_LDAP_*` variables in
  `common/config.py`, and `pip install ldap3`. See `idp/auth_backends.py`
  and `docs/HARDENING.md` for the honest scope of what this does and
  doesn't verify without a real LDAP server to test against.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `ModuleNotFoundError: No module named 'jwt'` | venv not activated, or `pip install -r requirements.txt` not run |
| `Address already in use` | a previous run's process is still bound to the port -- `netstat -ano \| findstr 9200` then `Stop-Process -Id <PID>` |
| `PowerShell ... cannot be loaded because running scripts is disabled` | run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once |
| Resource returns connection reset / TLS handshake failure when curled directly | expected -- `docs-app`/`finance-app` now require the Gateway's mTLS client cert; this is the new enforcement, not a bug |
| `423 account_locked` / `429` from `/login` | rate limiter engaged after repeated failed attempts for that username -- wait out `ZTNA_LOGIN_LOCKOUT_SECONDS` or restart the IdP (in-memory store) |
