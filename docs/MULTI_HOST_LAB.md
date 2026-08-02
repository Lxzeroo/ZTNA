# Multi-Host Lab: Running PyZTNA Across Real Machines

Everything in `docs/WINDOWS_SETUP.md` runs on one machine over loopback.
That proves the *logic* but not the *isolation*: when every component shares
a host, "the resource is unreachable except through the Gateway" is true
mostly because of loopback binding, and a reviewer is entitled to be
sceptical.

This guide deploys the same code across separate machines, where the
isolation claims become falsifiable -- and, importantly, where you can
capture evidence of access being **refused**, which is what actually
demonstrates enforcement.

---

## 1. Topology

Minimum three machines; four is better because it separates the two
resources from each other.

```
   ┌──────────────┐         ┌──────────────┐         ┌──────────────────┐
   │   HOST A     │         │   HOST B     │         │      HOST C      │
   │   Agent      │────────▶│   Gateway    │────────▶│   docs-app :9101 │
   │  (client)    │  HTTPS  │    :9200     │  mTLS   │ finance-app :9102│
   └──────┬───────┘         └──────────────┘         └──────────────────┘
          │                                            (protected zone)
          │  login (HTTPS)
          ▼
   ┌──────────────┐         ┌──────────────┐
   │   HOST D     │         │   HOST E     │
   │  IdP  :9000  │         │  ROGUE       │  ← no client cert, no firewall
   └──────────────┘         │  (attacker)  │    allowance: used purely to
                            └──────────────┘    prove access is refused
```

**Host E is the most valuable machine in the lab.** Without a host that is
*supposed* to fail, every result is a happy path. Any spare VM will do.

Anything works: Hyper-V, VirtualBox, VMware, or cloud VMs in one VPC. They
only need to be on the same subnet and able to reach each other.

Record each machine's address before continuing; this guide uses:

| Role | Address |
|---|---|
| IdP | `192.168.1.10` |
| Gateway | `192.168.1.11` |
| docs-app + finance-app | `192.168.1.12` |
| Agent | `192.168.1.20` |
| Rogue | `192.168.1.99` |

---

## 2. Install on every machine

On each host, install Python 3.10+, copy the project, and create the venv:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python VERIFY_INSTALL.py
```

`VERIFY_INSTALL.py` must report all checks passing on every machine. A
partially-updated tree on one host produces failures that look like network
problems and will waste hours.

**Do not start any service yet.** Starting a service auto-generates a local
CA and JWT keypair, which is exactly what section 3 exists to prevent.

---

## 3. Provision the PKI -- once, on one machine

This is the step that makes multi-host work, and skipping it is the single
most likely cause of failure.

Left to itself, each host generates its **own** internal CA and its **own**
JWT signing keypair. The consequences are silent and misleading:

- The Gateway's client certificate is signed by CA-A while the resource
  trusts CA-B, so **every mTLS handshake fails**.
- The IdP signs tokens with key-A while the Gateway verifies with key-B, so
  **every token is rejected as `token_signature_invalid`** the instant it is
  issued.

Neither error names the real cause. Both look like application bugs.

Pick one machine (an admin workstation, or the IdP host) and run:

```powershell
python -m tools.provision_certs `
    --idp-host 192.168.1.10 `
    --gateway-host 192.168.1.11 `
    --docs-host 192.168.1.12 `
    --finance-host 192.168.1.12 `
    --out dist
```

This produces one bundle per host under `dist/`:

| Bundle | Contains | Why |
|---|---|---|
| `idp/` | CA cert, IdP key+cert, **JWT private key** | only the IdP mints tokens |
| `gateway/` | CA cert, Gateway key+cert, mTLS client key+cert, **JWT public key only** | it verifies tokens; it must not be able to forge them |
| `docs-app/` | CA cert, its key+cert | |
| `finance-app/` | CA cert, its key+cert | |
| `agent/` | CA cert only | so the client can verify servers for real |

Copy each bundle's `certs/` directory into the project root on the matching
machine. The CA **private** key is deliberately in no bundle -- it stays on
the provisioning machine.

> The Gateway receiving only the public key is the entire point of the RS256
> migration (`docs/HARDENING.md` item 1). Copying the private key there
> "to make it work" silently undoes it.

Delete `dist/` when provisioning is done -- it contains private keys.

---

## 4. Environment variables per host

Each service needs to know two different things: what address **others**
use to reach it (goes in its certificate), and what interface it **binds**
to locally. On one machine these are identical; across machines they are
not.

**Host D — IdP**
```powershell
$env:ZTNA_IDP_HOST      = "192.168.1.10"   # goes in the certificate
$env:ZTNA_IDP_BIND_HOST = "0.0.0.0"        # accept remote connections
python -m idp.idp_server
```

**Host B — Gateway**
```powershell
$env:ZTNA_IDP_HOST          = "192.168.1.10"
$env:ZTNA_GATEWAY_HOST      = "192.168.1.11"
$env:ZTNA_GATEWAY_BIND_HOST = "0.0.0.0"
$env:ZTNA_DOCS_APP_HOST     = "192.168.1.12"
$env:ZTNA_FINANCE_APP_HOST  = "192.168.1.12"
python -m gateway.gateway_server
```

**Host C — resources**
```powershell
$env:ZTNA_DOCS_APP_HOST         = "192.168.1.12"
$env:ZTNA_DOCS_APP_BIND_HOST    = "0.0.0.0"
$env:ZTNA_FINANCE_APP_HOST      = "192.168.1.12"
$env:ZTNA_FINANCE_APP_BIND_HOST = "0.0.0.0"
python -m resources.docs_app
python -m resources.finance_app      # second terminal
```

**Host A — agent**
```powershell
$env:ZTNA_IDP_HOST     = "192.168.1.10"
$env:ZTNA_GATEWAY_HOST = "192.168.1.11"
```

Set these permanently with `[Environment]::SetEnvironmentVariable(...,
"Machine")` if you don't want to re-set them per terminal.

---

## 5. Firewall rules -- layer 1

On **Host C**, permit the resource ports only from the Gateway. Run as
Administrator:

```powershell
New-NetFirewallRule -DisplayName "ZTNA-Allow-DocsApp-FromGateway" `
  -Direction Inbound -LocalPort 9101 -Protocol TCP -Action Allow `
  -RemoteAddress 192.168.1.11

New-NetFirewallRule -DisplayName "ZTNA-Block-DocsApp-Everything-Else" `
  -Direction Inbound -LocalPort 9101 -Protocol TCP -Action Block `
  -RemoteAddress Any

# repeat both for 9102 / finance-app
```

Windows Firewall evaluates Allow before Block, so the Gateway is permitted
and everyone else is dropped.

This is **defence in depth, not the only control** -- section 7 demonstrates
that the resources refuse non-Gateway callers even when the firewall permits
them.

---

## 6. Run the demo scenarios from Host A

```powershell
python -m agent.client_agent --user alice --resource docs-app --demo
python -m agent.client_agent --user alice --resource finance-app --demo
python -m agent.client_agent --user carol --resource finance-app --demo --simulate-compromised
python -m agent.client_agent --user bob --resource finance-app --demo --watch --interval 8 --compromise-after 3
```

Outcomes are identical to the single-host run -- but now every request
crosses a real network, so the audit log's `source_ip` shows Host A's real
address rather than `127.0.0.1`. That is worth a screenshot.

---

## 7. Capture the evidence -- the part that matters

Run the probe from **three** machines. The expected results differ by role,
and that difference *is* the finding.

**From the Gateway (Host B):**
```powershell
python -m tools.network_probe --role gateway `
    --gateway-host 192.168.1.11 --idp-host 192.168.1.10 `
    --resource-host 192.168.1.12 --resource-port 9101
```

**From the Agent (Host A) and from the Rogue host (Host E):**
```powershell
python -m tools.network_probe --role agent `
    --gateway-host 192.168.1.11 --idp-host 192.168.1.10 `
    --resource-host 192.168.1.12 --resource-port 9101
```

### Expected matrix

| Check | From Gateway | From Agent / Rogue | Layer proved |
|---|---|---|---|
| Gateway reachable over TLS | allowed | allowed | service is up, cert chains to internal CA |
| IdP reachable over TLS | allowed | allowed | clients can authenticate |
| Direct TCP to resource | allowed | **blocked** | **layer 1 — firewall** |
| TLS to resource *without* client cert | **blocked** | **blocked** | **layer 2 — mTLS** |
| TLS to resource *with* client cert | allowed | n/a (no cert exists) | only the Gateway holds one |

The key row is the fourth. Note it is blocked **even from the Gateway
machine** — the firewall permits that host, so the packet arrives, and the
resource still refuses because no client certificate was presented. You will
see:

```
TLS to resource WITHOUT client cert    blocked    blocked    PASS
  TLS refused: TLSV13_ALERT_CERTIFICATE_REQUIRED
```

Two independent controls, failing separately, for different reasons. A
firewall alone could not produce that second line; mTLS alone could not
produce the timeout in row three.

### A TLS 1.3 detail worth knowing

Under TLS 1.2 a missing client certificate failed *during* the handshake.
Under **TLS 1.3 the handshake completes first**, and the server's rejection
only appears on the first read or write. An early version of this probe
reported "handshake OK" and therefore produced a false *"mTLS is not being
enforced"* result when it was in fact working perfectly.

`tools/network_probe.py` now performs a full request/response round trip
rather than trusting handshake completion. If you write your own checks, do
the same -- and if you cite a "connection succeeded" result anywhere, make
sure it involved actual I/O.

---

## 8. Optional: packet capture

Run Wireshark on Host B or C and filter `tcp.port==9101 || tcp.port==9200`.

- The agent→Gateway and Gateway→resource flows are both TLS; the JWT is not
  visible in cleartext anywhere.
- The failed mTLS attempt shows `Client Hello`, `Server Hello`, then an
  `Alert` — visual confirmation that rejection happened at the TLS layer,
  not the application.

A screenshot of that alert is strong report material.

---

## 9. Troubleshooting

| Symptom | Cause |
|---|---|
| `token_signature_invalid` on every request | IdP and Gateway have different JWT keypairs — section 3 was skipped or the Gateway generated its own before the bundle was copied. Delete `certs/jwt_keys/` on the Gateway and re-copy the bundle. |
| `TLSV13_ALERT_UNKNOWN_CA` between Gateway and resource | The two hosts have different CAs. Delete `certs/ca/` on both and re-copy from the same provisioning run. |
| `certificate verify failed: Hostname mismatch` | The certificate predates the address change. `provision_certs.py` reissues automatically; if you generated certs by starting a service first, delete `certs/services/` and re-provision. |
| Direct TCP to a resource succeeds from the rogue host | The Block rule is missing or scoped to the wrong profile. Check `Get-NetFirewallRule -DisplayName "ZTNA-*"` and confirm the profile matches your network type (Domain/Private/Public). |
| Everything times out between hosts | The VMs are on Host-Only/NAT networking and can't see each other. Confirm with `Test-NetConnection <ip> -Port 9200`. |
| Service starts but no one can reach it | `*_BIND_HOST` still defaults to the dial address rather than `0.0.0.0`. |
| Agent fails with `ProxyError` / `Tunnel connection failed`, but `tools.network_probe` passes | An HTTP(S) proxy is configured on that machine. The agent uses `requests`, which honours `HTTP_PROXY`/`HTTPS_PROXY` and tries to tunnel internal traffic through it; the probe uses raw sockets and bypasses it, which is why the two disagree. Exclude the lab addresses: `$env:NO_PROXY="192.168.1.10,192.168.1.11,192.168.1.12"`. Common on corporate machines. |

---

## 10. What this actually demonstrates

Worth stating precisely in a report, because it is stronger than "the demo
worked":

1. **Network location confers no access.** The rogue host sits on the same
   subnet as the Gateway and reaches nothing. Traditional perimeter security
   would have granted it everything.
2. **Two independent controls, verified separately.** Firewall isolation and
   mTLS each refuse the same request for different reasons, at different
   layers, with different error signatures. Defeating one is not enough.
3. **Identity travels, trust does not.** The same token that works from Host
   A works from anywhere — because it is verified cryptographically on every
   request, not because of where it came from. Equally, revoking it
   (`tools/revoke_token.py`) cuts access from everywhere at once.
4. **The negative results are the evidence.** Three refusals with three
   distinct causes prove enforcement in a way that any number of successful
   requests cannot.

### Still not demonstrated by this lab

- **High availability.** One instance of each component. See
  `deploy/README.md` for what multi-instance would require.
- **Untrusted networks.** All hosts are on one trusted subnet. Placing the
  Gateway behind a reverse proxy with a publicly-trusted certificate
  (`deploy/nginx.conf`) and connecting from outside would be the stronger
  version of claim 1.
- **Non-HTTP protocols.** SSH/RDP/database brokering is still out of scope.
