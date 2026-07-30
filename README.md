# PyZTNA -- A Zero Trust Network Access Implementation (Windows)

A from-scratch, working ZTNA system: identity provider with real MFA,
a policy decision point, a policy-enforcing gateway, two protected
resources, a client agent with device posture checking, an audit log, and
a dashboard -- built to run on Windows with only 4 third-party packages
(everything else is Python's standard library). See `docs/ARCHITECTURE.md`
for the full design, `docs/EVALUATION.md` for measured results, and
`docs/WINDOWS_SETUP.md` for the complete step-by-step setup.

## Why this exists

Built to accompany a report on implementing ZTNA on a Windows network,
following the approach in *"Fortifying Linux Server and Implementing a Zero
Trust Network Access (ZTNA) for Enhanced Security"* (MDPI, 2025), adapted
for Windows and evaluated using the quality framework from *"Zero Trust
Network Access (ZTNA) to Secure Website Applications Based on ISO 25023"*
(IEEE, 2025). Full citations in `docs/ARCHITECTURE.md`.

## What it demonstrates

- **Real MFA** -- password (bcrypt-hashed) + TOTP (RFC 6238, implemented
  from scratch, interoperable with any authenticator app).
- **Context-aware access control (ABAC)**, not just role-based -- a user
  with the correct role is still denied if their device's trust score is
  too low. See `carol` in the demo below.
- **Continuous verification** -- 45-second token TTL means a session that
  was valid a moment ago must be re-verified, not trusted indefinitely.
- **Least privilege / micro-segmentation** -- each resource has its own
  minimum role and minimum device-trust policy; protected resources are
  network-unreachable except through the gateway.
- **Full audit trail** -- every allow/deny decision logged; renders to a
  browsable HTML dashboard.
- **Cryptographic device attestation** -- resources can require proof of
  possession of a device's enrolled key (TPM-backed on Windows), not just
  a self-reported posture score. See `docs/DEVICE_ATTESTATION.md`.
- **Automated proof, not just a demo** -- 19 integration tests
  (`tests/test_ztna.py`) exercise the real system end to end over real
  HTTPS/HTTP requests. All 19 pass (`docs/TEST_RESULTS.md`).

## Quickstart (Windows)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
.\run_all.ps1
```

Then, in a new terminal:
```powershell
python -m agent.client_agent --user alice --resource docs-app --demo       # ALLOWED
python -m agent.client_agent --user alice --resource finance-app --demo    # DENIED (role)
python -m agent.client_agent --user bob   --resource finance-app --demo    # ALLOWED (attested + healthy device)
python -m agent.client_agent --user bob   --resource finance-app --demo --no-attestation  # DENIED (attestation_required)
python -m agent.client_agent --user carol --resource finance-app --demo --simulate-compromised  # DENIED (device trust)
```

Full walkthrough, including Windows Firewall network segmentation and
wiring up a real authenticator app: **`docs/WINDOWS_SETUP.md`**.

## Demo accounts

| Username | Password | Role | Notes |
|---|---|---|---|
| alice | `Intern#2026` | intern | can reach docs-app only |
| bob | `Manager#2026` | finance_manager | can reach both, on a healthy device |
| carol | `Manager#2026` | finance_manager | use `--simulate-compromised` to demo context-aware denial |
| admin | `Admin#2026` | admin | highest privilege |

(`--demo` auto-computes the correct TOTP code for these seeded accounts so
the project runs without needing a phone; see WINDOWS_SETUP.md Section 6
to wire up a real authenticator app instead.)

## Project layout

```
common/     shared config, JWT helpers, hand-written TOTP, TLS cert setup, audit logging
idp/        Identity Provider -- password + MFA -> short-lived JWT
pdp/        Policy Decision Point -- ABAC engine (role + device trust vs. resource policy)
gateway/    Policy Enforcement Point -- validates + authorizes + proxies + logs every request
resources/  Two protected backends (docs-app: low sensitivity, finance-app: high sensitivity)
agent/      Client agent: device posture check, cryptographic attestation, login + resource access, incl. --watch mode
tests/      Integration test suite (spins up all 4 services for real, 19 tests)
dashboard/  Generates a self-contained HTML audit dashboard from the access log
docs/       Architecture, device attestation design doc, Windows setup guide, evaluation results, captured test run
```

## Running the tests yourself

```powershell
python -m unittest tests.test_ztna -v
```

## Regenerating the dashboard

```powershell
python -m dashboard.generate_dashboard
start dashboard\dashboard.html
```

## Known limitations (documented deliberately -- good material for a
"future work" section in your report)

1. Device trust score self-report is now backed by optional cryptographic
   attestation (`docs/DEVICE_ATTESTATION.md`) for resources that require
   it -- but the Windows/TPM code path hasn't been run against real TPM
   hardware yet; see that document for exactly what's verified.
2. Attestation enrollment is trust-on-first-use (TOFU), with no
   authenticated provisioning step -- see `docs/DEVICE_ATTESTATION.md`
   Section 5.
3. JWT uses a shared HS256 secret rather than asymmetric signing.
4. No brute-force/rate-limiting on the IdP's `/login` endpoint.
5. No explicit token revocation list -- mitigated, not eliminated, by the
   short default TTL.

Each of these is a legitimate, citable extension if more scope is wanted.
