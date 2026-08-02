# PyZTNA -- A Zero Trust Network Access Implementation (Windows)

**Current release: [v2.0.0](https://github.com/Lxzeroo/ZTNA/releases/tag/v2.0.0)** -- security hardening pass (RS256 tokens, mutual TLS, revocation, rate limiting, tamper-evident audit log). Breaking change from v1.x: the token format and the mTLS requirement on protected resources are not backward compatible. Full drawback -> fix -> verification mapping in [`docs/HARDENING.md`](docs/HARDENING.md).

A from-scratch, working ZTNA system: identity provider with real MFA,
a policy decision point, a policy-enforcing gateway, two protected
resources, a client agent with device posture checking, an audit log, and
a dashboard -- built to run on Windows with a minimal dependency list
(everything else is Python's standard library). See `docs/ARCHITECTURE.md`
for the full design, `docs/EVALUATION.md` for measured results,
`docs/WINDOWS_SETUP.md` for the complete step-by-step setup, and
**`docs/HARDENING.md` for this revision's security hardening pass** --
asymmetric (RS256) tokens, mutual TLS between the Gateway and protected
resources via an internal CA, explicit token revocation, login rate
limiting, a tamper-evident (hash-chained) audit log, externalized policy,
and a pluggable (LDAP-capable) identity backend.

## Why this exists

Built to accompany a report on implementing ZTNA on a Windows network,
following the approach in *"Fortifying Linux Server and Implementing a Zero
Trust Network Access (ZTNA) for Enhanced Security"* (MDPI, 2025), adapted
for Windows and evaluated using the quality framework from *"Zero Trust
Network Access (ZTNA) to Secure Website Applications Based on ISO 25023"* (IEEE, 2025). Full citations in `docs/ARCHITECTURE.md`.

## What it demonstrates

- **Real MFA** -- password (bcrypt-hashed) + TOTP (RFC 6238, implemented
  from scratch, interoperable with any authenticator app).
- **Context-aware access control (ABAC)**, not just role-based -- a user
  with the correct role is still denied if their device's trust score is
  too low. See `carol` in the demo below.
- **Continuous verification** -- 45-second token TTL plus explicit
  revocation means a session that was valid a moment ago must be
  re-verified, not trusted indefinitely, and can be killed immediately if
  needed (`tools/revoke_token.py`).
- **Least privilege / micro-segmentation** -- each resource has its own
  minimum role and minimum device-trust policy (externalized to
  `pdp/policies.json`); protected resources are network-unreachable except
  through the gateway, and now additionally require mutual TLS with the
  gateway's CA-issued client certificate.
- **Cryptographic device attestation** -- `finance-app` requires a
  challenge-response proof of possession of an enrolled (TPM-backed on
  Windows) device key, independent of the self-reported posture score. See
  `docs/DEVICE_ATTESTATION.md`.
- **Full audit trail** -- every allow/deny decision logged to a
  hash-chained (tamper-evident) log; renders to a browsable HTML dashboard.
- **Automated proof, not just a demo** -- 28 integration tests
  (`tests/test_ztna.py`) exercise the real system end to end over real
  HTTPS requests. All 28 pass (`docs/TEST_RESULTS_HARDENED.md`).

## Quickstart (Windows)

```
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
.\run_all.ps1
```

OpenSSL is **not required** -- TLS certificates (including the internal CA
used for mutual TLS between the Gateway and the protected resources) are
generated with the `cryptography` package, already a required dependency.

Then, in a new terminal:

```
python -m agent.client_agent --user alice --resource docs-app --demo       # ALLOWED
python -m agent.client_agent --user alice --resource finance-app --demo    # DENIED (role)
python -m agent.client_agent --user bob   --resource finance-app --demo    # ALLOWED (real device posture permitting -- see note below)
python -m agent.client_agent --user carol --resource finance-app --demo --simulate-compromised  # DENIED (device trust)
```

Full walkthrough, including Windows Firewall network segmentation, mutual
TLS, and wiring up a real authenticator app: **`docs/WINDOWS_SETUP.md`**.

## Demo accounts

| Username | Password       | Role             | Notes                                                     |
| -------- | -------------- | ---------------- | --------------------------------------------------------- |
| alice    | `Intern#2026`  | intern           | can reach docs-app only                                   |
| bob      | `Manager#2026` | finance\_manager | can reach both, on a healthy device                       |
| carol    | `Manager#2026` | finance\_manager | use `--simulate-compromised` to demo context-aware denial |
| admin    | `Admin#2026`   | admin            | highest privilege                                         |

(`--demo` auto-computes the correct TOTP code for these seeded accounts so
the project runs without needing a phone; see `docs/WINDOWS_SETUP.md`
Section 6 to wire up a real authenticator app instead.)

`bob`'s "ALLOWED" outcome above depends on his device's REAL posture score
(unless `--simulate-compromised` is passed) -- on a machine without
Defender/BitLocker/Firewall detectable (e.g. this project's own Linux dev
sandbox), the real score can land below finance-app's 80 threshold, which
is the posture check working as intended, not a bug. Use
`python -m agent.device_posture` to see your machine's current score and
per-check breakdown.

## Project layout

```
common/     shared config, RS256 JWT helpers, internal CA + mTLS, rate
            limiting, revocation, hash-chained audit logging, TOTP
idp/        Identity Provider -- password + MFA (+ pluggable local/LDAP
            backend) -> RS256 JWT
pdp/        Policy Decision Point -- ABAC engine, policy externalized to
            pdp/policies.json
gateway/    Policy Enforcement Point -- validates + checks revocation +
            authorizes + proxies over mTLS + logs every request
resources/  Two protected backends (docs-app: low sensitivity,
            finance-app: high sensitivity), now mTLS-only
agent/      Client agent: device posture check (Windows/macOS/Linux) +
            login + resource access, incl. --watch mode
tests/      Integration test suite (spins up all 4 services for real,
            28 tests)
dashboard/  Generates a self-contained HTML audit dashboard from the
            access log
tools/      Admin CLIs: revoke_token.py, verify_audit_log.py,
            provision_certs.py (multi-host PKI), network_probe.py (evidence)
deploy/     Reverse-proxy configs (nginx/Caddy) + HA deployment notes for
            a real multi-host deployment
docs/       Architecture, hardening pass writeup, Windows setup guide,
            MULTI_HOST_LAB.md (real-network deployment + evidence capture),
            evaluation results, captured test runs
```

## Running the tests yourself

```
python -m unittest tests.test_ztna -v
```

## Regenerating the dashboard

```
python -m dashboard.generate_dashboard
start dashboard\dashboard.html
```

To verify the audit log's integrity:
```
python -m tools.verify_audit_log
```

## Revoking a session

```
python -m tools.revoke_token --jti <token-id-from-login-response>
python -m tools.revoke_token --user bob
```

## Known limitations (documented deliberately -- good material for a
"future work" section in your report)

This revision closed several of the original gaps -- see
`docs/HARDENING.md` for the full drawback -> fix -> verification mapping.
What's left, named explicitly rather than silently skipped:

1. Device trust score is still self-reported by the client agent (though
   now paired with an independent, cryptographically verifiable
   attestation dimension -- see `docs/DEVICE_ATTESTATION.md`). Production
   systems use external attestation (MDM) instead.
2. Device enrollment (`idp/device_registry.py`) is trust-on-first-use --
   the first enrollment for a device_id is accepted unconditionally.
3. No high-availability / multi-instance deployment story yet (note: running
   across separate machines IS supported and documented in
   `docs/MULTI_HOST_LAB.md`; what's missing is running *several instances of
   the same component*) -- the
   revocation store, audit-log writer, and IdP's in-memory rate-limit/
   enrollment state all currently assume a single instance. See
   `deploy/README.md`'s HA section for exactly what would need to change.
4. `idp/auth_backends.py`'s LDAP backend is structurally complete but has
   not been exercised against a real directory server in this development
   sandbox -- verify before citing as a tested result.
5. Still only proxies HTTP backends -- no TCP-level (SSH/RDP/DB) resource
   brokering, which a full commercial ZTNA product would also cover.

Each of these is a legitimate, citable extension if more scope is wanted.
