# PyZTNA — A Zero Trust Network Access Implementation (Windows)

Repo: https://github.com/Lxzeroo/ZTNA
Current release: **v2.0.0** — security hardening pass (RS256 tokens, mutual TLS, revocation, rate limiting, tamper-evident audit log)

> This document was written by pulling the actual repo source (not just the GitHub page) and tracing each claim to code, so what follows is verified against `common/`, `idp/`, `gateway/`, `tests/`, and `docs/` — not just restated from the project description.

A from-scratch, working ZTNA system: identity provider with real MFA, a policy decision point, a policy-enforcing gateway, two protected resources, a client agent with device posture + cryptographic attestation, a tamper-evident audit log, and a dashboard — built to run on Windows with a minimal dependency list (everything else is Python's standard library).

## Why this exists

Built to accompany a report on implementing ZTNA on a Windows network, following the approach in *"Fortifying Linux Server and Implementing a Zero Trust Network Access (ZTNA) for Enhanced Security"* (MDPI, 2025), adapted for Windows and evaluated against the quality framework from *"Zero Trust Network Access (ZTNA) to Secure Website Applications Based on ISO 25023"* (IEEE, 2025). Full citations in `docs/ARCHITECTURE.md`.

## What's actually implemented (verified in code)

| Area | Implementation | Where |
|---|---|---|
| MFA | bcrypt password hash + hand-rolled RFC 6238 TOTP, interoperable with any real authenticator app | `idp/idp_server.py`, `common/totp.py` |
| ABAC access control | Role **and** device-trust score both evaluated against per-resource policy | `pdp/policy_engine.py`, `pdp/policies.json` |
| Login rate limiting / lockout | In-memory, per-username sliding window: locks after `LOGIN_MAX_ATTEMPTS` (default 5) failures in `LOGIN_WINDOW_SECONDS` (default 300s) for `LOGIN_LOCKOUT_SECONDS` (default 300s); resets on success; checked *before* credentials are touched to avoid timing leaks | `common/rate_limiter.py`, wired into `idp/idp_server.py`; covered by `tests/test_ztna.py::TestRateLimiting` |
| Asymmetric token signing | JWT moved from shared-secret HS256 to RS256 (RSA‑2048); Gateway only ever needs the public key | `common/rsa_utils.py`, `common/jwt_utils.py`; `TestHardenedTokens::test_token_is_signed_with_rs256` |
| Token revocation | File-based revocation list checked by the Gateway on every request, plus per-user "kill all sessions" via a jti tracker; admin CLI, not a network-exposed endpoint | `common/revocation.py`, `common/token_store.py`, `tools/revoke_token.py`; `TestTokenRevocation` |
| Token binding | RFC 7800 `cnf` claim + DPoP-style per-request proof — a stolen token is unusable without the device's private key | `common/token_binding.py` |
| Step-up authentication | `auth_time`/`amr` claims with per-resource freshness requirements | `pdp/policies.json`, PDP logic |
| Internal CA + mutual TLS | Minimal internal CA issues per-service leaf certs; Gateway↔resource traffic requires a Gateway-issued client cert; no external OpenSSL dependency | `common/ca_utils.py`, `common/tls_utils.py`, `common/http_utils.py` |
| Cryptographic device attestation | Challenge–response proof of possession of an enrolled device key (TPM-backed on Windows where available, with a fixed export bug — see Changelog); independent of self-reported posture | `agent/device_attestation.py`; `docs/DEVICE_ATTESTATION.md` |
| Device enrollment approval | First enrollment returns 202 and waits for admin approval instead of trust-on-first-use | `idp/device_registry.py`, `tools/manage_devices.py` |
| Tamper-evident audit log | Hash-chained log entries; integrity verifiable after the fact | `common/audit_log.py`, `tools/verify_audit_log.py` |
| Key rotation | Scripted rotation including an emergency-compromise path | `tools/rotate_keys.py`, `docs/KEY_ROTATION.md` |
| Externalized, hot-reloadable policy | ABAC rules live in a data file, not hardcoded | `pdp/policies.json` |
| Pluggable auth backend | Local directory today; LDAP backend implemented but **not** exercised against a real directory server | `idp/auth_backends.py` |
| Multi-host deployment | Every host/port configurable via env vars; bind vs. dial addresses separated; per-host cert/key provisioning; negative-control network probe tooling | `tools/provision_certs.py`, `tools/network_probe.py`, `docs/MULTI_HOST_LAB.md` |
| Ops hygiene | `/health` + `/ready` endpoints, graceful shutdown/drain, config preflight validation before binding a port, structured JSON logs with request-id correlation, audit-log backup/restore with a manifest | `common/preflight.py`, `common/obs.py`, `tools/backup_audit_log.py` |
| Repo hygiene / CI | MIT license; GitHub Actions running the suite on Windows + Linux across Python 3.10/3.12, dependency CVE scanning, and a guard against committing key material again (motivated by a real past leak, now inert since the CA was regenerated) | `.github/workflows/ci.yml`, `tools/check_no_secrets.py` |
| Automated proof | **52** integration tests exercising all four services end-to-end over real HTTPS | `tests/test_ztna.py`; `docs/TEST_RESULTS_HARDENED.md` |

## Known limitations — current, code-verified state

The repo names these explicitly rather than burying them (see `docs/HARDENING.md` for the full drawback → fix → verification mapping of everything that *was* closed):

1. **Device trust score is still self-reported** by the client agent — now paired with the independent, cryptographically verifiable attestation dimension above, but the posture score itself is still client-asserted. Production systems would pair this with real MDM-based external attestation.
2. **Device enrollment is trust-on-first-use** — the first enrollment for a given `device_id` is accepted unconditionally (approval only gates *subsequent* access, not the initial claim of that ID).
3. **No high-availability / multi-instance story yet.** Running across *separate machines* is supported and documented (`docs/MULTI_HOST_LAB.md`) — what's missing is running *several instances of the same component*: the revocation store, audit-log writer, and IdP's in-memory rate-limit/enrollment state all assume a single instance. `deploy/README.md` documents exactly what would need to change.
4. **LDAP auth backend is structurally complete but untested** against a real directory server — don't cite it as a verified result without exercising it against one.
5. **HTTP-only backend proxying** — no TCP-level (SSH/RDP/DB) resource brokering, which a full commercial ZTNA product would also cover.

Each is a legitimate, citable "future work" item.

## Architecture

```
common/     shared config, RS256 JWT helpers, internal CA + mTLS, rate
            limiting, revocation, hash-chained audit logging, TOTP
idp/        Identity Provider — password + MFA (+ pluggable local/LDAP
            backend) -> RS256 JWT
pdp/        Policy Decision Point — ABAC engine, policy externalized to
            pdp/policies.json
gateway/    Policy Enforcement Point — validates + checks revocation +
            authorizes + proxies over mTLS + logs every request
resources/  Two protected backends (docs-app: low sensitivity,
            finance-app: high sensitivity), mTLS-only
agent/      Client agent: device posture check (Windows/macOS/Linux) +
            device attestation + login + resource access, incl. --watch
tests/      Integration test suite (spins up all 4 services for real,
            52 tests)
dashboard/  Generates a self-contained HTML audit dashboard
tools/      Admin CLIs: revoke_token.py, verify_audit_log.py,
            provision_certs.py, network_probe.py, manage_devices.py,
            rotate_keys.py, backup_audit_log.py, check_no_secrets.py
deploy/     Reverse-proxy configs (nginx/Caddy) + HA deployment notes
docs/       Architecture, hardening writeup, Windows setup, multi-host
            lab guide, evaluation results, changelog
```

Request flow: **agent → IdP (auth + MFA + rate-limit check) → PDP (ABAC decision) → Gateway (mTLS enforcement + revocation check) → resource**, with every decision logged to the hash-chained audit trail.

## Dependencies

Deliberately minimal — everything else (HTTP server, TLS/CA, hashing, TOTP, rate limiting, revocation, audit-log chaining) is standard library:

- `PyJWT` — signed access tokens (RS256)
- `bcrypt` — password hashing at rest
- `requests` — HTTP client for the agent and test suite
- `psutil` — process listing for the device-posture antivirus check
- `cryptography` — RSA keypairs for JWT signing, internal CA, device attestation
- `ldap3` — optional, only needed if `ZTNA_AUTH_BACKEND=ldap` is actually selected

## Quickstart (Windows)

```
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
.\run_all.ps1
```

OpenSSL is **not required** — all TLS certs (including the internal CA) are generated with the `cryptography` package.

Then, in a new terminal:

```
python -m agent.client_agent --user alice --resource docs-app --demo       # ALLOWED
python -m agent.client_agent --user alice --resource finance-app --demo    # DENIED (role)
python -m agent.client_agent --user bob   --resource finance-app --demo    # ALLOWED (real device posture permitting)
python -m agent.client_agent --user carol --resource finance-app --demo --simulate-compromised  # DENIED (device trust)
```

### One-time device approval

`finance-app` requires cryptographic device attestation, and a newly enrolled device waits for admin approval by default:

```
python -m tools.manage_devices --list --pending-only
python -m tools.manage_devices --approve <device_id>
```

Re-run the `bob` command afterward and it succeeds — that's the control working, not a failure. To skip approval on a throwaway single-machine demo: `ZTNA_REQUIRE_DEVICE_APPROVAL=0`.

Full walkthrough (Windows Firewall segmentation, mTLS, wiring a real authenticator app): `docs/WINDOWS_SETUP.md`.

## Demo accounts

| Username | Password       | Role             | Notes                                                     |
| -------- | -------------- | ---------------- | ---------------------------------------------------------- |
| alice    | `Intern#2026`  | intern           | can reach docs-app only                                    |
| bob      | `Manager#2026` | finance_manager  | can reach both, on a healthy device                        |
| carol    | `Manager#2026` | finance_manager  | use `--simulate-compromised` to demo context-aware denial  |
| admin    | `Admin#2026`   | admin            | highest privilege                                          |

`--demo` auto-computes the correct TOTP so the project runs without a phone.

## Running the tests

```
python -m unittest tests.test_ztna -v
```

## Admin / verification tools

```
python -m dashboard.generate_dashboard        # rebuild HTML audit dashboard
python -m tools.verify_audit_log               # verify hash-chain integrity
python -m tools.revoke_token --jti <token-id>   # revoke one session
python -m tools.revoke_token --user bob         # revoke all of bob's sessions
python -m agent.device_posture                  # show this machine's posture score breakdown
```

## Recommended next course of action

Given the limitations above are already precisely scoped in the repo's own docs, the highest-leverage next steps are:

1. **Pick one of the five open limitations and close it next**, in roughly this order of effort-to-payoff:
   - HA / multi-instance support (item 3) — `deploy/README.md` already says what's needed; this is the most "production-realness" per hour of work.
   - LDAP backend verification (item 4) — cheap to de-risk (spin up a test OpenLDAP container) and turns an unverified claim into a tested one.
   - Device-enrollment TOFU tightening (item 2) — e.g. require an out-of-band admin code on first enrollment, not just on subsequent access.
2. **If this is headed into an academic report**, explicitly map each ISO 25023 quality characteristic you're citing to the specific control that satisfies it (e.g. Security→Confidentiality → mTLS + RS256; Security→Non-repudiation → hash-chained audit log) — you already have the raw material, it just needs the mapping made explicit in `docs/EVALUATION.md`.
3. **If this is headed into a portfolio/interview context**, the CHANGELOG's documented bugs (Windows pipe-buffer deadlock, OneDrive `os.replace()` failure, silent TPM-attestation downgrade) are strong interview material — they show debugging real infrastructure issues, not just writing green-path code. Be ready to walk through the TPM bug in particular: a security control that fails silently and *looks* like it's working is a genuinely important lesson.
4. **Small polish item:** the repo currently shows no GitHub description or topics — add both (`zero-trust`, `ztna`, `abac`, `mfa`, `mtls`, `python`) now that it's public, since that's free discoverability you're not using yet.
