# Changelog / Bug Fix Log

Kept deliberately -- a documented bug found during real-world testing (by
someone other than the original author) and its fix is good evidence of an
actual engineering process, not just a first-draft submission.

## Fix: client agent used the wrong URL scheme on machines without OpenSSL

**Symptom:** `agent/client_agent.py` and `tests/test_ztna.py` failed with:
```
ssl.SSLError: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1081)
```

**Root cause:** `idp/idp_server.py` and `gateway/gateway_server.py` both
degrade gracefully to plain HTTP when `openssl` isn't found on PATH (see
`common/tls_utils.py`). That fallback worked correctly -- but the client
agent and the test suite both **hardcoded `https://`** in their base URLs
regardless of what scheme the servers actually came up on.

**Fix:** Added `common.tls_utils.scheme()`. `agent/client_agent.py` and
`tests/test_ztna.py` now call this instead of hardcoding a scheme.

## Fix: run_all.ps1 spawned windows didn't inherit the activated virtualenv

**Fix:** `run_all.ps1` now checks for `.venv\Scripts\Activate.ps1` next to
itself and, if present, activates it inside each spawned window before
running the service module.

## Feature: cryptographic device attestation (replaces "trust me" posture reporting for gated resources)

See `docs/DEVICE_ATTESTATION.md` for the full design, threat model, and
related-work comparison.

## Hardening pass (this revision) -- see docs/HARDENING.md

Following a security review, the following gaps identified in
`docs/ARCHITECTURE.md` Section 4 and the README's "Known limitations" were
addressed in this revision. Each is documented in detail, including honest
scope of what is/isn't fully verified, in `docs/HARDENING.md`:

- JWT switched from shared-secret HS256 to asymmetric RS256.
- Login rate-limiting / lockout added to the IdP.
- Explicit token revocation (by token id or by user) added.
- Internal CA + mutual TLS between the Gateway and protected resources.
- Audit log is now hash-chained (tamper-evident).
- PDP policy externalized to a data file, hot-reloadable.
- Pluggable IdP auth backend (local directory today; LDAP backend
  scaffolded, untested against a real directory server).
- Device posture disk-encryption check extended to macOS/Linux.
- Reverse-proxy (nginx/Caddy) configs added for edge-level request limits
  and TLS termination in a multi-host deployment.

None of these change the externally-observed behavior of the demo
scenarios in `README.md` -- the same `--demo` commands still produce the
same ALLOW/DENY outcomes. What changes is what's now cryptographically or
operationally enforced underneath.
