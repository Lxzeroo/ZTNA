# Hardening Pass: Drawback -> Fix -> How to Verify

This document maps every gap identified in `docs/ARCHITECTURE.md` Section
4 and the README's original "Known limitations" to what was actually
changed in this revision, where the code lives, and how to exercise it
yourself. Written in the same spirit as `docs/DEVICE_ATTESTATION.md`:
honest about what's fully tested versus what's structurally complete but
unverified against real external infrastructure this sandbox doesn't have
(no LDAP server, no TPM, no multi-host network).

## Addressed in this pass

### 1. JWT shared secret (HS256) -> asymmetric signing (RS256)

**Was:** every service that could verify a token also held the same
secret that could mint one (`common.config.JWT_SECRET`). Compromising the
Gateway would have exposed the ability to forge valid tokens.

**Now:** `common/rsa_utils.py` generates an RSA-2048 keypair
(`certs/jwt_keys/`). `common/jwt_utils.py` signs with the private key and
verifies with the public key. In a real multi-host deployment, only the
public key file needs to reach the Gateway machine.

**Verify:** `tests/test_ztna.py::TestHardenedTokens::test_token_is_signed_with_rs256`
decodes the JWT header and asserts `alg == "RS256"`.

### 2. No rate limiting / brute-force protection on `/login`

**Was:** unlimited password/OTP guesses against `/login`.

**Now:** `common/rate_limiter.py` -- after `ZTNA_LOGIN_MAX_ATTEMPTS`
(default 5) failures for a username within `ZTNA_LOGIN_WINDOW_SECONDS`
(default 300s), further attempts return `429 account_locked` for
`ZTNA_LOGIN_LOCKOUT_SECONDS` (default 300s). A successful login resets the
counter. Wired into `idp/idp_server.py::handle_login`.

**Verify:** `tests/test_ztna.py::TestRateLimiting`.

### 3. No token revocation list

**Was:** a compromised session stayed valid until its TTL (45s) elapsed,
with no way to kill it sooner.

**Now:** `common/revocation.py` (file-based, checked by the Gateway on
every request) plus `common/token_store.py` (tracks recently-issued jtis
per user so "revoke every session for user X" is possible without a full
session database) and `tools/revoke_token.py` (admin CLI, not an
unauthenticated network endpoint -- see the file's docstring for why).

**Verify:** `tests/test_ztna.py::TestTokenRevocation`.

### 4. Self-signed cert per service, ad-hoc via openssl CLI

**Was:** each service generated its own independent self-signed cert by
shelling out to `openssl`; clients ran with `verify=False`; no way to
distinguish "a real PyZTNA service" from "anything with a self-signed
cert." Also created an external-tool dependency (OpenSSL on PATH) with a
silent HTTP fallback if it was missing (see `docs/CHANGELOG.md`'s bug
writeup).

**Now:** `common/ca_utils.py` implements a minimal internal CA (root
key+cert in `certs/ca/`); every service gets its own leaf cert SIGNED by
that CA (`common/tls_utils.py`). Cert generation uses the `cryptography`
library, not an external tool, so the OpenSSL-missing fallback path no
longer exists -- `common.tls_utils.scheme()` always returns `"https"`.

**Verify:** `certs/ca/ca_cert.pem` and `certs/services/*_cert.pem` exist
after any service has started once; `openssl x509 -in certs/services/gateway_cert.pem -noout -issuer`
shows the internal CA as issuer.

### 5. No mTLS between Gateway and resources (network isolation was the only control)

**Was:** `docs-app`/`finance-app` bound to `127.0.0.1` and relied entirely
on that binding + optional firewall rules to prevent non-Gateway access.

**Now:** both resources serve TLS and require a client certificate signed
by the internal CA (`resources/docs_app.py`, `resources/finance_app.py`,
`common/http_utils.py::serve(..., require_client_cert=True)`). Only the
Gateway is issued a client cert (`common.config.GATEWAY_CLIENT_CERT_CN`),
built once at Gateway startup (`gateway/gateway_server.py`). This is a
SECOND, independent control alongside firewall/loopback isolation, not a
replacement for it.

**Verify:** `tests/test_ztna.py::TestMTLSIsolation::test_direct_resource_connection_without_client_cert_is_refused` --
attempts a plain TLS connection (no client cert) directly to `docs-app`
and confirms the TLS handshake itself fails, before any application-layer
check ever runs.

### 6. Audit log had no integrity protection

**Was:** `logs/access_log.jsonl` was a plain append-only file; anyone with
local write access could edit or delete historical entries undetected.

**Now:** `common/audit_log.py` hash-chains every line (each line's hash
covers its own content plus the previous line's hash). `tools/verify_audit_log.py`
walks the chain and reports exactly where it breaks, if it does. See that
module's docstring for the honest limit of what this catches (silent
partial edits) versus what it doesn't (a full-file rewrite with a freshly
recomputed chain).

**Verify:** `tests/test_ztna.py::TestAuditLogIntegrity` and
`python -m tools.verify_audit_log`.

### 7. Policy hardcoded in Python (`pdp/policy_engine.py`)

**Was:** resource thresholds lived directly in `common.config.RESOURCES`,
requiring a code change (and redeploy) to adjust.

**Now:** `pdp/policies.json` overrides those thresholds at runtime;
`pdp.policy_engine.reload_policies()` re-reads the file without a process
restart. Falls back to `common.config.RESOURCES` for anything not present
in the JSON file, so this is additive, not a breaking change.

**Verify:** edit `pdp/policies.json` (e.g. raise `docs-app`'s
`min_device_trust` to 90), call `reload_policies()`, and confirm
`pdp.policy_engine.evaluate()` reflects the new threshold immediately --
covered by `tests/test_ztna.py::TestPolicyExternalization`.

### 8. Single hardcoded identity source (no directory federation)

**Was:** `idp/users_db.py`'s in-memory dict was the only identity source.

**Now:** `idp/auth_backends.py` introduces a pluggable interface;
`LocalAuthBackend` (default, wraps the unchanged `users_db.py`) and
`LDAPAuthBackend` (binds to a real LDAP/AD server via the optional `ldap3`
package). Selected via `ZTNA_AUTH_BACKEND` env var.

**Honest scope:** `LDAPAuthBackend` was written against the documented
`ldap3` simple-bind API and reviewed carefully, but this sandbox has no
LDAP server to test against -- it has NOT been exercised end-to-end,
exactly like the Windows/TPM attestation path in
`docs/DEVICE_ATTESTATION.md`. Before citing "LDAP integration" as a
demonstrated result, stand up a test directory (e.g. a local OpenLDAP
Docker container) and confirm login + role-derivation against it.

### 9. Windows-only device posture checks

**Was:** `agent/device_posture.py`'s disk-encryption check only
implemented Windows (BitLocker); macOS/Linux unconditionally scored zero
for that dimension regardless of actual disk state.

**Now:** real FileVault (`fdesetup status`) and LUKS
(`lsblk`/`cryptsetup`) checks added for macOS and Linux respectively; the
firewall check also gained real macOS (`socketfilterfw`) and Linux
(`firewall-cmd`, in addition to the existing `ufw`) paths.

**Verify:** run `python -m agent.device_posture` on a Linux machine with
an active LUKS volume and confirm `disk_encryption: true` in the output
(this sandbox's own filesystem is not LUKS-encrypted, so a clean run here
will correctly show `false` -- that's the check working, not failing).

### 10. Stdlib HTTP servers have no WAF-level protection

**Was:** no request-size limits, connection throttling, or edge rate
limiting beyond the application-level login lockout.

**Now:** `deploy/nginx.conf` and `deploy/Caddyfile` (see
`deploy/README.md`) -- a reverse proxy is the recommended real-deployment
front door, adding request-size limits and IP-based rate limiting in
addition to (not instead of) the IdP's own per-username lockout.

## Explicitly NOT addressed in this pass (named, not silently skipped)

- **TOFU device enrollment** (`idp/device_registry.py`): first enrollment
  for a `device_id` is still accepted unconditionally. Gating this behind
  an admin-approval step remains future work (see
  `docs/DEVICE_ATTESTATION.md` Section 7).
- **Full high availability / multi-instance deployment**: see
  `deploy/README.md`'s HA section for exactly what would need to change
  (revocation store, audit-log writer, IdP in-memory state) and why it
  wasn't done here without real multi-host infrastructure to verify
  failover against.
- **TCP-level (non-HTTP) resource brokering**: PyZTNA still only proxies
  HTTP backends. Brokering SSH/RDP/database protocols the way a full
  commercial ZTNA product does would need a TCP-level (e.g. SNI-routed or
  SOCKS-style) broker, which is a materially larger project scoped out
  here.
- **Real LDAP directory verification**: `LDAPAuthBackend` is structurally
  complete and reviewed but has not been executed against a real directory
  server. Verify before citing it as a tested result -- see Section 8 above.

  (The Windows/TPM attestation path is **no longer** in this category -- it
  was verified on real AMD fTPM 2.0 hardware on 2026-08-02, which also
  uncovered a .NET API-compatibility bug that had been silently degrading
  it to a software key. See `docs/DEVICE_ATTESTATION.md` Section 4.)

## Updated test count

The original suite was 19 tests (`docs/TEST_RESULTS.md`). This revision
adds tests for RS256 tokens, revocation, rate limiting, audit-log
integrity, policy externalization, and mTLS isolation -- see
`tests/test_ztna.py` for the current full list and
`docs/TEST_RESULTS_HARDENED.md` for a captured run from this sandbox.
