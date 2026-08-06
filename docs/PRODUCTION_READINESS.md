# Production Readiness Pass

Drawback → fix → how to verify, in the same shape as `docs/HARDENING.md`.

The previous hardening pass closed the four gaps named in the original
README (HS256, rate limiting, revocation, network isolation). This pass
addresses what a production deployment needs beyond that: controls that only
matter once the system is real, plus the operational scaffolding that makes
it survivable.

Test count: **28 → 52**. Run `python -m unittest tests.test_ztna -v`.

---

## Security controls

### 1. Bearer tokens worked from anywhere

**Was:** a token was a bearer token in the literal sense. Anything that
obtained the string — a log file, a crash dump, a proxy, process memory —
could use it from any host on earth until it expired. The 45-second TTL
bounded that window without closing it, and 45 seconds is ample for an
automated exfiltration path.

**Now:** tokens issued to enrolled, approved devices carry a `cnf`
(confirmation) claim pinning them to that device's key thumbprint —
RFC 7800. The Gateway then requires a per-request proof signed by the device
private key, following the DPoP pattern (RFC 9449):

```
X-Device-Proof:      base64(signature)
X-Device-Proof-Data: base64("<jti>|<method>|<path>|<unix_ts>|<nonce>")
```

The signed payload binds the proof to the specific token, the specific
operation, a 30-second freshness window, and a single-use nonce. On Windows
with a TPM the private key is non-exportable, so the proof cannot be
produced off-device even by an attacker with local admin.

**Verify:** `TestTokenBinding`. `test_bound_token_without_proof_is_rejected`
is the exfiltration case directly — same token, valid signature, 200 with
the device key and 401 `device_proof_missing` without it.

**Scope:** binds to the device, not the TLS channel. Against a fully
compromised endpoint that can ask the TPM to sign arbitrary data, no
software control on that endpoint helps — which is the argument for external
attestation (`docs/DEVICE_ATTESTATION.md`). The replay-nonce cache is
per-process, so two Gateway instances would each accept a given proof once;
fixing that needs the shared state backend.

### 2. Authentication freshness was never checked

**Was:** policy asked whether a token was valid, never when the human behind
it last proved who they were. Those diverge the moment tokens are refreshed.

**Now:** tokens carry `auth_time` (when the user actually authenticated, as
distinct from `iat`, when this token was minted — the OpenID Connect
distinction) and `amr` (which methods were used). Resources declare
freshness requirements in `pdp/policies.json`:

```json
"finance-app": {
  "max_auth_age_seconds": 300,
  "required_amr": ["pwd", "otp"]
}
```

A stale token gets 401 `step_up_required` — deliberately not 403, because
the correct client response is to re-authenticate, not to give up.

**Verify:** `TestStepUpAuthentication`. Note
`test_token_without_auth_time_fails_closed`: tokens predating this feature
are treated as failing, not passing. Defaulting to "fresh" would have let
every old token silently bypass step-up.

### 3. Trust on first use in device enrollment

**Was:** the first enrollment for any `device_id` was accepted
unconditionally. `docs/HARDENING.md` named this openly as unaddressed.
Anyone who could reach `/enroll` could register their own key under an
unclaimed `device_id` and produce perfectly valid attestations afterwards.
The cryptography was never the weak part — the binding between "this key"
and "a device someone vouched for" was never established by anyone.

**Now:** enrollment lands in `pending` and returns **202 Accepted**, not 200.
An administrator approves out of band after comparing the thumbprint:

```bash
python -m tools.manage_devices --list --pending-only
python -m tools.manage_devices --approve DESKTOP-ABC123
```

Re-enrolling an approved device with a *different* key forces it back to
pending — otherwise approval was trivially bypassable: enroll honestly, get
approved, swap the key.

**Verify:** `TestDeviceApproval`, in particular
`test_unapproved_device_cannot_attest` (a cryptographically perfect
signature, refused because nobody approved the device) and
`test_reenrolling_with_a_different_key_resets_approval`.

**Demo note:** set `ZTNA_REQUIRE_DEVICE_APPROVAL=0` on a single-machine demo
where there is no administrator to do the approving. Preflight warns loudly
whenever it is disabled.

### 4. No key rotation story

**Was:** no documented expiry or rotation for the CA or JWT keypair. This is
not hypothetical — see `docs/KEY_ROTATION.md` for how five service private
keys ended up in public git history and were neutralised only by an
accidental CA regeneration.

**Now:** `tools/rotate_keys.py` (`--check`, `--what service-certs|jwt|ca`),
scheduled cadences, an emergency compromise runbook, and startup warnings
before expiry. Old material is archived rather than deleted so a botched
rotation can be backed out.

**Verify:** `python -m tools.rotate_keys --check`.

---

## Operational

### 5. No liveness/readiness distinction

**Was:** `/health` on the IdP and Gateway returned a static `{"status":"ok"}`
that would keep returning ok with an unusable state store. Resources had
nothing at all.

**Now:** every service gets `/health` (liveness — restart me if this fails)
and `/ready` (readiness — stop sending me traffic, but do **not** restart
me). Conflating the two causes restart storms during a dependency outage:
every instance fails its check, every instance gets killed, and the
recovering dependency now also faces a thundering herd. `/ready` reports
state-store health and in-flight request count, and returns 503 while
draining.

**Verify:** `TestOperationalEndpoints`.

### 6. No graceful shutdown

**Was:** `serve_forever()` under a bare `KeyboardInterrupt`. A rolling deploy
dropped in-flight requests.

**Now:** SIGTERM/SIGINT flip readiness to false *first* — so load balancers
remove the instance before the listener disappears — then wait up to
`ZTNA_SHUTDOWN_GRACE_SECONDS` for in-flight requests to finish. Closing the
socket first would drop requests already heading toward us, which is the
exact failure a rolling deploy exists to avoid. Forced shutdown logs how many
requests were abandoned rather than exiting quietly.

### 7. Configuration failures were silent

**Was:** the project's own worst bug (`docs/CHANGELOG.md`) was TPM
attestation silently degrading to a software key on every Windows PowerShell
5.1 host — working, reporting success, providing a materially weaker
guarantee. The same shape was available elsewhere: TLS falling back to plain
HTTP, a missing JWT key discovered on first login, an expired CA surfacing
as a confusing handshake error.

**Now:** `common/preflight.py` runs before the port is bound. ERROR findings
refuse startup; WARN findings start loudly. It also flags deployment posture
— a JWT *private* key present on a Gateway host, approval disabled, a memory
state backend, an over-long token TTL.

```bash
python -m common.preflight          # check every service
```

**Verify:** `TestPreflightValidation`, including that a missing policy file
is blocking rather than ignored.

### 8. No request correlation

**Was:** one user request touches three processes. Nothing tied them
together.

**Now:** `X-Request-Id` is adopted or generated at the edge, attached to
every log line via `common/obs.py`, echoed to the client, forwarded on the
internal mTLS hop, and recorded in audit events. Operational logs go to
stdout as JSON (`ZTNA_JSON_LOGS=1`) so a shipper can consume them —
deliberately separate from the audit log, which stays narrow and
hash-chained so it remains usable as evidence.

Unhandled handler exceptions no longer return their text to the caller;
that leaked paths and filenames. The correlation id is returned instead.

**Verify:** `test_correlation_id_is_echoed_back`,
`test_correlation_id_is_generated_when_absent`.

### 9. The only forensic record had no backup

**Was:** hash-chained, so silent partial edits were detectable — but a single
file on one host. Delete it and the chain proves nothing, because there is
nothing left to check.

**Now:** `tools/backup_audit_log.py` verifies the chain before copying,
re-verifies the copy afterwards (verifying the source then copying proves
nothing about what landed on disk), and writes a manifest recording event
count, chain head hash and file SHA-256. Restore refuses to destroy a log
longer than the backup without `--force`.

```bash
python -m tools.backup_audit_log --backup
python -m tools.backup_audit_log --verify <path>
```

**Verify:** tamper a backed-up line and `--verify` reports the exact break
line.

---

## Data layer

### 10. State was welded into each module

**Was:** the revocation list was file-backed (so a CLI could write to it),
the rate limiter in memory (to avoid a disk write per failed login). Both
correct for one instance; both broken at two. In-memory rate limiting gives
an attacker N× the attempts across N instances. File-backed revocation means
a token revoked on host A still works on host B.

**Now:** `common/storage.py` puts one interface in front of that state, so
storage is a deployment choice rather than something welded in. The `file`
default preserves today's exact behaviour. A corrupt state file is logged
loudly, because for the revocation namespace "treat as empty" means "nothing
is revoked".

**Verify:** `TestStorageBackend`.

**Scope:** the Redis backend is described and shaped for, not implemented.
Every operation is a key/value get/set/delete precisely so it can be added
without touching callers. Implementing it also forces an explicit
fail-open/fail-closed decision when the shared store is unreachable — that
decision should be made deliberately, not inherited.

---

## Still open

Named rather than quietly skipped, in the tradition of `docs/HARDENING.md`:

- **PDP is a library, not a service.** `gateway_server.py` does
  `from pdp.policy_engine import evaluate` — in-process. Splitting it out is
  the largest remaining architectural gap, and only then does the
  fail-open/fail-closed question become real.
- **No JWKS / `kid`.** JWT rotation is a hard cutover with no overlap window.
  The highest-value next improvement to key management.
- **Replay cache and rate limiter are still per-process.** The interface
  exists; the shared backend does not.
- **No metrics endpoint.** Logs are structured, but there is no
  Prometheus-style scrape target.
- **PyJWT pinned to 2.3.0** (October 2021). Not exploitable here —
  `verify_token` passes `algorithms=["RS256"]` explicitly, the documented
  mitigation for CVE-2022-29217 — but the pin should be bumped.
- **No admin UI, no self-service enrollment, no "log out everywhere".**
- **TCP brokering** for SSH/RDP/databases remains out of scope.
