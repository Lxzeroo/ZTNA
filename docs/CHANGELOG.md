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


## Fix: TPM attestation silently degraded to a software key on all Windows PowerShell 5.1 hosts

**Symptom:** on a machine with a healthy, enabled TPM 2.0,
`ensure_enrolled()` always returned
`{'hardware_backed': False, 'mode': 'software_fallback'}`. No error was
shown beyond the routine fallback warning, so the system appeared to be
working while providing a materially weaker guarantee than it claimed.

**Root cause:** `agent/device_attestation.py` asked PowerShell to export
the public key with `RSA.ExportSubjectPublicKeyInfo()`. That method arrived
in .NET Core 3.0 and is **absent from .NET Framework 4.x**, which is what
Windows PowerShell 5.1 runs on -- and 5.1 is the `powershell.exe` shipped
with every Windows 10/11 machine. The TPM-bound certificate was created
successfully; the export line then threw `MethodNotFound`; the script
exited non-zero; the caller treated that as "no TPM available".

Confirmed by running the same `New-SelfSignedCertificate` command manually
(succeeded, returning a thumbprint) and then
`[System.Security.Cryptography.RSA]::Create().ExportSubjectPublicKeyInfo()`
(method not found) on PowerShell 5.1.

**Fix:** export the raw certificate bytes via `$cert.RawData` -- available
on every PowerShell version -- and derive the SubjectPublicKeyInfo on the
Python side using the `cryptography` library, which is already a required
dependency. Backtick line-continuations were also removed from the embedded
scripts, as they are fragile when a multi-line script is passed as a single
`-Command` argument through `subprocess`.

**Also added:** `ZTNA_ATTESTATION_DEBUG=1` now prints the underlying
PowerShell stdout/stderr on failure. The original bug was hard to find
precisely because the failure path was silent.

**Verified by:** `hardware_backed: True, mode: tpm` on AMD firmware TPM 2.0
(ManufacturerVersion 3.87.0.5) under Windows PowerShell 5.1, elevated for
key creation and non-elevated for subsequent reuse. Full suite still
28/28. See `docs/DEVICE_ATTESTATION.md` Section 4.

**Takeaway for the report:** graceful degradation is the right instinct for
availability, but degrading a *security* control silently is a hazard in
itself -- the deployment was weaker than it appeared and said nothing. Any
fallback that lowers a security guarantee should be loud, and in production
should be an auditable event rather than a log line.


## Feature: multi-host deployment support and negative-control evidence tooling

**Motivation:** every component defaulted to `127.0.0.1`, so the isolation
claims could only be demonstrated on one machine -- where "unreachable
except through the Gateway" is true largely because of loopback binding.

**Four blockers were found and fixed** before the code could run across
machines. Each failed silently or with a misleading error:

1. Resource addresses were hardcoded to `127.0.0.1`, so the Gateway could
   not dial a remote backend. Every host/port is now settable via
   `ZTNA_*` environment variables, and bind address is now distinct from
   dial address (`*_BIND_HOST` vs `*_HOST`).
2. Each host generated its **own** internal CA on first start, so the
   Gateway's client certificate was signed by one CA while the resource
   trusted another -- every mTLS handshake failed.
3. Each host generated its **own** JWT keypair, so the Gateway rejected
   every token the IdP issued as `token_signature_invalid`.
4. Certificates carried only `localhost` and `127.0.0.1` in
   SubjectAltName, so TLS hostname verification failed against real
   addresses.

Blockers 2 and 3 are addressed by `tools/provision_certs.py`, which
generates the CA and JWT keypair once and emits per-host bundles containing
only what each host needs -- notably the Gateway receives the JWT **public**
key only, preserving the security property that RS256 was adopted for.
Blocker 4 is addressed by SAN support in `common/ca_utils.py`, including a
check that reissues rather than silently reusing a certificate that does not
cover the required names.

**Added `tools/network_probe.py`** to capture negative-control evidence:
it verifies that a direct connection to a protected resource is refused at
the network layer (firewall) and, independently, at the TLS layer (missing
client certificate) -- with distinct error signatures for each.

**A TLS 1.3 subtlety found while building it:** under TLS 1.2 a missing
client certificate failed during the handshake, but under TLS 1.3 the
handshake completes and the rejection only surfaces on the first read or
write. The first version of the probe reported "handshake OK" and therefore
produced a false result stating that mTLS was *not* being enforced when it
was working correctly. The probe now performs a full request/response round
trip. The general lesson -- do not treat handshake completion as proof of
admission -- is documented in `docs/MULTI_HOST_LAB.md` section 7.

**Verified:** full suite still 28/28; additionally exercised end to end with
services bound to `0.0.0.0` and dialled by a non-`127.0.0.1` address, with
certificate hostname verification enabled, confirming the SAN and
bind/dial separation work. Full guide: `docs/MULTI_HOST_LAB.md`.
