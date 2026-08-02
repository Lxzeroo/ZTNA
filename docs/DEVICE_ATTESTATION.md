# Device Attestation: From Self-Reported Posture to Cryptographic Proof

## 1. Motivation

The original design (see `docs/ARCHITECTURE.md` Section 4) computes a
device trust score locally (`agent/device_posture.py`) and simply *tells*
the Identity Provider that number. This was flagged as the project's most
significant limitation: nothing stops a modified agent from lying about
its own health, because the server has no independent way to verify the
claim -- it is a self-report, not a proof.

This document describes the mechanism added to close that gap: a
challenge-response protocol in which a resource can require proof that the
login came from a specific, previously-enrolled device key, rather than
trusting whatever score the agent happens to report. On Windows this key
is generated and held inside the machine's TPM 2.0 chip, so answering the
challenge correctly requires possession of hardware that cannot be copied
by editing a script.

## 2. Related work and how this differs

| Approach | What it verifies | Key weakness this design addresses |
|---|---|---|
| Self-reported posture score (this project's original design; also common in commercial ZTNA products) | Whatever the agent claims | Agent can lie; server has no independent verification |
| US11936671B1 -- "Zero trust architecture with browser-supported security posture data collection" | Browser-collected posture *data* forwarded to the access decision | Still a data-collection/reporting model, not a cryptographic proof of device identity -- a compromised collector can still misreport |
| WebAuthn / FIDO2 (W3C standard, widely deployed for user authentication) | Possession of a hardware-bound private key, via challenge-response | Designed for *user* authentication to a single relying party, not *device* posture gating per-resource inside an internal ZTNA policy engine |
| TPM remote attestation (quote + PCR values, e.g. TCG's standard remote attestation) | The exact boot-time software state of a machine | Requires a full attestation certificate chain and a reference PCR database; heavyweight for a project-scale system (noted as future work below) |
| **This project's design** | Possession of a TPM-bound (or, on non-Windows/no-TPM, software) private key, via a single-use signed challenge, combined *as a separate policy dimension* alongside role and self-reported trust score | Narrower than full TPM quote-based attestation, but demonstrably closes the "agent can lie" gap for the specific claim that matters here -- "is this the same enrolled device" -- and integrates directly into a per-resource ABAC policy engine rather than being a standalone identity check |

## 3. Protocol

```
 Agent                              Identity Provider           Policy Decision Point
   |                                        |                            |
   |--- POST /enroll {device_id, pubkey} -->|  (idempotent, TOFU)        |
   |                                        |  stores pubkey             |
   |                                        |                            |
   |--- POST /challenge {device_id} ------->|  generates random nonce,   |
   |<-- {nonce, expires_in: 30s} -----------|  stores (device_id, nonce) |
   |                                        |  single-use                |
   |  sign(nonce) using device private key  |                            |
   |  (TPM on Windows / local key fallback) |                            |
   |                                        |                            |
   |--- POST /login {..., device_id,        |                            |
   |     attestation_signature} ----------->|  verify signature against  |
   |                                        |  enrolled pubkey; consume  |
   |                                        |  nonce (prevents replay)   |
   |<-- JWT {..., attested: true/false} ----|                            |
   |                                        |                            |
   |--- GET /access/<resource>              |                            |
   |     Authorization: Bearer <JWT> ------------------------------------>|  evaluate(claims, resource):
   |                                        |                            |  if resource.require_attestation
   |                                        |                            |    and not claims.attested:
   |                                        |                            |      deny("attestation_required")
```

### Cryptographic choices

- **RSA-2048** key pairs.
- **PKCS#1 v1.5** signature padding (SHA-256).
- Each challenge nonce is 32 random bytes (`os.urandom(32)`), single-use,
  and expires after 30 seconds (`idp/device_registry.py:CHALLENGE_TTL_SECONDS`).

## 4. Two key backends -- and an honest statement of what's verified

**Windows / TPM path**: creates an RSA-2048 key using the "Microsoft
Platform Crypto Provider" Key Storage Provider via PowerShell's
`New-SelfSignedCertificate`. Signing is done via
`RSACertificateExtensions.GetRSAPrivateKey(cert).SignData(...)`.

**Software fallback**: an ordinary RSA-2048 key pair generated with the
`cryptography` library and stored as a local PEM file, used automatically
on any non-Windows machine, or on Windows if the TPM/provider is
unavailable. `hardware_backed: False` for this path.

**What has actually been verified.** Both paths are now confirmed working.

*Software fallback path:* the full protocol -- enrollment, challenge
issuance, signing, verification, replay prevention, forgery rejection and
policy gating -- is exercised end to end by `tests/test_ztna.py`
(`TestDeviceAttestation`, 5 tests), which run on any platform.

*Windows / TPM path: VERIFIED on real hardware (2026-08-02).*

| | |
|---|---|
| TPM | AMD firmware TPM 2.0, ManufacturerVersion 3.87.0.5, PPI 1.3 |
| State | `TpmPresent: True`, `TpmReady: True`, `TpmEnabled: True`, `TpmActivated: True` |
| Shell | Windows PowerShell 5.1 (build 26100.8875) -- i.e. .NET Framework, not .NET Core |
| Result | `{'hardware_backed': True, 'mode': 'tpm'}` |

Reproduce with:

```powershell
$env:ZTNA_ATTESTATION_DEBUG=1
python -c "from agent.device_attestation import ensure_enrolled; print(ensure_enrolled('verify-tpm-test'))"
```

**Privilege requirements (measured, not assumed).** Creating the TPM-bound
key was performed in an **elevated** PowerShell. Once the key exists, a
**non-elevated** process reuses it successfully and returns the *same*
public key -- confirming that day-to-day operation does not require
administrator rights. This mirrors how commercial MDM-managed attestation
is deployed: a privileged one-time provisioning step, then unprivileged
use. Whether *initial creation* also succeeds unprivileged was not tested,
since the key already existed by that point; assume elevation is needed for
enrollment unless you verify otherwise.

**A bug this verification exposed, and why it matters.** The first attempts
against this same working TPM all fell back to a software key. Two defects
were stacked:

1. The PowerShell helper called `RSA.ExportSubjectPublicKeyInfo()`. That
   method was introduced in .NET Core 3.0 and **does not exist in .NET
   Framework 4.x**, which is what Windows PowerShell 5.1 -- the
   `powershell.exe` present on every Windows 10/11 install -- runs on. The
   certificate was created correctly inside the TPM; the very next line
   threw `MethodNotFound`; the script exited non-zero. The export now uses
   `$cert.RawData`, available on every PowerShell version, and derives the
   public key on the Python side with the `cryptography` library.
2. That failure was **silent**. The graceful-degradation design caught the
   error and quietly produced a software key, so a fully capable TPM looked
   indistinguishable from absent hardware. `ZTNA_ATTESTATION_DEBUG=1` now
   surfaces the underlying PowerShell error.

The second defect is the more interesting one for the report: fail-safe
degradation is correct behaviour for availability, but silent degradation
of a *security* property is dangerous -- the system was weaker than it
appeared, and reported nothing. Degradation should be loud and, in a
production deployment, should itself be an auditable event.

## 5. Security analysis

- **Replay resistance**: nonce is deleted on first use regardless of
  outcome.
- **Forgery resistance**: verification uses the enrolled public key only.
- **Graceful degradation**: unenrolled/no-signature logins result in
  `attested: False`, not an error.
- **Known limitation -- trust-on-first-use (TOFU)**: the first enrollment
  for a device_id is accepted unconditionally. Not addressed by this
  hardening pass (see `docs/HARDENING.md` for what was and wasn't in
  scope) -- still noted as future work below.
- **Known limitation -- no attestation certificate chain**: still not
  implemented; noted as future work (see Section 7).

## 6. Framing for a novelty/report claim

> A per-resource ABAC policy dimension that requires a fresh, single-use,
> challenge-response proof of possession of a TPM-bound device key --
> evaluated independently of, and in addition to, a continuously-
> reverified self-reported context score -- inside a gateway that re-runs
> the full policy decision on every request rather than once per session.

## 7. Future work

- Attestation certificate chain validation (full TPM quote + PCR
  comparison against a reference database).
- ECDSA P-256 support.
- Mobile TEE (Secure Enclave / StrongBox) backends.
- Replacing open self-enrollment with an admin-approved provisioning flow
  (closes the TOFU gap in Section 5; not addressed by this hardening pass).
- Per-resource attestation strength tiers ("software key acceptable" vs.
  "TPM required").
