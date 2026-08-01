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

**What has actually been verified:** the full protocol has been tested
end-to-end via the software fallback path (see `tests/test_ztna.py`,
`TestDeviceAttestation`). The Windows/TPM-specific code has NOT been
executed against real TPM hardware. Verify on real hardware with:

```powershell
python -c "from agent.device_attestation import ensure_enrolled; print(ensure_enrolled('verify-tpm-test'))"
```

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
