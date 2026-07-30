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

The specific combination used here -- a challenge-response key-possession
proof gating individual resource policies in a continuous-verification ZTNA
gateway, alongside (not instead of) a self-reported context score -- is the
part of the design that goes beyond directly reusing an existing published
technique. Section 6 discusses this framing further for anyone using this
project as the basis of a novelty claim in a report.

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

Implementation: `idp/device_registry.py` (enrollment store, challenge
issuance, signature verification), `idp/idp_server.py` (`/enroll`,
`/challenge` endpoints, and the attestation check wired into `/login`),
`agent/device_attestation.py` (key management and signing on the client),
`pdp/policy_engine.py` (the `require_attestation` policy dimension).

### Cryptographic choices

- **RSA-2048** key pairs.
- **PKCS#1 v1.5** signature padding (SHA-256), chosen deliberately over
  RSA-PSS: PKCS#1v1.5 is fully deterministic with no salt-length
  negotiation, and its signing API (`RSA.SignData(..., RSASignaturePadding.Pkcs1)`)
  is identical across .NET Framework and .NET Core. Since the Windows agent
  signs via PowerShell/.NET while the verifier runs in Python
  (`cryptography` library), removing any possibility of a padding-mode
  mismatch between the two implementations was judged more important than
  PSS's marginally stronger security proof at this key size.
- Each challenge nonce is 32 random bytes (`os.urandom(32)`), single-use,
  and expires after 30 seconds (`idp/device_registry.py:CHALLENGE_TTL_SECONDS`).

## 4. Two key backends -- and an honest statement of what's verified

**Windows / TPM path** (`agent/device_attestation.py`, `_windows_*`
functions): creates an RSA-2048 key using the "Microsoft Platform Crypto
Provider" Key Storage Provider via PowerShell's `New-SelfSignedCertificate`,
which generates and holds the private key inside the TPM 2.0 chip and marks
it non-exportable at the CNG level. Signing is done via
`RSACertificateExtensions.GetRSAPrivateKey(cert).SignData(...)`, which asks
the TPM to perform the signature without the key material ever entering
process memory.

**Software fallback** (`_fallback_*` functions): an ordinary RSA-2048 key
pair generated with the `cryptography` library and stored as a local PEM
file, used automatically on any non-Windows machine, or on Windows if the
TPM/provider is unavailable. This is clearly **not** hardware-backed --
`ensure_enrolled()` returns `hardware_backed: False` for this path, and
that value is available for logging/reporting so the two are never
conflated.

**What has actually been verified, and how:** this project was built and
tested in a Linux sandbox with no TPM hardware available. The full protocol
-- enrollment, challenge issuance, signing, verification, replay
prevention, forgery rejection, and policy gating -- has been tested
end-to-end via the software fallback path and passes all cases in
`tests/test_ztna.py` (`TestDeviceAttestation`, 5 tests; see
`docs/TEST_RESULTS.md`). The Windows/TPM-specific code
(`_windows_ensure_and_export_public_key`, `_windows_sign`) was written
against the documented .NET/CNG APIs and reviewed carefully, but **has not
been executed against a real TPM**. Before citing "hardware-backed
attestation" as a demonstrated result in a report or defense, run this on
a real Windows 10/11 machine with TPM 2.0 enabled and confirm
`hardware_backed: True` is returned:

```powershell
python -c "from agent.device_attestation import ensure_enrolled; print(ensure_enrolled('verify-tpm-test'))"
```

If it prints `hardware_backed: True`, the TPM path is confirmed working on
that machine; if `False`, check `Get-Tpm` output and that the machine
actually has TPM 2.0 enabled in firmware.

## 5. Security analysis

- **Replay resistance**: `device_registry.verify_and_consume()` deletes
  the nonce on first use regardless of outcome (`tests/test_ztna.py::
  test_attestation_signature_cannot_be_replayed`), so a captured signature
  cannot be reused for a second login.
- **Forgery resistance**: verification uses the enrolled public key only;
  a tampered signature byte fails `RSAPublicKey.verify()` and is rejected
  (`test_forged_attestation_signature_is_rejected`).
- **Graceful degradation**: a login for a never-enrolled device, or one
  submitted with no signature at all, does not error -- it simply results
  in `attested: False`, so resources that don't require attestation keep
  working unaffected (`test_unenrolled_device_gets_unattested_not_an_error`).
- **Known limitation -- trust-on-first-use (TOFU)**: the *first*
  enrollment for a given `device_id` is accepted unconditionally, with no
  proof that the enrolling party is who they claim to be. This mirrors how
  SSH host keys and WebAuthn credentials are bootstrapped, and is a
  standard, named limitation of TOFU models -- an attacker who enrolls a
  device_id before the legitimate device does could impersonate it. A
  production system would gate enrollment behind an authenticated
  admin/IT-issued provisioning step rather than open self-enrollment.
- **Known limitation -- no attestation certificate chain**: this design
  proves "the same key that was enrolled is being used again," not "this
  key was genuinely generated inside a genuine TPM with these firmware
  properties" (that stronger claim requires validating the manufacturer's
  attestation certificate chain and PCR quote, which TPM 2.0 supports but
  this project does not implement -- noted as future work).

## 6. Framing for a novelty/report claim

Being direct about scope: broad "check device posture before granting
access" is well-established prior art (see the comparison table above), so
that alone is not a novel contribution. What is more specific to this
project's design, and worth stating precisely in a report rather than
overclaiming:

> A per-resource ABAC policy dimension that requires a fresh,
> single-use, challenge-response proof of possession of a TPM-bound
> device key -- evaluated independently of, and in addition to, a
> continuously-reverified self-reported context score -- inside a
> gateway that re-runs the full policy decision on every request rather
> than once per session.

The distinguishing details are: (a) attestation and self-reported posture
are tracked as two independent claims in the same token rather than one
score, so a policy can require either, both, or neither per resource; (b)
the check re-runs per-request via the existing short-TTL continuous
verification loop, so an attestation "expires" along with everything else
rather than being a one-time login check; and (c) it is implemented as
data-driven policy (`require_attestation: True/False` per resource in
`common/config.py`) rather than hardcoded logic, so the strength of
identity guarantee required is a per-resource configuration choice.

Whether this rises to patentable novelty is a legal question this document
cannot answer -- see the caveats already discussed in chat. For a project
report, the important thing is that this section gives you concrete,
defensible language for what was built and why it differs from the
patent/prior-art it was compared against, backed by a passing, repeatable
test suite rather than an unverified claim.

## 7. Future work

- Attestation certificate chain validation (full TPM quote + PCR
  comparison against a reference database), for the stronger "genuinely
  ran on unmodified firmware" guarantee.
- ECDSA P-256 support as a faster alternative to RSA-2048 for
  resource-constrained devices.
- Mobile TEE (Secure Enclave / StrongBox) backends for a mobile client.
- Replacing open self-enrollment with an admin-approved provisioning flow,
  closing the TOFU gap described in Section 5.
- Per-resource attestation *strength tiers* (e.g., "software key
  acceptable" vs. "TPM required") rather than the current boolean.
