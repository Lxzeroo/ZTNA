# Evaluation

Scored against the quality characteristics used in the reference paper
*"Zero Trust Network Access (ZTNA) to Secure Website Applications Based on
ISO 25023"* (IEEE, 2025), plus the automated test evidence produced by this
project's own test suite (`tests/test_ztna.py`).

## 1. Functional suitability

`python -m unittest tests.test_ztna -v` -- 19/19 tests passed on the
original design (transcript in `docs/TEST_RESULTS.md`); this hardening
revision adds further tests for RS256 tokens, revocation, rate limiting,
and audit-log integrity (see `docs/HARDENING.md` for the updated count and
`tests/test_ztna.py` for the full suite).

## 2. Performance efficiency

Benchmarked locally (50 requests per measurement, loopback network), prior
to this hardening pass:

| Operation | Mean | Median | p95 |
|---|---|---|---|
| Direct resource call (no ZTNA, baseline) | 2.55 ms | 2.44 ms | 3.31 ms |
| IdP login (password + MFA verify + JWT issue) | 248.8 ms | 236.2 ms | 323.7 ms |
| Gateway-mediated access (token verify + PDP + proxy) | 6.61 ms | 6.59 ms | 7.83 ms |

RS256 verification is slightly more CPU-expensive than HS256 per call, but
still sub-millisecond at 2048-bit key size; not expected to be visible
against the login path's dominant bcrypt cost. mTLS between gateway and
resources adds a one-time handshake per proxied connection (the gateway
opens a fresh connection per request currently -- see docs/HARDENING.md
"known remaining gaps" for the connection-pooling follow-up this implies).

## 3. Security

- **Confidentiality in transit**: IdP and Gateway serve over TLS; with
  this revision, protected resources also serve TLS and require a client
  certificate from the Gateway (mTLS) -- see `docs/HARDENING.md`.
- **Integrity**: JWTs are now signed with RS256 (asymmetric); the Gateway
  only ever holds the public key.
- **Resistance to lateral movement**: unchanged -- resources bind to
  `127.0.0.1` only, now additionally protected by mTLS at the application
  layer, not just network/firewall isolation.
- **Multi-factor authentication**: unchanged -- real TOTP (RFC 6238).
- **Device identity attestation**: now verified end to end on real TPM 2.0
  hardware (AMD fTPM 3.87.0.5), not only via the software fallback --
  `hardware_backed: True`. Reaching that result also exposed a .NET
  API-compatibility defect that had been silently degrading the TPM path to
  a software key on every Windows PowerShell 5.1 host. See
  `docs/DEVICE_ATTESTATION.md` Section 4 and `docs/CHANGELOG.md`.
- **Remaining known gaps**: see `docs/HARDENING.md`'s "not addressed in
  this pass" section -- TOFU device enrollment, full HA/multi-instance
  deployment, and TCP-level (non-HTTP) resource brokering are still future
  work, named explicitly rather than silently out of scope.

## 4. Reliability

Unchanged: `gateway/gateway_server.py` catches backend connection failures
explicitly and returns `502 backend_unreachable` with a logged reason.

## 5. Usability

Unchanged for the end user -- the same `--demo` CLI commands work
identically. Operationally, running the project now requires no extra
manual step (the internal CA and per-service certs are generated
automatically on first run, same UX as the previous self-signed cert).

## 6. Comparison back to the literature

Unchanged conclusions from the original evaluation: ZTNA's dominant cost is
at the identity-verification step (~250ms, bcrypt-dominated), not the
per-request enforcement step (~4-7ms). This revision's mTLS handshake adds
to the per-request gateway-to-resource cost specifically; see
`docs/HARDENING.md` for the measured delta and the connection-pooling
mitigation noted as follow-up work.
