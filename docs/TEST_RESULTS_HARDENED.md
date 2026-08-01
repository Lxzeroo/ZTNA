# Captured Test Run -- Hardening Revision

Command: `python -m unittest tests.test_ztna -v`
Environment: Python 3.10, all 4 services started as real subprocesses on loopback (Linux sandbox, no TPM/LDAP available -- see docs/HARDENING.md for what that does and doesn't cover).
Date: 2026-08-01

```
test_current_log_chain_is_intact (tests.test_ztna.TestAuditLogIntegrity) ... ok
test_tampering_with_a_historical_line_is_detected (tests.test_ztna.TestAuditLogIntegrity) ... ok
test_every_decision_is_logged (tests.test_ztna.TestAuditTrail) ... ok
test_unknown_user_rejected (tests.test_ztna.TestAuthentication) ... ok
test_valid_credentials_and_mfa_issue_token (tests.test_ztna.TestAuthentication) ... ok
test_wrong_otp_rejected (tests.test_ztna.TestAuthentication) ... ok
test_wrong_password_rejected (tests.test_ztna.TestAuthentication) ... ok
test_correct_role_but_compromised_device_is_still_denied (tests.test_ztna.TestContextAwareAccessControl) ... ok
test_low_trust_device_denied_even_for_low_sensitivity_resource (tests.test_ztna.TestContextAwareAccessControl) ... ok
test_attestation_signature_cannot_be_replayed (tests.test_ztna.TestDeviceAttestation) ... ok
test_forged_attestation_signature_is_rejected (tests.test_ztna.TestDeviceAttestation) ... ok
test_high_trust_correct_role_but_no_attestation_is_denied (tests.test_ztna.TestDeviceAttestation) ... ok
test_unenrolled_device_gets_unattested_not_an_error (tests.test_ztna.TestDeviceAttestation) ... ok
test_valid_attestation_signature_is_accepted (tests.test_ztna.TestDeviceAttestation) ... ok
test_token_carries_a_unique_jti (tests.test_ztna.TestHardenedTokens) ... ok
test_token_is_signed_with_rs256 (tests.test_ztna.TestHardenedTokens) ... ok
test_finance_manager_with_healthy_device_reaches_finance_app (tests.test_ztna.TestLeastPrivilegeAccessControl) ... ok
test_intern_can_reach_low_sensitivity_resource (tests.test_ztna.TestLeastPrivilegeAccessControl) ... ok
test_intern_cannot_reach_high_sensitivity_resource (tests.test_ztna.TestLeastPrivilegeAccessControl) ... ok
test_direct_resource_connection_without_client_cert_is_refused (tests.test_ztna.TestMTLSIsolation) ... ok
test_editing_policy_file_changes_enforcement_after_reload (tests.test_ztna.TestPolicyExternalization) ... ok
test_repeated_failed_logins_trigger_lockout (tests.test_ztna.TestRateLimiting) ... ok
test_missing_token_rejected (tests.test_ztna.TestTokenIntegrityAndContinuousVerification) ... ok
test_tampered_token_rejected (tests.test_ztna.TestTokenIntegrityAndContinuousVerification) ... ok
test_token_expires_and_is_rejected_after_ttl (tests.test_ztna.TestTokenIntegrityAndContinuousVerification) ... ok
test_revoke_by_username_finds_active_jti (tests.test_ztna.TestTokenRevocation) ... ok
test_revoked_token_is_denied_even_though_still_unexpired (tests.test_ztna.TestTokenRevocation) ... ok
test_request_for_undefined_resource_is_rejected (tests.test_ztna.TestUnknownResource) ... ok

----------------------------------------------------------------------
Ran 28 tests in 23.326s

OK
```

28/28 passing: the original 19 (unchanged scenarios/outcomes) plus 9 new
tests covering RS256 signing, token revocation (by jti and by username),
rate limiting/lockout, audit-log hash-chain integrity (both the positive
case and actual tamper detection), PDP policy hot-reload from
`pdp/policies.json`, and mTLS isolation (a direct TLS connection to
`docs-app` with no client certificate is refused at the handshake level).

Also manually verified in this sandbox (not part of the automated suite,
since it depends on the local machine's real posture rather than an
injected value):
- `python -m tools.verify_audit_log` -> `OK -- N log entries, hash chain intact.`
- `python -m dashboard.generate_dashboard` -> renders correctly with the
  hardened event set.
- End-to-end CLI demo (`agent.client_agent`) against all 4 live services:
  alice->docs-app ALLOWED, alice->finance-app DENIED (insufficient_role),
  carol(compromised)->finance-app DENIED (insufficient_device_trust). Note
  that in this Linux sandbox, `bob`'s REAL (non-simulated) device posture
  score comes out below finance-app's 80 threshold (no AV process,
  firewall, or disk encryption detected in this environment) -- this is
  the posture check doing exactly what it's supposed to do, not a defect;
  on real Windows hardware with Defender/BitLocker/Firewall active, the
  score is higher, as documented in the original evaluation.

Regenerate this evidence yourself at any time with:
```
python -m unittest tests.test_ztna -v
```
