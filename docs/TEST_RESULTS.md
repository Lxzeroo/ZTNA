# Captured Test Run

Command: `python -m unittest tests.test_ztna -v`
Environment: Python 3.10, all 4 services started as real subprocesses on loopback.
Date: 2026-07-30

```
/usr/local/lib/python3.10/dist-packages/urllib3/connectionpool.py:1110: InsecureRequestWarning: Unverified HTTPS request is being made to host '127.0.0.1'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
test_every_decision_is_logged (tests.test_ztna.TestAuditTrail) ... ok
test_unknown_user_rejected (tests.test_ztna.TestAuthentication) ... ok
test_valid_credentials_and_mfa_issue_token (tests.test_ztna.TestAuthentication) ... ok
test_wrong_otp_rejected (tests.test_ztna.TestAuthentication) ... ok
test_wrong_password_rejected (tests.test_ztna.TestAuthentication) ... ok
test_correct_role_but_compromised_device_is_still_denied (tests.test_ztna.TestContextAwareAccessControl) ... ok
test_low_trust_device_denied_even_for_low_sensitivity_resource (tests.test_ztna.TestContextAwareAccessControl) ... ok
test_finance_manager_with_healthy_device_reaches_finance_app (tests.test_ztna.TestLeastPrivilegeAccessControl) ... ok
test_intern_can_reach_low_sensitivity_resource (tests.test_ztna.TestLeastPrivilegeAccessControl) ... ok
test_intern_cannot_reach_high_sensitivity_resource (tests.test_ztna.TestLeastPrivilegeAccessControl) ... ok
test_missing_token_rejected (tests.test_ztna.TestTokenIntegrityAndContinuousVerification) ... ok
test_tampered_token_rejected (tests.test_ztna.TestTokenIntegrityAndContinuousVerification) ... ok
test_token_expires_and_is_rejected_after_ttl (tests.test_ztna.TestTokenIntegrityAndContinuousVerification)
Proves the system re-verifies on every call instead of trusting ... ok
test_request_for_undefined_resource_is_rejected (tests.test_ztna.TestUnknownResource) ... ok

----------------------------------------------------------------------
Ran 14 tests in 10.110s

OK
```

Regenerate this evidence yourself at any time with:
```
python -m unittest tests.test_ztna -v
```
