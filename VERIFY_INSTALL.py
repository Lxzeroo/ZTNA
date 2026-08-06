#!/usr/bin/env python3
"""
Self-check that this copy of PyZTNA is the complete, correctly-wired
v2.1.0 tree -- not a partially-updated one.

This exists because a previous packaging mistake left the new modules in
place while every *modified* file stayed at its pre-hardening version. The
old code was internally consistent, so everything still ran and nothing
errored -- the security features were simply never called. That failure
mode is silent, so this script makes it loud.

Run from the project root:
    python VERIFY_INSTALL.py

Exit code 0 = all checks pass. 1 = something is stale or missing.
"""
import os
import sys

CHECKS = [
    # (path, must-contain marker, human description)
    ("idp/idp_server.py", "rate_limiter", "IdP calls the login rate limiter"),
    ("idp/idp_server.py", "auth_backends", "IdP uses the pluggable auth backend"),
    ("idp/idp_server.py", "account_locked", "IdP returns 429 on lockout"),
    ("common/config.py", 'JWT_ALGORITHM = "RS256"', "Tokens are RS256, not HS256"),
    ("common/config.py", "MTLS_ENABLED", "mTLS configuration present"),
    ("common/config.py", "LOGIN_MAX_ATTEMPTS", "Rate-limit thresholds configured"),
    ("common/jwt_utils.py", "jti", "Tokens carry a revocable token id"),
    ("common/jwt_utils.py", "load_private_key_pem", "Signing uses the RSA private key"),
    ("gateway/gateway_server.py", "revocation.is_revoked", "Gateway checks the revocation list"),
    ("gateway/gateway_server.py", "HTTPSConnection", "Gateway proxies over TLS"),
    ("common/audit_log.py", "prev_hash", "Audit log is hash-chained"),
    ("common/audit_log.py", "verify_chain", "Audit chain verification available"),
    ("pdp/policy_engine.py", "POLICIES_FILE", "Policy loads from pdp/policies.json"),
    ("agent/device_attestation.py", "CERT_B64", "TPM path uses RawData export (PS 5.1 compatible)"),
    ("agent/device_attestation.py", "_debug(", "Attestation failures are diagnosable"),
    ("agent/device_posture.py", "fdesetup", "Posture checks cover macOS"),
    ("agent/device_posture.py", "cryptsetup", "Posture checks cover Linux"),
    ("common/http_utils.py", "PyZTNA/2.1", "Server version string is current"),
    # --- production-readiness pass (docs/PRODUCTION_READINESS.md) ---
    ("common/jwt_utils.py", "auth_time", "Tokens carry auth_time for step-up policy"),
    ("common/jwt_utils.py", "cnf_jkt", "Tokens can be bound to a device key"),
    ("common/http_utils.py", "_builtin_ready", "Readiness endpoint is present"),
    ("common/http_utils.py", "_drain_and_stop", "Graceful shutdown is wired up"),
    ("idp/device_registry.py", "STATUS_PENDING", "Device enrollment requires approval"),
    ("pdp/policy_engine.py", "max_auth_age", "PDP enforces step-up freshness"),
    ("gateway/gateway_server.py", "token_requires_proof", "Gateway enforces token binding"),
]

REQUIRED_FILES = [
    "common/rate_limiter.py", "common/revocation.py", "common/rsa_utils.py",
    "common/ca_utils.py", "common/token_store.py", "common/totp.py",
    "idp/auth_backends.py", "pdp/policies.json",
    "tools/revoke_token.py", "tools/verify_audit_log.py",
    "docs/HARDENING.md",
    # production-readiness pass
    "common/storage.py", "common/obs.py", "common/preflight.py",
    "common/token_binding.py",
    "tools/manage_devices.py", "tools/rotate_keys.py",
    "tools/backup_audit_log.py", "tools/check_no_secrets.py",
    "docs/PRODUCTION_READINESS.md", "docs/KEY_ROTATION.md",
    "LICENSE", ".github/workflows/ci.yml",
]

# Markers that must be ABSENT -- these indicate a stale pre-hardening file.
FORBIDDEN = [
    ("common/config.py", 'JWT_ALGORITHM = "HS256"', "config.py is the OLD pre-hardening version"),
    ("common/config.py", "JWT_SECRET = os.environ", "config.py still uses a shared secret"),
]


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    failures = []

    for rel in REQUIRED_FILES:
        if not os.path.exists(os.path.join(root, rel)):
            failures.append(f"MISSING FILE   {rel}")

    for rel, marker, desc in CHECKS:
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            failures.append(f"MISSING FILE   {rel}")
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            if marker not in f.read():
                failures.append(f"STALE FILE     {rel}  ({desc})")

    for rel, marker, desc in FORBIDDEN:
        path = os.path.join(root, rel)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                if marker in f.read():
                    failures.append(f"OLD CODE FOUND {rel}  ({desc})")

    total = len(CHECKS) + len(REQUIRED_FILES) + len(FORBIDDEN)
    if failures:
        print("FAILED -- this tree is not a clean v2.2.0 install:\n")
        for f in failures:
            print("  " + f)
        print(f"\n{len(failures)} problem(s) across {total} checks.")
        print("Re-copy the full project folder rather than individual files.")
        sys.exit(1)

    print(f"OK -- all {total} checks passed. This is a complete, correctly-wired v2.1.0 tree.")
    print("\nNext: python -m unittest tests.test_ztna -v      (expect 52 tests, OK)")
    sys.exit(0)


if __name__ == "__main__":
    main()
