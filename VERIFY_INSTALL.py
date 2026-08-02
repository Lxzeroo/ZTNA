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
    ("common/http_utils.py", "PyZTNA/2.0", "Server version string is current"),
]

REQUIRED_FILES = [
    "common/rate_limiter.py", "common/revocation.py", "common/rsa_utils.py",
    "common/ca_utils.py", "common/token_store.py", "common/totp.py",
    "idp/auth_backends.py", "pdp/policies.json",
    "tools/revoke_token.py", "tools/verify_audit_log.py",
    "docs/HARDENING.md",
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
        print("FAILED -- this tree is not a clean v2.0.1 install:\n")
        for f in failures:
            print("  " + f)
        print(f"\n{len(failures)} problem(s) across {total} checks.")
        print("Re-copy the full project folder rather than individual files.")
        sys.exit(1)

    print(f"OK -- all {total} checks passed. This is a complete, correctly-wired v2.1.0 tree.")
    print("\nNext: python -m unittest tests.test_ztna -v      (expect 28 tests, OK)")
    sys.exit(0)


if __name__ == "__main__":
    main()
