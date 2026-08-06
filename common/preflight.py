"""
Startup configuration validation -- fail loudly, not silently.

This exists because of a bug this project already suffered. From
docs/CHANGELOG.md: TPM attestation silently degraded to a software key on
every Windows PowerShell 5.1 host. The system kept working and kept
reporting success, while providing a materially weaker guarantee than it
claimed. The takeaway recorded there --

    "degrading a *security* control silently is a hazard in itself ... Any
     fallback that lowers a security guarantee should be loud"

-- generalises past attestation. The same shape of failure is available in
several other places:

  * common/tls_utils.py falls back to plain HTTP when openssl is missing,
    so the whole system can come up unencrypted and look healthy;
  * a missing JWT private key is only discovered on the first login;
  * an expired CA certificate is only discovered on the first mTLS
    handshake, as a confusing TLS error rather than "your CA expired";
  * a state directory that is not writable makes revocation silently
    ineffective (see common/storage.py).

Each check below returns a finding rather than raising, so a service can
report *all* of its problems at once instead of one per restart.

Severity:
  ERROR -- refuse to start. The service cannot do its job correctly.
  WARN  -- start, but say so loudly. Degraded, not broken.

Usage:
    from common.preflight import run_preflight
    run_preflight("gateway", strict=True)

    python -m common.preflight            # check everything, human-readable
"""
import os
import sys
import time

from common import obs
from common.config import (
    JWT_PRIVATE_KEY_PATH, JWT_PUBLIC_KEY_PATH, CA_CERT_PATH, CA_KEY_PATH,
    SERVICE_CERT_DIR, STATE_DIR, LOG_DIR, POLICIES_FILE, MTLS_ENABLED,
    TOKEN_TTL_SECONDS, CERT_EXPIRY_WARN_DAYS, STATE_BACKEND,
    REQUIRE_DEVICE_APPROVAL, TOKEN_BINDING_ENABLED,
)

ERROR = "ERROR"
WARN = "WARN"


class PreflightError(RuntimeError):
    pass


def _finding(severity, check, detail, remedy=None):
    return {"severity": severity, "check": check, "detail": detail, "remedy": remedy}


def _check_writable_dir(path, label):
    """Confirm we can actually write to `path`, not merely that it exists.

    The probe filename includes the pid because every service runs this at
    startup and they start simultaneously. With a shared fixed name, one
    process would delete the probe another was still using, and the loser
    reported the directory as unwritable -- refusing to start over a race
    rather than a real permissions problem. Cleanup tolerates the file
    already being gone for the same reason.
    """
    findings = []
    probe = os.path.join(path, f".preflight_probe.{os.getpid()}")
    try:
        os.makedirs(path, exist_ok=True)
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
    except OSError as e:
        findings.append(_finding(
            ERROR, f"{label}_writable",
            f"{label} directory is not writable: {path} ({e})",
            "Fix filesystem permissions, or point the corresponding ZTNA_*_DIR "
            "environment variable somewhere writable.",
        ))
    finally:
        # Failure to clean up a probe is not a reason to refuse startup.
        try:
            os.remove(probe)
        except OSError:
            pass
    return findings


def _cert_expiry_findings(path, label):
    """Report a certificate that has expired or is about to.

    Without this, an expired internal CA surfaces as an opaque TLS handshake
    failure at request time, which is a genuinely annoying thing to debug
    under pressure.
    """
    findings = []
    if not os.path.exists(path):
        return findings
    try:
        from cryptography import x509
        with open(path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        try:
            not_after = cert.not_valid_after_utc.timestamp()
        except AttributeError:  # cryptography < 42
            not_after = cert.not_valid_after.timestamp()
        days_left = (not_after - time.time()) / 86400.0
        if days_left < 0:
            findings.append(_finding(
                ERROR, f"{label}_expired",
                f"{label} certificate EXPIRED {abs(days_left):.1f} days ago: {path}",
                "Rotate now -- see docs/KEY_ROTATION.md "
                "(python -m tools.rotate_keys --what service-certs).",
            ))
        elif days_left < CERT_EXPIRY_WARN_DAYS:
            findings.append(_finding(
                WARN, f"{label}_expiring",
                f"{label} certificate expires in {days_left:.1f} days: {path}",
                "Schedule rotation -- see docs/KEY_ROTATION.md.",
            ))
    except Exception as e:  # noqa: BLE001
        findings.append(_finding(
            WARN, f"{label}_unreadable",
            f"Could not parse {label} certificate at {path}: {e}",
            "Confirm the file is a PEM X.509 certificate.",
        ))
    return findings


def collect_findings(service: str):
    """Run every applicable check. Returns a list of findings."""
    findings = []
    needs_private_key = service in ("idp",)
    needs_public_key = service in ("idp", "gateway")

    # --- JWT signing material ---
    if needs_private_key and not os.path.exists(JWT_PRIVATE_KEY_PATH):
        findings.append(_finding(
            ERROR, "jwt_private_key_missing",
            f"IdP cannot sign tokens: no private key at {JWT_PRIVATE_KEY_PATH}",
            "Run: python -m tools.provision_certs",
        ))
    if needs_public_key and not os.path.exists(JWT_PUBLIC_KEY_PATH):
        findings.append(_finding(
            ERROR, "jwt_public_key_missing",
            f"Cannot verify tokens: no public key at {JWT_PUBLIC_KEY_PATH}",
            "Run: python -m tools.provision_certs",
        ))

    # The Gateway must NOT hold the signing key. Holding it would silently
    # undo the whole reason RS256 replaced HS256 -- a compromised Gateway
    # could mint tokens again.
    if service == "gateway" and os.path.exists(JWT_PRIVATE_KEY_PATH):
        findings.append(_finding(
            WARN, "gateway_holds_signing_key",
            f"The JWT PRIVATE key is present on the Gateway host: {JWT_PRIVATE_KEY_PATH}. "
            "Only the IdP should hold it; a compromised Gateway can otherwise forge tokens.",
            "Deploy per-host bundles: python -m tools.provision_certs --host gateway "
            "(see docs/MULTI_HOST_LAB.md). Harmless on a single-host demo.",
        ))

    # --- CA / mTLS material ---
    if MTLS_ENABLED:
        if not os.path.exists(CA_CERT_PATH):
            findings.append(_finding(
                ERROR, "ca_cert_missing",
                f"mTLS is enabled but the internal CA certificate is missing: {CA_CERT_PATH}",
                "Run: python -m tools.provision_certs, or set ZTNA_MTLS_ENABLED=0 "
                "to run without mTLS (weaker -- network isolation becomes the only control).",
            ))
        findings.extend(_cert_expiry_findings(CA_CERT_PATH, "ca"))
        if os.path.isdir(SERVICE_CERT_DIR):
            for name in sorted(os.listdir(SERVICE_CERT_DIR)):
                if name.endswith("_cert.pem"):
                    findings.extend(_cert_expiry_findings(
                        os.path.join(SERVICE_CERT_DIR, name),
                        name[: -len("_cert.pem")],
                    ))

    # --- TLS availability ---
    # tls_utils degrades to plain HTTP when it cannot build a server context.
    # That is a reasonable availability choice and a terrible silent one.
    try:
        from common import tls_utils
        scheme = tls_utils.scheme() if hasattr(tls_utils, "scheme") else "https"
        if scheme != "https":
            findings.append(_finding(
                WARN, "tls_disabled",
                "Services are running over plain HTTP, not HTTPS -- tokens and "
                "credentials will cross the network unencrypted.",
                "Install OpenSSL / provision certificates so TLS can be enabled. "
                "Acceptable on an isolated demo host only.",
            ))
    except Exception:  # noqa: BLE001
        pass

    # --- Writable state ---
    findings.extend(_check_writable_dir(LOG_DIR, "log"))
    findings.extend(_check_writable_dir(STATE_DIR, "state"))

    # --- Policy file ---
    if not os.path.exists(POLICIES_FILE):
        findings.append(_finding(
            ERROR, "policies_missing",
            f"PDP policy file not found: {POLICIES_FILE}",
            "Restore pdp/policies.json -- without it no authorization decision can be made.",
        ))
    else:
        try:
            import json
            with open(POLICIES_FILE, "r", encoding="utf-8") as f:
                json.load(f)
        except (ValueError, OSError) as e:
            findings.append(_finding(
                ERROR, "policies_invalid",
                f"PDP policy file is not valid JSON: {POLICIES_FILE} ({e})",
                "Fix the JSON. A malformed policy file must not be silently ignored.",
            ))

    # --- Deployment posture warnings ---
    if not REQUIRE_DEVICE_APPROVAL:
        findings.append(_finding(
            WARN, "device_approval_disabled",
            "ZTNA_REQUIRE_DEVICE_APPROVAL=0 -- any device that enrolls is trusted "
            "on first use, with no administrator in the loop.",
            "Leave enabled outside the single-machine demo.",
        ))
    if not TOKEN_BINDING_ENABLED:
        findings.append(_finding(
            WARN, "token_binding_disabled",
            "ZTNA_TOKEN_BINDING=0 -- a stolen token can be replayed from any host.",
            "Leave enabled unless you are debugging the proof path.",
        ))
    if STATE_BACKEND == "memory":
        findings.append(_finding(
            WARN, "state_backend_memory",
            "State backend is 'memory': revocations and lockouts are lost on restart "
            "and are not shared across instances.",
            "Use ZTNA_STATE_BACKEND=file for anything but tests.",
        ))
    if TOKEN_TTL_SECONDS > 3600:
        findings.append(_finding(
            WARN, "token_ttl_long",
            f"Token TTL is {TOKEN_TTL_SECONDS}s. Long-lived tokens weaken continuous "
            "verification -- the property this system is built to demonstrate.",
            "Prefer minutes, not hours.",
        ))

    return findings


def run_preflight(service: str, strict: bool = True, exit_on_error: bool = True):
    """Validate configuration for `service`.

    strict=True  -> any ERROR finding aborts startup.
    strict=False -> everything is reported, nothing aborts (used by tests
                    and by `python -m common.preflight`).
    """
    findings = collect_findings(service)
    errors = [f for f in findings if f["severity"] == ERROR]
    warns = [f for f in findings if f["severity"] == WARN]

    for f in warns:
        obs.warning(service, "preflight_warning", check=f["check"],
                    detail=f["detail"], remedy=f["remedy"])
    for f in errors:
        obs.critical(service, "preflight_error", check=f["check"],
                     detail=f["detail"], remedy=f["remedy"])

    if errors and strict:
        msg = (
            f"\nPreflight FAILED for '{service}' -- {len(errors)} blocking problem(s):\n\n"
            + "\n".join(
                f"  [{f['check']}] {f['detail']}\n      fix: {f['remedy']}"
                for f in errors
            )
            + "\n\nRefusing to start. A service that starts in this state would "
              "appear healthy while failing to enforce what it claims to enforce.\n"
        )
        if exit_on_error:
            print(msg, file=sys.stderr, flush=True)
            raise SystemExit(2)
        raise PreflightError(msg)

    obs.info(service, "preflight_ok", errors=len(errors), warnings=len(warns))
    return findings


def main():
    service = sys.argv[1] if len(sys.argv) > 1 else "all"
    services = ["idp", "gateway", "docs-app", "finance-app"] if service == "all" else [service]
    worst = 0
    for svc in services:
        print(f"\n=== preflight: {svc} ===")
        findings = run_preflight(svc, strict=False)
        if not findings:
            print("  OK -- no findings.")
        for f in findings:
            print(f"  {f['severity']:<5} [{f['check']}] {f['detail']}")
            if f["remedy"]:
                print(f"        fix: {f['remedy']}")
            worst = max(worst, 1 if f["severity"] == ERROR else 0)
    return worst


if __name__ == "__main__":
    sys.exit(main())
