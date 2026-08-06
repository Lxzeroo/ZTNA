"""
Key and certificate rotation.

Why this exists
---------------
This repository has already demonstrated, accidentally, why rotation needs
to be a procedure rather than an event. Five service private keys were
committed to public git history in an earlier revision. They are inert today
purely because the internal CA happened to be regenerated afterwards, so
certificates signed by the old CA no longer validate. Nobody planned that.
The exposure was resolved by luck.

A rotation procedure turns that into something deliberate and repeatable:
you can answer "when were these keys last replaced", "how long until they
expire", and "what do I do right now if a key leaks" without hoping.

What can be rotated
-------------------
  service-certs  Per-service TLS certificates (idp, gateway, resources) and
                 the Gateway's mTLS client certificate. Cheap and safe --
                 restart services afterwards.

  jwt            The RS256 signing keypair. Invalidates every live access
                 token, because they were signed by the old private key.
                 With a 45-second TTL that is a 45-second disruption, which
                 is the entire argument for short TTLs.

  ca             The internal CA. The most disruptive: every service
                 certificate must be reissued from the new CA, and until
                 they are, mTLS handshakes fail. Implies service-certs.

Usage
-----
    python -m tools.rotate_keys --check
    python -m tools.rotate_keys --what service-certs
    python -m tools.rotate_keys --what jwt
    python -m tools.rotate_keys --what ca --yes

Old material is moved into certs/archive/<timestamp>/ rather than deleted,
so a botched rotation can be backed out. Archived private keys are still
secrets -- certs/ is gitignored in full, and tools/check_no_secrets.py fails
CI if anything under it is ever staged.

See docs/KEY_ROTATION.md for the operational runbook, including the
emergency (suspected compromise) path.
"""
import argparse
import os
import shutil
import sys
import time

from common.config import (
    CA_DIR, CA_CERT_PATH, CA_KEY_PATH, SERVICE_CERT_DIR, CERT_DIR,
    JWT_KEY_DIR, JWT_PRIVATE_KEY_PATH, JWT_PUBLIC_KEY_PATH,
    CERT_EXPIRY_WARN_DAYS,
)

ARCHIVE_DIR = os.path.join(CERT_DIR, "archive")


def _cert_days_left(path):
    try:
        from cryptography import x509
        with open(path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        try:
            not_after = cert.not_valid_after_utc.timestamp()
        except AttributeError:
            not_after = cert.not_valid_after.timestamp()
        return (not_after - time.time()) / 86400.0
    except Exception:  # noqa: BLE001
        return None


def cmd_check(_args):
    """Report the age and remaining validity of all key material."""
    print("Key material status\n" + "=" * 64)
    rows = []

    if os.path.exists(CA_CERT_PATH):
        rows.append(("CA", CA_CERT_PATH, _cert_days_left(CA_CERT_PATH)))
    else:
        print("  CA certificate      : MISSING -- run tools/provision_certs.py")

    if os.path.isdir(SERVICE_CERT_DIR):
        for name in sorted(os.listdir(SERVICE_CERT_DIR)):
            if name.endswith("_cert.pem"):
                path = os.path.join(SERVICE_CERT_DIR, name)
                rows.append((name[: -len("_cert.pem")], path, _cert_days_left(path)))

    worst = None
    for label, path, days in rows:
        if days is None:
            status = "UNREADABLE"
        elif days < 0:
            status = f"EXPIRED {abs(days):.0f}d ago"
        elif days < CERT_EXPIRY_WARN_DAYS:
            status = f"expires in {days:.0f}d  <-- rotate soon"
        else:
            status = f"valid, {days:.0f}d left"
        print(f"  {label:<22}: {status}")
        if days is not None and (worst is None or days < worst):
            worst = days

    print()
    if os.path.exists(JWT_PRIVATE_KEY_PATH):
        age_days = (time.time() - os.path.getmtime(JWT_PRIVATE_KEY_PATH)) / 86400.0
        print(f"  JWT signing keypair   : created {age_days:.0f} days ago")
        # No expiry is embedded in a raw keypair, so age is the only signal
        # available -- which is itself an argument for scheduled rotation.
        if age_days > 365:
            print("                          (>1 year -- consider rotating: "
                  "python -m tools.rotate_keys --what jwt)")
    else:
        print("  JWT signing keypair   : MISSING -- run tools/provision_certs.py")

    if worst is not None and worst < 0:
        print("\nACTION REQUIRED: expired certificates present. "
              "mTLS handshakes will be failing.")
        return 1
    return 0


def _archive(paths, label):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(ARCHIVE_DIR, f"{stamp}-{label}")
    os.makedirs(dest, exist_ok=True)
    moved = []
    for path in paths:
        if os.path.exists(path):
            shutil.move(path, os.path.join(dest, os.path.basename(path)))
            moved.append(os.path.basename(path))
    if moved:
        print(f"  archived {len(moved)} file(s) -> {dest}")
    return dest


def cmd_rotate_service_certs(args):
    print("Rotating service certificates...")
    paths = []
    if os.path.isdir(SERVICE_CERT_DIR):
        paths = [os.path.join(SERVICE_CERT_DIR, n) for n in os.listdir(SERVICE_CERT_DIR)]
    if not args.yes and not _confirm(
            "This invalidates current service certs. Services must be restarted."):
        return 1
    _archive(paths, "service-certs")
    _reprovision()
    print("\nDone. RESTART all services now -- they hold the old certificate "
          "in memory until they do.")
    return 0


def cmd_rotate_jwt(args):
    print("Rotating the JWT signing keypair...")
    print("  NOTE: every currently-issued access token becomes invalid "
          "immediately (signed by the old key).")
    if not args.yes and not _confirm("Continue?"):
        return 1
    _archive([JWT_PRIVATE_KEY_PATH, JWT_PUBLIC_KEY_PATH], "jwt")
    _reprovision()
    print("\nDone. Restart the IdP and Gateway. Clients will need to log in again.")
    print("In a multi-host deployment, redistribute the PUBLIC key to the Gateway:")
    print("    python -m tools.provision_certs --host gateway")
    return 0


def cmd_rotate_ca(args):
    print("Rotating the internal CA...")
    print("  WARNING: this is the disruptive one. Every service certificate")
    print("  must be reissued from the new CA. Until every service has been")
    print("  restarted with its new certificate, mTLS handshakes WILL FAIL.")
    print("  On a multi-host deployment, redistribute bundles before restarting.")
    if not args.yes and not _confirm("Continue?"):
        return 1
    paths = [CA_CERT_PATH, CA_KEY_PATH]
    if os.path.isdir(SERVICE_CERT_DIR):
        paths += [os.path.join(SERVICE_CERT_DIR, n) for n in os.listdir(SERVICE_CERT_DIR)]
    _archive(paths, "ca")
    _reprovision()
    print("\nDone. Restart ALL services. For multi-host, run:")
    print("    python -m tools.provision_certs --host <name>   (for each host)")
    return 0


def _reprovision():
    """Regenerate whatever is missing, using the project's existing provisioner
    rather than duplicating certificate-generation logic here."""
    os.makedirs(CA_DIR, exist_ok=True)
    os.makedirs(SERVICE_CERT_DIR, exist_ok=True)
    os.makedirs(JWT_KEY_DIR, exist_ok=True)
    try:
        from tools import provision_certs
        if hasattr(provision_certs, "main"):
            argv_backup = sys.argv
            sys.argv = ["provision_certs"]
            try:
                provision_certs.main()
            finally:
                sys.argv = argv_backup
            return
    except Exception as e:  # noqa: BLE001
        print(f"  (provision_certs could not be invoked directly: {e})")

    print("  Run this to regenerate the missing material:")
    print("      python -m tools.provision_certs")


def _confirm(prompt):
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    if answer not in ("y", "yes"):
        print("Aborted -- nothing changed.")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Rotate PyZTNA keys and certificates.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true",
                       help="report age and remaining validity of all key material")
    group.add_argument("--what", choices=["service-certs", "jwt", "ca"],
                       help="what to rotate")
    parser.add_argument("--yes", action="store_true", help="skip confirmation prompts")
    args = parser.parse_args()

    if args.check:
        return cmd_check(args)
    if args.what == "service-certs":
        return cmd_rotate_service_certs(args)
    if args.what == "jwt":
        return cmd_rotate_jwt(args)
    if args.what == "ca":
        return cmd_rotate_ca(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
