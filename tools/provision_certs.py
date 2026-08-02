#!/usr/bin/env python3
"""
Central PKI provisioning for a MULTI-HOST PyZTNA deployment.

WHY THIS EXISTS
---------------
On a single machine everything self-provisions: the first service to start
generates the internal CA and the JWT signing keypair, and every other
service finds them already on disk. Across machines that breaks silently
and confusingly, because each host generates its OWN:

  * CA          -> the Gateway's client certificate is signed by CA-A while
                   the resource trusts CA-B, so every mTLS handshake fails.
  * JWT keypair -> the IdP signs tokens with key-A while the Gateway
                   verifies against key-B, so every token is rejected as
                   "token_signature_invalid" even though it was just issued.

Neither failure names the real cause, and both look like application bugs.

This tool generates the CA and the JWT keypair ONCE, issues every leaf
certificate with the correct SubjectAltNames for the real addresses, and
writes one bundle per host containing only what that host legitimately
needs. Copy each bundle to its machine and start the services normally.

WHAT EACH HOST GETS (least privilege -- deliberately not "copy certs/ to
everything"):

  idp          CA cert, its own key+cert, JWT PRIVATE key (it mints tokens)
  gateway      CA cert, its own key+cert, the mTLS client key+cert,
               JWT PUBLIC key only (it only verifies -- it cannot forge)
  docs-app     CA cert, its own key+cert
  finance-app  CA cert, its own key+cert
  agent        CA cert only (so it can verify the IdP/Gateway for real
               instead of disabling TLS verification)

Note the Gateway never receives the JWT private key. That is the whole
point of the RS256 migration (docs/HARDENING.md item 1): compromising the
Gateway must not confer the ability to mint tokens.

USAGE
-----
    python -m tools.provision_certs \\
        --idp-host 192.168.1.10 \\
        --gateway-host 192.168.1.11 \\
        --docs-host 192.168.1.12 \\
        --finance-host 192.168.1.12 \\
        --out dist

Addresses may be IPs or DNS names; both are placed in the certificates.
Add --extra-san to include additional names (e.g. a DNS alias clients use).
"""
import argparse
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import ca_utils
from common.config import (CA_CERT_PATH, CA_KEY_PATH, GATEWAY_CLIENT_CERT_CN,
                            JWT_PRIVATE_KEY_PATH, JWT_PUBLIC_KEY_PATH)
from common import rsa_utils


def _copy(src, dst_dir, rename=None):
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, rename or os.path.basename(src))
    shutil.copyfile(src, dst)
    return dst


def main():
    ap = argparse.ArgumentParser(
        description="Provision the internal CA, JWT keypair and per-host certificate bundles "
                    "for a multi-host PyZTNA deployment.")
    ap.add_argument("--idp-host", required=True, help="address other machines use to reach the IdP")
    ap.add_argument("--gateway-host", required=True, help="address clients use to reach the Gateway")
    ap.add_argument("--docs-host", required=True, help="address the Gateway uses to reach docs-app")
    ap.add_argument("--finance-host", required=True, help="address the Gateway uses to reach finance-app")
    ap.add_argument("--extra-san", action="append", default=[],
                    help="additional hostname/IP to place on every certificate (repeatable)")
    ap.add_argument("--out", default="dist", help="output directory for the per-host bundles")
    args = ap.parse_args()

    extra = list(args.extra_san)

    print("Generating internal CA (if not already present)...")
    ca_utils.ensure_ca()
    print(f"  CA certificate: {CA_CERT_PATH}")

    print("Generating JWT signing keypair (if not already present)...")
    rsa_utils.ensure_jwt_keypair()
    print(f"  private: {JWT_PRIVATE_KEY_PATH}")
    print(f"  public : {JWT_PUBLIC_KEY_PATH}")

    print("\nIssuing leaf certificates...")
    leaves = {
        "idp":         ca_utils.issue_cert("idp",         extra_sans=[args.idp_host] + extra),
        "gateway":     ca_utils.issue_cert("gateway",     extra_sans=[args.gateway_host] + extra),
        "docs-app":    ca_utils.issue_cert("docs-app",    extra_sans=[args.docs_host] + extra),
        "finance-app": ca_utils.issue_cert("finance-app", extra_sans=[args.finance_host] + extra),
    }
    client_key, client_cert = ca_utils.issue_cert(GATEWAY_CLIENT_CERT_CN, is_client=True,
                                                   extra_sans=extra)
    for name, (k, c) in leaves.items():
        print(f"  {name:<12} {os.path.basename(c)}")
    print(f"  {'gateway(mTLS client)':<12} {os.path.basename(client_cert)}")

    out = os.path.abspath(args.out)
    print(f"\nWriting per-host bundles to {out} ...")

    def bundle(host_name, leaf=None, jwt_private=False, jwt_public=False, mtls_client=False):
        root = os.path.join(out, host_name)
        ca_dir = os.path.join(root, "certs", "ca")
        svc_dir = os.path.join(root, "certs", "services")
        jwt_dir = os.path.join(root, "certs", "jwt_keys")
        _copy(CA_CERT_PATH, ca_dir)
        if leaf:
            k, c = leaves[leaf]
            _copy(k, svc_dir); _copy(c, svc_dir)
        if mtls_client:
            _copy(client_key, svc_dir); _copy(client_cert, svc_dir)
        if jwt_private:
            _copy(JWT_PRIVATE_KEY_PATH, jwt_dir)
        if jwt_public:
            _copy(JWT_PUBLIC_KEY_PATH, jwt_dir)
        print(f"  {host_name}/")
        return root

    bundle("idp", leaf="idp", jwt_private=True, jwt_public=True)
    bundle("gateway", leaf="gateway", jwt_public=True, mtls_client=True)
    bundle("docs-app", leaf="docs-app")
    bundle("finance-app", leaf="finance-app")
    bundle("agent")

    print(f"""
Done.

NEXT STEPS
  1. Copy each bundle's `certs/` directory onto the matching machine, into
     the project root (so it becomes <project>/certs/).
  2. Set the environment variables for that host -- see
     docs/MULTI_HOST_LAB.md section 4.
  3. Start the service on each host as usual.
  4. Verify with:  python -m tools.network_probe --gateway-host {args.gateway_host} \\
                       --resource-host {args.docs_host} --resource-port 9101

SECURITY NOTES
  * The CA private key ({os.path.basename(CA_KEY_PATH)}) is NOT included in any
    bundle. It stays only on the machine you ran this from. If that machine is
    the IdP, keep it there; for a lab, keeping it on an admin workstation is
    cleaner.
  * The gateway bundle contains the JWT PUBLIC key only. Do not copy the
    private key to it -- doing so would undo the point of asymmetric signing.
  * These bundles contain private keys. Move them over a trusted channel and
    delete `{args.out}/` when provisioning is finished. Never commit them.
""")


if __name__ == "__main__":
    main()
