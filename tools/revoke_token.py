#!/usr/bin/env python3
"""
Admin CLI to revoke a specific token (by jti) or every currently-active
token for a user, without needing an authenticated network admin endpoint
(deliberately kept as a local CLI, not an HTTP route, to avoid adding an
unauthenticated network-facing "revoke anything" endpoint to the Gateway --
see docs/HARDENING.md for the reasoning).

Writes directly to the same revocation store (common/revocation.py) the
Gateway checks on every request, so a revoked session is cut off on its
very next call -- no service restart required.

Usage:
    python -m tools.revoke_token --jti <token-id>
    python -m tools.revoke_token --user bob
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import revocation, token_store


def main():
    parser = argparse.ArgumentParser(description="Revoke a PyZTNA access token")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--jti", help="revoke a single token by its jti claim")
    group.add_argument("--user", help="revoke every currently-active token for this username")
    parser.add_argument("--reason", default="manual_revocation", help="reason recorded in the revocation entry")
    args = parser.parse_args()

    if args.jti:
        revocation.revoke(args.jti, reason=args.reason)
        print(f"Revoked jti={args.jti}")
        return

    jtis = token_store.active_jtis_for_user(args.user)
    if not jtis:
        print(f"No active (non-expired, recorded) tokens found for user '{args.user}'. "
              f"Note: only tokens issued since token_store tracking was enabled are visible here.")
        return
    for jti in jtis:
        revocation.revoke(jti, reason=args.reason)
    print(f"Revoked {len(jtis)} token(s) for user '{args.user}': {jtis}")


if __name__ == "__main__":
    main()
