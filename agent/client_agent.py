#!/usr/bin/env python3
"""
ZTNA Client Agent -- runs on the endpoint (a Windows laptop in the real
deployment) and is the only piece of software a user interacts with.

What it does, matching the flow a real ZTNA client (Ziti Desktop Edge,
Tailscale, etc.) goes through under the hood:

  1. Run a local device posture check (agent/device_posture.py).
  2. Authenticate to the Identity Provider with password + TOTP MFA,
     submitting the current posture score.
  3. Receive a short-lived signed token.
  4. Present that token to the Gateway to reach a specific resource.
  5. (--watch mode) Repeat the cycle forever, so the demo can show a
     previously-authorized session being cut off the moment the device's
     posture drops or the token simply ages out -- proving verification is
     continuous, not a one-time login.

Usage examples:
    python -m agent.client_agent --user alice --resource docs-app --demo
    python -m agent.client_agent --user bob --resource finance-app --demo --watch
    python -m agent.client_agent --user carol --resource finance-app --demo --simulate-compromised
"""
import argparse
import base64
import getpass
import json
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import urllib3
urllib3.disable_warnings()

from common.config import IDP_HOST, IDP_PORT, GATEWAY_HOST, GATEWAY_PORT
from common.totp import current_totp
from common.tls_utils import scheme as _tls_scheme
from common import token_binding
from agent.device_posture import compute_trust_score
from agent import device_attestation

_SCHEME = _tls_scheme()
IDP_URL = f"{_SCHEME}://{IDP_HOST}:{IDP_PORT}"
GATEWAY_URL = f"{_SCHEME}://{GATEWAY_HOST}:{GATEWAY_PORT}"


def _demo_secret_lookup(username: str) -> str:
    """Only used with --demo. In a real deployment the agent never has
    access to the TOTP seed -- the user reads the 6-digit code off their
    own authenticator app and types it in (see the `else` branch below)."""
    from idp.users_db import USERS
    return USERS[username]["totp_secret"]


def _do_attestation(device_id: str):
    """Enroll this device's attestation key (idempotent) with the IdP, then
    complete a fresh challenge-response proving possession of the private
    key. Returns the base64 signature to submit with /login, or None if
    attestation could not be completed."""
    try:
        enroll_info = device_attestation.ensure_enrolled(device_id)
        mode = enroll_info["mode"]
        print(f"[agent] device attestation key ready (mode={mode}, "
              f"hardware_backed={enroll_info['hardware_backed']})")

        enroll_resp = requests.post(f"{IDP_URL}/enroll", json={
            "device_id": device_id,
            "public_key_pem": enroll_info["public_key_pem"],
        }, verify=False, timeout=5)

        # 202 = enrolled but awaiting administrator approval. Say so plainly
        # and print the exact command needed, rather than letting the user
        # discover it later as an unexplained "attestation_required" denial.
        if enroll_resp.status_code == 202:
            info = enroll_resp.json()
            print(f"[agent] device is enrolled but NOT YET APPROVED "
                  f"(thumbprint {info.get('thumbprint', '')[:16]}...)")
            print(f"[agent] an administrator must run:")
            print(f"[agent]     python -m tools.manage_devices --approve {device_id}")
            print(f"[agent] until then this device cannot attest, and resources "
                  f"requiring attestation will deny access.")
            return None

        chal = requests.post(f"{IDP_URL}/challenge", json={"device_id": device_id},
                              verify=False, timeout=5)
        if chal.status_code != 200:
            print(f"[agent] attestation challenge failed: {chal.status_code} {chal.text} "
                  f"-- continuing without attestation")
            return None
        nonce_b64 = chal.json()["nonce"]

        signature_b64 = device_attestation.sign_nonce(
            device_id, nonce_b64, enroll_info["hardware_backed"]
        )
        return signature_b64
    except Exception as e:  # noqa: BLE001
        print(f"[agent] attestation unavailable ({e}) -- continuing without it")
        return None


def authenticate(username: str, password: str, demo: bool, simulate_compromised: bool,
                  use_attestation: bool = True):
    posture = compute_trust_score(device_id=username, simulate_compromised=simulate_compromised)
    print(f"[agent] device posture check -> score={posture['score']} checks={posture['checks']}")

    if demo:
        otp = current_totp(_demo_secret_lookup(username))
        print(f"[agent] (--demo) computed current TOTP code locally: {otp}")
    else:
        otp = input("Enter 6-digit authenticator code: ").strip()

    device_id = device_attestation.get_local_device_id()
    attestation_signature = _do_attestation(device_id) if use_attestation else None

    resp = requests.post(f"{IDP_URL}/login", json={
        "username": username,
        "password": password,
        "otp": otp,
        "device_trust_score": posture["score"],
        "device_id": device_id,
        "attestation_signature": attestation_signature,
    }, verify=False, timeout=5)

    if resp.status_code != 200:
        print(f"[agent] AUTH FAILED: {resp.status_code} {resp.json()}")
        return None
    data = resp.json()
    claims = data["claims"]
    attested = claims.get("attested", False)
    bound = bool(claims.get("cnf"))
    print(f"[agent] authenticated OK (attested={attested}, token_bound={bound}), "
          f"token expires in {data['expires_in']}s")
    if bound:
        print("[agent] token is bound to this device's key -- it cannot be used elsewhere")
    return data["access_token"]


def _build_device_proof(claims: dict, method: str, path: str):
    """Produce the X-Device-Proof headers for a bound token.

    Returns {} when the token carries no `cnf` claim, so an unenrolled or
    unapproved device keeps working exactly as before rather than being
    locked out by a feature it cannot participate in.
    """
    if not claims.get("cnf"):
        return {}
    try:
        device_id = device_attestation.get_local_device_id()
        info = device_attestation.ensure_enrolled(device_id)
        nonce = secrets.token_hex(16)
        timestamp = int(time.time())
        payload = token_binding.build_proof_payload(
            claims["jti"], method, path, timestamp, nonce
        )
        signature = device_attestation.sign_bytes(
            device_id, payload, info["hardware_backed"]
        )
        return {
            token_binding.PROOF_HEADER: base64.b64encode(signature).decode("ascii"),
            token_binding.PROOF_DATA_HEADER: base64.b64encode(payload).decode("ascii"),
        }
    except Exception as e:  # noqa: BLE001
        # Do not silently proceed unsigned -- the request will be denied at
        # the Gateway and "device_proof_missing" is a far more confusing
        # thing to debug than the actual signing error.
        print(f"[agent] WARNING: could not build device proof ({e}); "
              f"the Gateway will reject this bound token.")
        return {}


def _decode_claims_unverified(token: str) -> dict:
    """Read our own token's claims to decide whether a proof is needed.

    Unverified is fine here and only here: this is the client reading a
    token it was just handed, purely to shape its next request. Nothing is
    authorized on the basis of it -- the Gateway independently verifies the
    signature. Never use this pattern server-side.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:  # noqa: BLE001
        return {}


def request_resource(resource: str, token: str):
    path = f"/access/{resource}"
    headers = {"Authorization": f"Bearer {token}"}
    headers.update(_build_device_proof(_decode_claims_unverified(token), "GET", path))
    resp = requests.get(f"{GATEWAY_URL}{path}", headers=headers, verify=False, timeout=5)
    return resp.status_code, resp.json()


def run_once(args):
    password = args.password or getpass.getpass(f"Password for {args.user}: ")
    token = authenticate(args.user, password, args.demo, args.simulate_compromised,
                          use_attestation=not args.no_attestation)
    if token is None:
        return
    status, payload = request_resource(args.resource, token)
    verdict = "ALLOWED" if status == 200 else "DENIED"
    print(f"[agent] access to '{args.resource}': {verdict} (HTTP {status})")
    print(json.dumps(payload, indent=2))


def run_watch(args):
    password = args.password or getpass.getpass(f"Password for {args.user}: ")
    cycle = 0
    print(f"[agent] watch mode: re-authenticating every {args.interval}s. Ctrl+C to stop.")
    if args.compromise_after > 0:
        print(f"[agent] device will report itself COMPROMISED starting at cycle {args.compromise_after} "
              f"to demonstrate continuous verification revoking a previously-trusted session.")
    try:
        while True:
            cycle += 1
            compromised = args.simulate_compromised or (
                args.compromise_after > 0 and cycle >= args.compromise_after
            )
            print(f"\n--- cycle {cycle} ---")
            token = authenticate(args.user, password, args.demo, compromised,
                                  use_attestation=not args.no_attestation)
            if token is not None:
                status, payload = request_resource(args.resource, token)
                verdict = "ALLOWED" if status == 200 else "DENIED"
                print(f"[agent] access to '{args.resource}': {verdict} (HTTP {status}) -> {payload}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[agent] stopped.")


def main():
    parser = argparse.ArgumentParser(description="PyZTNA client agent")
    parser.add_argument("--user", required=True, help="username, e.g. alice/bob/carol/admin")
    parser.add_argument("--password", help="omit to be prompted securely")
    parser.add_argument("--resource", required=True, choices=["docs-app", "finance-app"])
    parser.add_argument("--demo", action="store_true",
                         help="auto-compute the TOTP code locally instead of prompting "
                              "(classroom convenience; not how a real deployment works)")
    parser.add_argument("--simulate-compromised", action="store_true",
                         help="force device posture checks to fail, to demo denial despite a valid role")
    parser.add_argument("--watch", action="store_true", help="repeat the auth+access cycle continuously")
    parser.add_argument("--interval", type=float, default=10.0, help="seconds between --watch cycles")
    parser.add_argument("--compromise-after", type=int, default=0,
                         help="in --watch mode, start reporting a compromised device at this cycle number")
    parser.add_argument("--no-attestation", action="store_true",
                         help="skip cryptographic device attestation entirely")
    args = parser.parse_args()

    if args.watch:
        run_watch(args)
    else:
        run_once(args)


if __name__ == "__main__":
    main()
