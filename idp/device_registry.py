"""
Device registry for cryptographic attestation.

This replaces "trust me, my score is 90" (the self-reported posture score
from agent/device_posture.py) with a challenge-response proof of possession
of a hardware-bound private key, for devices that have enrolled one.

Design (deliberately close to how TPM-backed attestation / WebAuthn /
FIDO2 work, adapted to a classroom-scale system with no external CA):

  1. ENROLLMENT (once per device): the agent generates a key pair where the
     private key is bound to the device's TPM (Windows: Microsoft Platform
     Crypto Provider, non-exportable) and sends only the PUBLIC key here.
     We store {device_id -> public_key_pem}. This is a trust-on-first-use
     (TOFU) model -- exactly like how SSH host keys or WebAuthn credentials
     are first registered. A production system would additionally verify
     an attestation certificate chain proving the key really lives in a
     genuine TPM (this is noted as future work in
     docs/DEVICE_ATTESTATION.md).

  2. CHALLENGE (each login): the IdP hands out a random, single-use, short-
     lived nonce for a device_id.

  3. PROOF (same login): the agent signs that exact nonce with the
     device's private key (an operation that must go through the TPM/local
     key store -- a compromised agent script cannot forge this without
     also compromising the hardware key). The IdP verifies the signature
     against the enrolled public key and marks the login `attested=True`.

Why this matters over the plain posture score: `agent/device_posture.py`
reports a score the agent computes and simply *tells* the server -- nothing
stops a modified agent from lying about it. A signature verified against a
key that was never transmitted and (on real hardware) never leaves a TPM is
a materially stronger guarantee: forging it requires compromising the key
material itself, not just editing a Python script.
"""
import base64
import os
import time
from threading import Lock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.exceptions import InvalidSignature

# RSA PKCS#1 v1.5 (not PSS) is used deliberately: it is fully deterministic
# (no salt-length negotiation), and its signing API
# (RSA.SignData(..., RSASignaturePadding.Pkcs1)) is identical across .NET
# Framework and .NET Core, which matters because the Windows agent signs
# via PowerShell/.NET while this verifier runs in Python -- PSS's salt
# length handling has historically caused cross-implementation mismatches
# that are hard to debug without a shared test environment.

_lock = Lock()

# device_id -> {"public_key_pem": str, "enrolled_at": float, "key_type": str}
_DEVICES = {}

# device_id -> (nonce_bytes, expires_at) -- single-use, consumed on success
# or on expiry, whichever comes first.
_CHALLENGES = {}

CHALLENGE_TTL_SECONDS = 30


def register_device(device_id: str, public_key_pem: str) -> None:
    """Enroll (or re-enroll) a device's public key. Idempotent by design --
    re-running enrollment with the SAME key is a no-op; enrolling a
    *different* key for an already-known device_id overwrites the old one,
    which mirrors how you'd re-provision a lost/replaced device in
    practice. (A production system would gate re-enrollment behind an
    admin approval step -- see docs/DEVICE_ATTESTATION.md limitations.)
    """
    with _lock:
        _DEVICES[device_id] = {
            "public_key_pem": public_key_pem,
            "enrolled_at": time.time(),
        }


def is_enrolled(device_id: str) -> bool:
    return device_id in _DEVICES


def issue_challenge(device_id: str) -> str:
    """Return a base64-encoded random nonce the caller must sign and submit
    with their next /login call within CHALLENGE_TTL_SECONDS."""
    nonce = os.urandom(32)
    with _lock:
        _CHALLENGES[device_id] = (nonce, time.time() + CHALLENGE_TTL_SECONDS)
    return base64.b64encode(nonce).decode("ascii")


def _load_public_key(pem: str):
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def verify_and_consume(device_id: str, signature_b64: str) -> bool:
    """Verify `signature_b64` is a valid signature over the outstanding
    challenge nonce for `device_id`, using that device's enrolled public
    key. The nonce is consumed (deleted) whether verification succeeds or
    fails, so a signature can never be replayed -- each challenge is
    single-use."""
    with _lock:
        challenge = _CHALLENGES.pop(device_id, None)

    if challenge is None:
        return False  # no outstanding challenge for this device (or already used)

    nonce, expires_at = challenge
    if time.time() > expires_at:
        return False  # expired -- caller must fetch a fresh challenge

    device = _DEVICES.get(device_id)
    if device is None:
        return False  # device never enrolled

    try:
        signature = base64.b64decode(signature_b64)
        public_key = _load_public_key(device["public_key_pem"])

        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, nonce, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
        else:
            return False  # unsupported key type

        return True
    except (InvalidSignature, ValueError, Exception):
        return False
