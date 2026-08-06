"""
Device registry for cryptographic attestation and token binding.

This replaces "trust me, my score is 90" (the self-reported posture score
from agent/device_posture.py) with a challenge-response proof of possession
of a hardware-bound private key, for devices that have enrolled one.

  1. ENROLLMENT (once per device): the agent generates a key pair where the
     private key is bound to the device's TPM (Windows: Microsoft Platform
     Crypto Provider, non-exportable) and sends only the PUBLIC key here.
     We store {device_id -> public_key_pem}.

  2. APPROVAL (production-readiness revision): enrollment now lands in
     `pending`. An administrator must approve the device before it can
     produce an attested login. See "Why approval" below.

  3. CHALLENGE (each login): the IdP hands out a random, single-use, short-
     lived nonce for a device_id.

  4. PROOF (same login): the agent signs that exact nonce with the
     device's private key. The IdP verifies the signature against the
     enrolled public key and marks the login `attested=True`.

Why approval
------------
The previous revision accepted the first enrollment for any device_id
unconditionally -- trust on first use. docs/HARDENING.md named this openly
as unaddressed. TOFU means an attacker who reaches the enrollment endpoint
can register their own key under a device_id nobody has claimed yet and
thereafter produce perfectly valid attestations. The cryptography is sound
and the answer is still wrong, because the binding between "this key" and
"a device we actually trust" was never established by anyone.

Approval inserts a human (or an MDM system) at exactly that binding step.
`ZTNA_REQUIRE_DEVICE_APPROVAL=0` restores the old behaviour for the
single-machine demo, where there is nobody to do the approving -- and
common/preflight.py warns loudly when it is disabled.

Why persistent
--------------
State moved from a module-level dict to common/storage.py for two reasons:

  * a restart previously wiped every enrolled device, silently downgrading
    every subsequent login to unattested -- the same class of silent
    security degradation as the TPM export bug in docs/CHANGELOG.md;
  * the Gateway needs the device public key to verify token-binding proofs
    (common/token_binding.py), and it is a different process from the IdP.

Challenges deliberately stay in memory: they live 30 seconds, are
single-use, and losing them on restart is correct behaviour rather than a
bug.
"""
import base64
import hashlib
import os
import time
from threading import Lock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.exceptions import InvalidSignature

from common import obs
from common.config import REQUIRE_DEVICE_APPROVAL
from common.storage import get_backend

_lock = Lock()

NAMESPACE = "devices"

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REVOKED = "revoked"

# device_id -> (nonce_bytes, expires_at) -- single-use, consumed on success
# or on expiry, whichever comes first.
_CHALLENGES = {}

CHALLENGE_TTL_SECONDS = 30


def key_thumbprint(public_key_pem: str) -> str:
    """Stable SHA-256 thumbprint of a public key, over its DER SubjectPublicKeyInfo.

    Hashing the DER rather than the PEM text matters: PEM differs by line
    wrapping, trailing newlines and CRLF-vs-LF, so two byte-different PEMs
    can carry the identical key. On Windows that difference is routine.
    """
    key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def register_device(device_id: str, public_key_pem: str) -> dict:
    """Enroll (or re-enroll) a device. Returns the stored record.

    Re-enrolling an already-approved device with a DIFFERENT key forces it
    back to pending. Otherwise device rotation would be a free bypass of
    approval: enroll honestly, get approved, then swap in a key of your
    choosing.
    """
    thumbprint = key_thumbprint(public_key_pem)
    store = get_backend()

    with _lock:
        existing = store.get(NAMESPACE, device_id)
        now = time.time()

        if existing and existing.get("thumbprint") == thumbprint:
            existing["last_enrolled_at"] = now
            store.set(NAMESPACE, device_id, existing)
            return existing

        status = STATUS_PENDING
        if not REQUIRE_DEVICE_APPROVAL:
            status = STATUS_APPROVED

        record = {
            "device_id": device_id,
            "public_key_pem": public_key_pem,
            "thumbprint": thumbprint,
            "status": status,
            "enrolled_at": now,
            "last_enrolled_at": now,
            "approved_at": now if status == STATUS_APPROVED else None,
            "approved_by": "auto (approval disabled)" if status == STATUS_APPROVED else None,
            "previous_thumbprint": existing.get("thumbprint") if existing else None,
        }
        store.set(NAMESPACE, device_id, record)

        if existing:
            obs.warning("idp", "device_key_changed", device_id=device_id,
                        old_thumbprint=(existing.get("thumbprint") or "")[:16],
                        new_thumbprint=thumbprint[:16], status=status,
                        detail="device re-enrolled with a different key; approval reset")
        else:
            obs.info("idp", "device_enrolled", device_id=device_id,
                     thumbprint=thumbprint[:16], status=status)
        return record


def get_device(device_id: str):
    return get_backend().get(NAMESPACE, device_id)


def list_devices() -> dict:
    return get_backend().all(NAMESPACE)


def is_enrolled(device_id: str) -> bool:
    return get_device(device_id) is not None


def is_approved(device_id: str) -> bool:
    record = get_device(device_id)
    return bool(record) and record.get("status") == STATUS_APPROVED


def approve_device(device_id: str, approved_by: str = "admin") -> bool:
    store = get_backend()
    with _lock:
        record = store.get(NAMESPACE, device_id)
        if not record:
            return False
        record["status"] = STATUS_APPROVED
        record["approved_at"] = time.time()
        record["approved_by"] = approved_by
        store.set(NAMESPACE, device_id, record)
    obs.info("idp", "device_approved", device_id=device_id, approved_by=approved_by)
    return True


def revoke_device(device_id: str, revoked_by: str = "admin", reason: str = "") -> bool:
    """Revoke a device.

    Note this does not kill sessions already issued to it -- that is
    common/revocation.py's job. tools/manage_devices.py --revoke does both,
    because revoking a device while leaving its live tokens usable is a
    trap worth closing at the tool level rather than expecting an operator
    to remember under pressure.
    """
    store = get_backend()
    with _lock:
        record = store.get(NAMESPACE, device_id)
        if not record:
            return False
        record["status"] = STATUS_REVOKED
        record["revoked_at"] = time.time()
        record["revoked_by"] = revoked_by
        record["revoked_reason"] = reason
        store.set(NAMESPACE, device_id, record)
    obs.warning("idp", "device_revoked", device_id=device_id,
                revoked_by=revoked_by, reason=reason)
    return True


def issue_challenge(device_id: str) -> str:
    nonce = os.urandom(32)
    with _lock:
        _CHALLENGES[device_id] = (nonce, time.time() + CHALLENGE_TTL_SECONDS)
    return base64.b64encode(nonce).decode("ascii")


def _load_public_key(pem: str):
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def verify_signature(public_key_pem: str, signature: bytes, message: bytes) -> bool:
    """Verify `signature` over `message`. Shared with common/token_binding.py
    so enrollment proofs and per-request proofs cannot drift apart."""
    try:
        public_key = _load_public_key(public_key_pem)
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify_and_consume(device_id: str, signature_b64: str) -> bool:
    """Verify an attestation signature over this device's outstanding nonce.

    Returns False for every failure mode, but logs WHICH one -- an operator
    debugging "why is my device not attested" otherwise cannot distinguish
    an expired challenge from a device awaiting approval, and those have
    completely different remedies.
    """
    with _lock:
        challenge = _CHALLENGES.pop(device_id, None)

    if challenge is None:
        obs.info("idp", "attestation_failed", device_id=device_id,
                 reason="no_outstanding_challenge")
        return False

    nonce, expires_at = challenge
    if time.time() > expires_at:
        obs.info("idp", "attestation_failed", device_id=device_id,
                 reason="challenge_expired")
        return False

    record = get_device(device_id)
    if record is None:
        obs.info("idp", "attestation_failed", device_id=device_id,
                 reason="device_not_enrolled")
        return False

    status = record.get("status")
    if status != STATUS_APPROVED:
        # Deliberately loud: a pending device attempting attestation is
        # either a legitimate user waiting on an admin, or someone probing
        # an enrollment they should not have. Both are worth seeing.
        obs.warning("idp", "attestation_denied_unapproved", device_id=device_id,
                    status=status,
                    detail="device has not been approved by an administrator")
        return False

    try:
        signature = base64.b64decode(signature_b64)
    except (ValueError, TypeError):
        obs.info("idp", "attestation_failed", device_id=device_id,
                 reason="signature_not_base64")
        return False

    if not verify_signature(record["public_key_pem"], signature, nonce):
        obs.warning("idp", "attestation_failed", device_id=device_id,
                    reason="signature_invalid")
        return False

    return True


def reset_for_tests() -> None:
    """Clear registry and challenges. Test-only."""
    with _lock:
        _CHALLENGES.clear()
    get_backend().replace_namespace(NAMESPACE, {})
