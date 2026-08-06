"""
Token binding -- proof of possession, so a stolen token is useless off-device.

The problem
-----------
Until now a PyZTNA access token was a bearer token in the literal sense:
whoever bears it, wins. Every other control in the system assumes the token
reached the Gateway from the machine it was issued to, and nothing checks
that. Copy the string out of a log, a crash dump, a proxy, or the client's
memory, and it works from anywhere in the world until it expires.

The 45-second TTL bounds that window but does not close it, and the window
is exactly long enough for an automated exfiltration path to use.

The mechanism
-------------
On login, if the device is enrolled and approved, the IdP embeds a `cnf`
(confirmation) claim in the token -- RFC 7800's mechanism for saying "this
token may only be used by whoever holds the key with this thumbprint":

    "cnf": {"jkt": "<sha256 of the device public key DER>"}

The Gateway then requires, on every request, a proof header signed by that
device's private key -- the DPoP pattern (RFC 9449) applied to our own
transport:

    X-Device-Proof: <base64 signature>
    X-Device-Proof-Data: <base64 of "<jti>|<method>|<path>|<unix_ts>|<nonce>">

The signed string binds the proof to:

  * `jti`    -- this specific token, so a proof captured alongside token A
                cannot be replayed to authorize token B;
  * method+path -- this specific operation, so a proof for GET /access/docs-app
                cannot be replayed against /access/finance-app;
  * timestamp -- a 30s freshness window (ZTNA_PROOF_MAX_AGE_SECONDS);
  * nonce    -- a client-chosen random value, remembered by the Gateway for
                the length of that window, so a proof cannot be replayed
                even *within* it.

The private key never leaves the device, and on Windows with a TPM it
cannot leave (non-exportable, Microsoft Platform Crypto Provider -- see
agent/device_attestation.py). So an attacker who steals the token string
still cannot produce a proof.

Honest scope
------------
  * This binds the token to the DEVICE, not to the TLS channel. A true
    channel binding (RFC 8471) would also defeat an attacker who has fully
    compromised the device and can ask the TPM to sign whatever they want.
    Against a fully-compromised endpoint no software control on that
    endpoint helps; that is why device trust needs external attestation,
    which is a separate axis (docs/DEVICE_ATTESTATION.md).
  * The replay cache is per-Gateway-process and in memory. With two Gateway
    instances, a proof could be replayed once against each. Fixing that
    needs the shared state backend (common/storage.py) -- noted rather than
    hidden.
  * Tokens issued to devices with no enrolled key carry no `cnf` claim and
    are accepted without a proof, otherwise enabling this would break every
    unenrolled client at once. A resource that needs the stronger guarantee
    sets `require_attestation` in policy, which already forces enrollment.
"""
import base64
import threading
import time

from common import obs
from common.config import PROOF_MAX_AGE_SECONDS, TOKEN_BINDING_ENABLED

PROOF_HEADER = "X-Device-Proof"
PROOF_DATA_HEADER = "X-Device-Proof-Data"

_lock = threading.Lock()
# nonce -> expires_at. Bounded by the freshness window: an entry is only
# useful for as long as a proof carrying it could still be accepted.
_seen_nonces = {}


class ProofError(Exception):
    """Raised with a short machine-readable reason, used as a denial reason."""


def build_proof_payload(jti: str, method: str, path: str, timestamp: int, nonce: str) -> bytes:
    """The exact byte string both sides sign/verify.

    Single definition, imported by the agent and the Gateway, so the two can
    never disagree about field order or separator -- a mismatch there fails
    as "invalid signature", which is a genuinely miserable thing to debug.
    """
    return f"{jti}|{method}|{path}|{timestamp}|{nonce}".encode("utf-8")


def _prune_nonces(now: float) -> None:
    stale = [n for n, exp in _seen_nonces.items() if exp < now]
    for n in stale:
        _seen_nonces.pop(n, None)


def _remember_nonce(nonce: str, now: float) -> bool:
    """Returns True if this nonce is fresh, False if already used."""
    with _lock:
        _prune_nonces(now)
        if nonce in _seen_nonces:
            return False
        _seen_nonces[nonce] = now + PROOF_MAX_AGE_SECONDS + 5
        return True


def token_requires_proof(claims: dict) -> bool:
    """True when the token carries a cnf claim and binding is enabled."""
    if not TOKEN_BINDING_ENABLED:
        return False
    cnf = claims.get("cnf")
    return isinstance(cnf, dict) and bool(cnf.get("jkt"))


def verify_proof(claims: dict, method: str, path: str,
                 proof_b64: str, proof_data_b64: str) -> None:
    """Verify a device proof for this token and request. Raises ProofError.

    The device's public key is looked up from the shared device registry by
    the token's device_id, then cross-checked against the thumbprint pinned
    in the token's `cnf` claim. Checking both matters: without the
    thumbprint check, an attacker who can re-enroll a new key for that
    device_id could mint proofs for tokens issued to the OLD key.
    """
    from idp.device_registry import get_device, verify_signature, key_thumbprint

    expected_jkt = (claims.get("cnf") or {}).get("jkt")
    if not expected_jkt:
        raise ProofError("token_not_bound")

    if not proof_b64 or not proof_data_b64:
        raise ProofError("device_proof_missing")

    try:
        proof_data = base64.b64decode(proof_data_b64).decode("utf-8")
        signature = base64.b64decode(proof_b64)
    except (ValueError, TypeError, UnicodeDecodeError):
        raise ProofError("device_proof_malformed")

    parts = proof_data.split("|")
    if len(parts) != 5:
        raise ProofError("device_proof_malformed")
    proof_jti, proof_method, proof_path, proof_ts_raw, nonce = parts

    if proof_jti != claims.get("jti"):
        raise ProofError("device_proof_wrong_token")
    if proof_method != method or proof_path != path:
        raise ProofError("device_proof_wrong_request")

    try:
        proof_ts = int(proof_ts_raw)
    except ValueError:
        raise ProofError("device_proof_malformed")

    now = time.time()
    age = now - proof_ts
    # Reject future-dated proofs too: a client with a fast clock would
    # otherwise get an arbitrarily long replay window.
    if age > PROOF_MAX_AGE_SECONDS or age < -PROOF_MAX_AGE_SECONDS:
        raise ProofError("device_proof_stale")

    if not nonce or len(nonce) < 8:
        raise ProofError("device_proof_nonce_weak")
    if not _remember_nonce(nonce, now):
        obs.warning("gateway", "device_proof_replay_blocked",
                    device_id=claims.get("device_id"), jti=claims.get("jti"),
                    detail="a proof with this nonce was already accepted")
        raise ProofError("device_proof_replayed")

    device_id = claims.get("device_id")
    record = get_device(device_id) if device_id else None
    if not record:
        raise ProofError("device_proof_unknown_device")

    if record.get("status") != "approved":
        raise ProofError("device_proof_device_not_approved")

    actual_jkt = record.get("thumbprint") or key_thumbprint(record["public_key_pem"])
    if actual_jkt != expected_jkt:
        obs.warning("gateway", "device_proof_key_mismatch", device_id=device_id,
                    detail="registered device key does not match the key this token was bound to")
        raise ProofError("device_proof_key_mismatch")

    payload = build_proof_payload(proof_jti, proof_method, proof_path, proof_ts, nonce)
    if not verify_signature(record["public_key_pem"], signature, payload):
        raise ProofError("device_proof_signature_invalid")


def reset_for_tests() -> None:
    with _lock:
        _seen_nonces.clear()
