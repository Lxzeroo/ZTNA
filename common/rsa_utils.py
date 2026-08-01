"""
RSA keypair management for JWT signing (RS256).

This hardening revision replaces the original shared-secret HS256 design
(see docs/HARDENING.md) with asymmetric signing: the Identity Provider is
the only service that ever touches the PRIVATE key
(certs/jwt_keys/jwt_private.pem); the Gateway (and anything else that only
needs to verify tokens) only needs the PUBLIC key
(certs/jwt_keys/jwt_public.pem). In a real multi-host deployment, only the
public key file needs to be copied to the Gateway machine -- the private
key never has to leave the IdP host, which is a materially better story
than shipping a shared secret to every service that verifies tokens.

Uses the `cryptography` library (already a required dependency for device
attestation) rather than shelling out to openssl, so key generation works
identically on a bare Windows Python install with no external tool on PATH.
"""
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from common.config import JWT_KEY_DIR, JWT_PRIVATE_KEY_PATH, JWT_PUBLIC_KEY_PATH


def ensure_jwt_keypair() -> None:
    """Generate the RSA-2048 JWT signing keypair if it doesn't exist yet.
    Idempotent -- safe to call from every service on startup."""
    os.makedirs(JWT_KEY_DIR, exist_ok=True)
    if os.path.exists(JWT_PRIVATE_KEY_PATH) and os.path.exists(JWT_PUBLIC_KEY_PATH):
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(JWT_PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_pem)
    try:
        os.chmod(JWT_PRIVATE_KEY_PATH, 0o600)  # best-effort; Windows ACLs differ
    except Exception:
        pass

    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(JWT_PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_pem)


def load_private_key_pem() -> bytes:
    ensure_jwt_keypair()
    with open(JWT_PRIVATE_KEY_PATH, "rb") as f:
        return f.read()


def load_public_key_pem() -> bytes:
    ensure_jwt_keypair()
    with open(JWT_PUBLIC_KEY_PATH, "rb") as f:
        return f.read()
