"""
Thin wrapper around PyJWT for issuing and verifying the short-lived access
tokens used throughout the ZTNA demo.

Hardening revision (see docs/HARDENING.md): switched from HS256 (a single
secret shared between every service that issues OR verifies a token) to
RS256 (asymmetric) -- the Identity Provider holds the private key and is
the only service that can mint a valid token; the Gateway (and anything
else) only needs the public key to verify one. Compromising the Gateway
host no longer lets an attacker forge tokens, which was a named limitation
of the original design.

Every token also now carries a `jti` (JWT ID, a random unique value) so a
SPECIFIC token can be explicitly revoked (common/revocation.py) instead of
relying solely on the short TTL to bound a compromised session's lifetime.
"""
import time
import uuid
import jwt

from common.config import JWT_ALGORITHM, TOKEN_TTL_SECONDS
from common.rsa_utils import load_private_key_pem, load_public_key_pem
from common import token_store


def issue_token(username: str, role: str, device_id: str, device_trust_score: int,
                 attested: bool = False) -> dict:
    now = int(time.time())
    jti = uuid.uuid4().hex
    exp = now + TOKEN_TTL_SECONDS
    claims = {
        "sub": username,
        "role": role,
        "device_id": device_id,
        "device_trust_score": device_trust_score,
        "attested": bool(attested),
        "iat": now,
        "exp": exp,
        "jti": jti,
    }
    token = jwt.encode(claims, load_private_key_pem(), algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):  # PyJWT <2.0 compatibility
        token = token.decode("utf-8")

    token_store.record_issued(jti, username, exp)

    return {"access_token": token, "token_type": "Bearer", "expires_in": TOKEN_TTL_SECONDS, "claims": claims}


class TokenError(Exception):
    pass


def verify_token(token: str) -> dict:
    """Raise TokenError with a human-readable reason on any failure. Only
    checks signature/expiry here -- revocation is a separate, explicit
    check the Gateway performs (common/revocation.py:is_revoked), since
    "signature valid" and "not revoked" are different questions with
    different failure-reporting needs for the audit log."""
    try:
        claims = jwt.decode(token, load_public_key_pem(), algorithms=[JWT_ALGORITHM])
        return claims
    except jwt.ExpiredSignatureError:
        raise TokenError("token_expired")
    except jwt.InvalidSignatureError:
        raise TokenError("token_signature_invalid")
    except jwt.DecodeError:
        raise TokenError("token_malformed")
    except Exception as e:  # noqa: BLE001 - surfaced to caller as a denial reason
        raise TokenError(f"token_invalid:{e}")
