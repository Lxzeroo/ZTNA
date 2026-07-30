"""
Thin wrapper around PyJWT for issuing and verifying the short-lived access
tokens used throughout the ZTNA demo.

Every token embeds the signals the Policy Decision Point needs to make a
per-request decision: identity (sub), role, device_id, and the device's
current trust score. Because TTL is short (see common.config.TOKEN_TTL_SECONDS)
a stale or since-compromised device cannot keep using an old token --
it must go back through the Identity Provider, resubmit a fresh posture
check, and get re-evaluated. That re-evaluation loop is what makes this
"continuous verification" instead of "log in once, trust forever".
"""
import time
import jwt

from common.config import JWT_SECRET, JWT_ALGORITHM, TOKEN_TTL_SECONDS


def issue_token(username: str, role: str, device_id: str, device_trust_score: int) -> dict:
    now = int(time.time())
    claims = {
        "sub": username,
        "role": role,
        "device_id": device_id,
        "device_trust_score": device_trust_score,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    token = jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)
    if isinstance(token, bytes):  # PyJWT <2.0 compatibility
        token = token.decode("utf-8")
    return {"access_token": token, "token_type": "Bearer", "expires_in": TOKEN_TTL_SECONDS, "claims": claims}


class TokenError(Exception):
    pass


def verify_token(token: str) -> dict:
    """Raise TokenError with a human-readable reason on any failure."""
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return claims
    except jwt.ExpiredSignatureError:
        raise TokenError("token_expired")
    except jwt.InvalidSignatureError:
        raise TokenError("token_signature_invalid")
    except jwt.DecodeError:
        raise TokenError("token_malformed")
    except Exception as e:  # noqa: BLE001 - surfaced to caller as a denial reason
        raise TokenError(f"token_invalid:{e}")
