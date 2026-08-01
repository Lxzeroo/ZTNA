"""
A from-scratch RFC 6238 (TOTP) implementation using only the Python
standard library (hmac, hashlib, base64, struct, time).

Written by hand instead of pulling in `pyotp` so the project demonstrates
understanding of the MFA mechanism itself, not just a library call. It is
interoperable with real authenticator apps (Google Authenticator, Authy,
Microsoft Authenticator).
"""
import base64
import hashlib
import hmac
import struct
import time
import os


def generate_secret() -> str:
    """Return a random base32 secret suitable for an authenticator app."""
    raw = os.urandom(20)
    return base64.b32encode(raw).decode("utf-8")


def _hotp(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def current_totp(secret: str, step: int = 30, digits: int = 6, at_time: float = None) -> str:
    t = at_time if at_time is not None else time.time()
    counter = int(t // step)
    return _hotp(secret, counter, digits)


def verify_totp(secret: str, code: str, step: int = 30, digits: int = 6, window: int = 1) -> bool:
    """Accept the current code plus +/- `window` steps to tolerate clock drift."""
    now = time.time()
    for w in range(-window, window + 1):
        if _hotp(secret, int(now // step) + w, digits) == str(code).zfill(digits):
            return True
    return False


def provisioning_uri(secret: str, username: str, issuer: str = "PyZTNA") -> str:
    return (
        f"otpauth://totp/{issuer}:{username}?secret={secret}"
        f"&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )


if __name__ == "__main__":
    s = generate_secret()
    print("Secret:", s)
    print("URI:", provisioning_uri(s, "demo-user"))
    print("Current code:", current_totp(s))
