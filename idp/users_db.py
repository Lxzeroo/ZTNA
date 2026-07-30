"""
Seed user directory for the demo Identity Provider.

In a real deployment this would be Active Directory / Entra ID / a proper
user store. For the classroom demo it's an in-memory dict with bcrypt
password hashes and a per-user TOTP secret (second factor), which is enough
to demonstrate real MFA (not a fake checkbox) end to end.

Demo credentials (also documented in README.md):
    alice / Intern#2026     (role: intern)
    bob   / Manager#2026    (role: finance_manager)
    carol / Manager#2026    (role: finance_manager)   -- used to demo a
                                                          "compromised device"
                                                          being denied despite
                                                          having the right role
    admin / Admin#2026      (role: admin)
"""
import bcrypt

from common.totp import generate_secret

# Fixed secrets (normally random per user / provisioned via QR code) so the
# demo and automated tests are reproducible.
_TOTP_SECRETS = {
    "alice": "JBSWY3DPEHPK3PXPJBSWY3DP",
    "bob":   "KRSXG5CTMVRXEZLUEB2GK43F",
    "carol": "MFRGGZDFMZTWQ2LKNNWG23TP",
    "admin": "GEZDGNBVGY3TQOJQGEZDGNBV",
}


def _hash(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt())


USERS = {
    "alice": {
        "password_hash": _hash("Intern#2026"),
        "role": "intern",
        "totp_secret": _TOTP_SECRETS["alice"],
        "device_id": "WIN-LAPTOP-ALICE",
    },
    "bob": {
        "password_hash": _hash("Manager#2026"),
        "role": "finance_manager",
        "totp_secret": _TOTP_SECRETS["bob"],
        "device_id": "WIN-LAPTOP-BOB",
    },
    "carol": {
        "password_hash": _hash("Manager#2026"),
        "role": "finance_manager",
        "totp_secret": _TOTP_SECRETS["carol"],
        "device_id": "WIN-LAPTOP-CAROL",
    },
    "admin": {
        "password_hash": _hash("Admin#2026"),
        "role": "admin",
        "totp_secret": _TOTP_SECRETS["admin"],
        "device_id": "WIN-LAPTOP-ADMIN",
    },
}


def verify_password(username: str, password: str) -> bool:
    user = USERS.get(username)
    if not user:
        return False
    return bcrypt.checkpw(password.encode("utf-8"), user["password_hash"])


def get_user(username: str) -> dict:
    return USERS.get(username)
