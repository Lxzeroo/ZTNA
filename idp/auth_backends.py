"""
Pluggable identity backend for the Identity Provider (this hardening
revision -- see docs/HARDENING.md). The original design had exactly one
hardcoded identity source (idp/users_db.py, an in-memory dict) --
documented as a gap versus a real deployment, which would federate to
Active Directory / Entra ID / an LDAP directory rather than maintaining a
separate local user list.

Two backends, selected via common.config.AUTH_BACKEND ("local" | "ldap"):

  - LocalAuthBackend: wraps the existing idp/users_db.py exactly as
    before. This is the DEFAULT and is what the automated test suite and
    the README's --demo commands use -- no behavior change for the
    existing demo scenarios.

  - LDAPAuthBackend: binds to a real LDAP/Active Directory server to
    verify the password and derive a role from group membership, using
    the optional `ldap3` package (NOT a required dependency -- see
    requirements.txt). HONEST SCOPE: this has been written against the
    documented ldap3 simple-bind API and reviewed carefully, but has NOT
    been executed against a real directory server (no LDAP server was
    available in this development sandbox) -- the same caveat this
    project already applies to the Windows/TPM attestation path in
    docs/DEVICE_ATTESTATION.md. Verify against a real directory before
    citing this as a working result; see docs/HARDENING.md.

Both backends implement the same two-function interface the IdP actually
calls, so idp/idp_server.py doesn't need to know which one is active:
    verify_password(username, password) -> bool
    get_user(username) -> dict | None   # must include "role"; MFA still
                                          # uses a local TOTP secret store
                                          # even when identity is
                                          # federated (see LDAPAuthBackend
                                          # docstring for why).
"""
from common.config import (
    AUTH_BACKEND, LDAP_SERVER, LDAP_USER_DN_TEMPLATE, LDAP_ROLE_ATTRIBUTE,
    LDAP_GROUP_ROLE_MAP,
)


class LocalAuthBackend:
    """Wraps idp/users_db.py unchanged -- the original design's behavior."""

    def verify_password(self, username: str, password: str) -> bool:
        from idp.users_db import verify_password
        return verify_password(username, password)

    def get_user(self, username: str) -> dict:
        from idp.users_db import get_user
        return get_user(username)


class LDAPAuthBackend:
    """Binds to a real LDAP/Active Directory server instead of the local
    users_db.py dict.

    MFA note: TOTP secrets are deliberately NOT sourced from LDAP (most
    directories don't store them, and shoving a TOTP seed into a directory
    attribute is a poor practice most orgs avoid) -- this backend still
    looks up the per-user TOTP secret from idp/users_db.py's
    `_TOTP_SECRETS`-style local map, which in a real deployment would be
    swapped for a dedicated MFA provider (Duo, Okta Verify, Entra
    Conditional Access, etc.) rather than reinvented here. This mirrors
    how real organizations commonly split "who are you" (directory) from
    "prove it's really you right now" (separate MFA system).
    """

    def __init__(self):
        try:
            import ldap3  # noqa: F401
        except ImportError as e:
            raise RuntimeError(
                "ZTNA_AUTH_BACKEND=ldap requires the optional 'ldap3' package "
                "(pip install ldap3). See docs/HARDENING.md for scope/status "
                "of this backend."
            ) from e
        self._ldap3 = ldap3

    def verify_password(self, username: str, password: str) -> bool:
        ldap3 = self._ldap3
        user_dn = LDAP_USER_DN_TEMPLATE.format(username=username)
        try:
            server = ldap3.Server(LDAP_SERVER, use_ssl=True)
            conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
            conn.unbind()
            return True
        except ldap3.core.exceptions.LDAPBindError:
            return False
        except Exception:
            # Connection/config errors fail CLOSED (deny), not open --
            # consistent with the project's fail-closed philosophy
            # elsewhere (agent/device_posture.py).
            return False

    def get_user(self, username: str) -> dict:
        ldap3 = self._ldap3
        user_dn = LDAP_USER_DN_TEMPLATE.format(username=username)
        try:
            server = ldap3.Server(LDAP_SERVER, use_ssl=True)
            # Anonymous/service-account bind to READ attributes; a real
            # deployment should use a dedicated read-only service account
            # here rather than an anonymous bind.
            conn = ldap3.Connection(server, auto_bind=True)
            conn.search(user_dn, "(objectClass=*)", attributes=[LDAP_ROLE_ATTRIBUTE])
            if not conn.entries:
                return None
            entry = conn.entries[0]
            groups = list(entry[LDAP_ROLE_ATTRIBUTE]) if LDAP_ROLE_ATTRIBUTE in entry else []
            role = "intern"  # least-privilege default if no mapped group is found
            for group_dn in groups:
                if str(group_dn) in LDAP_GROUP_ROLE_MAP:
                    role = LDAP_GROUP_ROLE_MAP[str(group_dn)]
                    break

            from idp.users_db import USERS as _LOCAL_TOTP_STORE
            local_entry = _LOCAL_TOTP_STORE.get(username, {})
            totp_secret = local_entry.get("totp_secret")
            if not totp_secret:
                return None  # no MFA secret provisioned -- fail closed

            return {
                "role": role,
                "totp_secret": totp_secret,
                "device_id": f"LDAP-{username}",
            }
        except Exception:
            return None


_BACKENDS = {
    "local": LocalAuthBackend,
    "ldap": LDAPAuthBackend,
}

_instance = None


def get_backend():
    """Return the configured auth backend (singleton). Selection is via
    common.config.AUTH_BACKEND, set from the ZTNA_AUTH_BACKEND env var."""
    global _instance
    if _instance is None:
        backend_cls = _BACKENDS.get(AUTH_BACKEND, LocalAuthBackend)
        _instance = backend_cls()
    return _instance
