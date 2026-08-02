"""
Central configuration for the PyZTNA project.

Everything that would normally live in environment variables / a secrets
manager is centralised here for a classroom-scale demo. In a production
deployment, keys/secrets must come from a secrets store and never be
committed -- see docs/HARDENING.md for what changed here versus the
original design (shared HS256 secret -> RS256 keypair, single self-signed
cert -> internal CA + mTLS, etc.).
"""
import os

# --- Network ---
#
# Two distinct concepts, which only diverge once services are on separate
# machines (see docs/MULTI_HOST_LAB.md):
#
#   *_HOST       the address OTHER components dial to reach this service.
#                On a multi-host deployment this is the machine's real LAN
#                address, because that is what a remote caller must connect to.
#   *_BIND_HOST  the local interface the service listens on. Usually
#                "0.0.0.0" on a multi-host deployment so the service accepts
#                connections from other machines at all; defaults to the dial
#                address so the single-host demo is unchanged.
#
# Everything below defaults to loopback, so a fresh clone still runs entirely
# on one machine with no configuration.
IDP_HOST = os.environ.get("ZTNA_IDP_HOST", "127.0.0.1")
IDP_PORT = int(os.environ.get("ZTNA_IDP_PORT", "9000"))
IDP_BIND_HOST = os.environ.get("ZTNA_IDP_BIND_HOST", IDP_HOST)

GATEWAY_HOST = os.environ.get("ZTNA_GATEWAY_HOST", "127.0.0.1")
GATEWAY_PORT = int(os.environ.get("ZTNA_GATEWAY_PORT", "9200"))
GATEWAY_BIND_HOST = os.environ.get("ZTNA_GATEWAY_BIND_HOST", GATEWAY_HOST)

DOCS_APP_HOST = os.environ.get("ZTNA_DOCS_APP_HOST", "127.0.0.1")
DOCS_APP_PORT = int(os.environ.get("ZTNA_DOCS_APP_PORT", "9101"))
DOCS_APP_BIND_HOST = os.environ.get("ZTNA_DOCS_APP_BIND_HOST", DOCS_APP_HOST)

FINANCE_APP_HOST = os.environ.get("ZTNA_FINANCE_APP_HOST", "127.0.0.1")
FINANCE_APP_PORT = int(os.environ.get("ZTNA_FINANCE_APP_PORT", "9102"))
FINANCE_APP_BIND_HOST = os.environ.get("ZTNA_FINANCE_APP_BIND_HOST", FINANCE_APP_HOST)

# Additional SubjectAltName entries to place on issued certificates, as a
# comma-separated list of hostnames and/or IP addresses. Required in a
# multi-host deployment: a certificate that only carries "localhost" and
# 127.0.0.1 will fail hostname verification when a remote caller dials the
# machine's real address. tools/provision_certs.py sets this for you.
CERT_EXTRA_SANS = [
    x.strip() for x in os.environ.get("ZTNA_CERT_SANS", "").split(",") if x.strip()
]

# Protected resources bind ONLY to loopback by default. In a multi-machine
# deployment, set the *_HOST / *_BIND_HOST variables above and add the
# firewall rules in docs/MULTI_HOST_LAB.md -- but network-level isolation is
# defense-in-depth, not the only control: docs-app/finance-app also require a
# TLS client certificate issued by the internal CA (mTLS), so a host that gets
# past the firewall still cannot complete a handshake without the Gateway's
# client cert. See docs/HARDENING.md.
RESOURCES = {
    "docs-app": {
        "host": DOCS_APP_HOST,
        "bind_host": DOCS_APP_BIND_HOST,
        "port": DOCS_APP_PORT,
        "sensitivity": "low",
        "min_role_level": 1,
        "min_device_trust": 50,
        "require_attestation": False,
        "require_mtls": True,
    },
    "finance-app": {
        "host": FINANCE_APP_HOST,
        "bind_host": FINANCE_APP_BIND_HOST,
        "port": FINANCE_APP_PORT,
        "sensitivity": "high",
        "min_role_level": 3,
        "min_device_trust": 80,
        "require_attestation": True,
        "require_mtls": True,
    },
}

# --- Identity ---
ROLE_LEVELS = {
    "intern": 1,
    "employee": 2,
    "finance_manager": 3,
    "admin": 4,
}

# Which IdP auth backend to use -- "local" (idp/users_db.py, default) or
# "ldap" (idp/auth_backends.py:LDAPAuthBackend -- scaffolded, requires the
# optional ldap3 package, and has NOT been exercised against a real
# directory server; see docs/HARDENING.md for honest scope).
AUTH_BACKEND = os.environ.get("ZTNA_AUTH_BACKEND", "local")

LDAP_SERVER = os.environ.get("ZTNA_LDAP_SERVER", "ldaps://dc.example.local")
LDAP_BASE_DN = os.environ.get("ZTNA_LDAP_BASE_DN", "dc=example,dc=local")
LDAP_USER_DN_TEMPLATE = os.environ.get(
    "ZTNA_LDAP_USER_DN_TEMPLATE", "cn={username},ou=Users,dc=example,dc=local"
)
LDAP_ROLE_ATTRIBUTE = os.environ.get("ZTNA_LDAP_ROLE_ATTRIBUTE", "memberOf")
# Map an LDAP group DN (or attribute value) to a PyZTNA role name. Adjust
# to match your directory's actual group structure before use.
LDAP_GROUP_ROLE_MAP = {
    "CN=ZTNA-Interns,OU=Groups,DC=example,DC=local": "intern",
    "CN=ZTNA-Employees,OU=Groups,DC=example,DC=local": "employee",
    "CN=ZTNA-FinanceManagers,OU=Groups,DC=example,DC=local": "finance_manager",
    "CN=ZTNA-Admins,OU=Groups,DC=example,DC=local": "admin",
}

# --- Tokens ---
# Deliberately short so the demo visibly shows continuous re-verification
# instead of "authenticate once, trust forever".
JWT_ALGORITHM = "RS256"
TOKEN_TTL_SECONDS = int(os.environ.get("ZTNA_TOKEN_TTL_SECONDS", "45"))

# --- Login rate limiting (this hardening revision) ---
LOGIN_MAX_ATTEMPTS = int(os.environ.get("ZTNA_LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SECONDS = int(os.environ.get("ZTNA_LOGIN_WINDOW_SECONDS", "300"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("ZTNA_LOGIN_LOCKOUT_SECONDS", "300"))

# --- mTLS between Gateway and protected resources (this hardening revision) ---
MTLS_ENABLED = os.environ.get("ZTNA_MTLS_ENABLED", "1") not in ("0", "false", "False")
GATEWAY_CLIENT_CERT_CN = "ztna-gateway-client"

# --- Paths ---
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
ACCESS_LOG_PATH = os.path.join(LOG_DIR, "access_log.jsonl")
CERT_DIR = os.path.join(PROJECT_ROOT, "certs")

CA_DIR = os.path.join(CERT_DIR, "ca")
CA_KEY_PATH = os.path.join(CA_DIR, "ca_key.pem")
CA_CERT_PATH = os.path.join(CA_DIR, "ca_cert.pem")
SERVICE_CERT_DIR = os.path.join(CERT_DIR, "services")

JWT_KEY_DIR = os.path.join(CERT_DIR, "jwt_keys")
JWT_PRIVATE_KEY_PATH = os.path.join(JWT_KEY_DIR, "jwt_private.pem")
JWT_PUBLIC_KEY_PATH = os.path.join(JWT_KEY_DIR, "jwt_public.pem")

REVOCATION_LIST_PATH = os.path.join(LOG_DIR, "revoked_tokens.json")
ISSUED_TOKENS_PATH = os.path.join(LOG_DIR, "issued_tokens.json")

POLICIES_FILE = os.path.join(PROJECT_ROOT, "pdp", "policies.json")
