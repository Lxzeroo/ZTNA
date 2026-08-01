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
IDP_HOST = os.environ.get("ZTNA_IDP_HOST", "127.0.0.1")
IDP_PORT = int(os.environ.get("ZTNA_IDP_PORT", "9000"))

GATEWAY_HOST = os.environ.get("ZTNA_GATEWAY_HOST", "127.0.0.1")
GATEWAY_PORT = int(os.environ.get("ZTNA_GATEWAY_PORT", "9200"))

# Protected resources bind ONLY to loopback by default. In a multi-machine
# deployment, change these hosts to real addresses and add the Windows
# Firewall / iptables rules in docs/WINDOWS_SETUP.md Section 5 -- but as of
# this hardening revision, network-level isolation is defense-in-depth,
# not the only control: docs-app/finance-app also require a TLS client
# certificate issued by the internal CA (mTLS), so a host that gets past
# the firewall still cannot complete a handshake without the Gateway's
# client cert. See docs/HARDENING.md.
RESOURCES = {
    "docs-app": {
        "host": "127.0.0.1",
        "port": 9101,
        "sensitivity": "low",
        "min_role_level": 1,
        "min_device_trust": 50,
        "require_attestation": False,
        "require_mtls": True,
    },
    "finance-app": {
        "host": "127.0.0.1",
        "port": 9102,
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
