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

# --- State backend (production-readiness revision) ---
# Where request-path state (revocation list, login failure counts, device
# registry) lives. "file" reproduces the historical single-host behaviour.
# See common/storage.py for why this is now an explicit choice, and
# docs/HARDENING.md for what must change before running >1 instance.
STATE_BACKEND = os.environ.get("ZTNA_STATE_BACKEND", "file")
STATE_DIR = os.environ.get("ZTNA_STATE_DIR", os.path.join(LOG_DIR, "state"))

DEVICE_REGISTRY_PATH = os.path.join(STATE_DIR, "devices.json")

# --- Device enrollment approval (production-readiness revision) ---
# Closes the trust-on-first-use gap named in docs/HARDENING.md: an enrolling
# device lands in "pending" and cannot produce an `attested` login until an
# administrator approves it (tools/manage_devices.py).
#
# Set to 0 ONLY for the single-machine demo, where there is no administrator
# to do the approving and requiring one would break `run_all.ps1` out of the
# box. Any real deployment leaves this at 1.
REQUIRE_DEVICE_APPROVAL = os.environ.get("ZTNA_REQUIRE_DEVICE_APPROVAL", "1") not in ("0", "false", "False")

# --- Token binding / proof of possession (production-readiness revision) ---
# When enabled, a token carrying a `cnf` (confirmation) claim may only be
# used by a caller that can prove possession of the matching device private
# key, by signing a per-request challenge. A token copied off the device is
# then useless. Modelled on RFC 7800 (`cnf`) and the DPoP proof pattern.
TOKEN_BINDING_ENABLED = os.environ.get("ZTNA_TOKEN_BINDING", "1") not in ("0", "false", "False")
# How much clock skew to tolerate on a proof's timestamp. Small, because the
# window is also the replay window.
PROOF_MAX_AGE_SECONDS = int(os.environ.get("ZTNA_PROOF_MAX_AGE_SECONDS", "30"))

# --- Step-up authentication (production-readiness revision) ---
# A resource may require that the user authenticated RECENTLY, not merely
# that they hold a valid token. Enforced per-resource via
# `max_auth_age_seconds` in pdp/policies.json.
STEP_UP_ENABLED = os.environ.get("ZTNA_STEP_UP", "1") not in ("0", "false", "False")

# --- Key rotation (production-readiness revision) ---
# Certificate/key lifetimes. Short by production standards on purpose: a
# rotation procedure that is never exercised is not a procedure.
# See docs/KEY_ROTATION.md.
CA_VALIDITY_DAYS = int(os.environ.get("ZTNA_CA_VALIDITY_DAYS", "825"))
SERVICE_CERT_VALIDITY_DAYS = int(os.environ.get("ZTNA_SERVICE_CERT_VALIDITY_DAYS", "90"))
# Warn this far ahead of expiry at startup, so rotation is planned not urgent.
CERT_EXPIRY_WARN_DAYS = int(os.environ.get("ZTNA_CERT_EXPIRY_WARN_DAYS", "21"))

# --- Observability (production-readiness revision) ---
# Emit machine-readable JSON logs to stdout in addition to the audit trail,
# so a real deployment can ship them to a SIEM without scraping prose.
JSON_LOGS = os.environ.get("ZTNA_JSON_LOGS", "0") not in ("0", "false", "False")
LOG_LEVEL = os.environ.get("ZTNA_LOG_LEVEL", "INFO").upper()
# Header used to carry a correlation id across IdP -> Gateway -> resource.
CORRELATION_HEADER = "X-Request-Id"

# --- Graceful shutdown (production-readiness revision) ---
# How long to let in-flight requests finish after SIGTERM before forcing the
# listener closed. Must be shorter than the orchestrator's kill timeout.
SHUTDOWN_GRACE_SECONDS = int(os.environ.get("ZTNA_SHUTDOWN_GRACE_SECONDS", "10"))
