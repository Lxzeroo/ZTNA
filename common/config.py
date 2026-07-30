"""
Central configuration for the PyZTNA project.

Everything that would normally live in environment variables / a secrets
manager is centralised here for a classroom-scale demo. In a production
deployment JWT_SECRET must come from a secrets store and never be committed.
"""
import os

# --- Network ---
IDP_HOST = "127.0.0.1"
IDP_PORT = 9000

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 9200

# Protected resources bind ONLY to loopback. They are never reachable from
# another machine directly -- the Windows Firewall rule in
# docs/WINDOWS_SETUP.md blocks inbound traffic to these ports from anywhere
# except the gateway process itself. The gateway is the single enforcement
# point (Policy Enforcement Point / PEP) for the whole network.
RESOURCES = {
    "docs-app": {
        "host": "127.0.0.1",
        "port": 9101,
        "sensitivity": "low",
        "min_role_level": 1,
        "min_device_trust": 50,
        "require_attestation": False,   # graceful-degradation demo: self-report is enough here
    },
    "finance-app": {
        "host": "127.0.0.1",
        "port": 9102,
        "sensitivity": "high",
        "min_role_level": 3,
        "min_device_trust": 80,
        "require_attestation": True,    # a self-reported score alone is not enough for this resource --
                                         # the login must also carry a verified device-attestation signature
                                         # (see idp/device_registry.py, docs/DEVICE_ATTESTATION.md)
    },
}

# --- Identity ---
ROLE_LEVELS = {
    "intern": 1,
    "employee": 2,
    "finance_manager": 3,
    "admin": 4,
}

# --- Tokens ---
# Deliberately short so the demo visibly shows continuous re-verification
# instead of "authenticate once, trust forever" (the traditional VPN model
# ZTNA is designed to replace).
JWT_SECRET = os.environ.get("ZTNA_JWT_SECRET", "classroom-demo-secret-change-me")
JWT_ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = int(os.environ.get("ZTNA_TOKEN_TTL_SECONDS", "45"))

# --- Paths ---
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
ACCESS_LOG_PATH = os.path.join(LOG_DIR, "access_log.jsonl")
CERT_DIR = os.path.join(PROJECT_ROOT, "certs")
