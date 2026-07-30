"""
Policy Decision Point (PDP) -- the Attribute-Based Access Control (ABAC)
brain of the ZTNA system.

The Gateway calls `evaluate()` on EVERY request (not just at login) with the
claims from the caller's current access token and the resource being
requested. This is what makes the system "zero trust": possessing a valid
token is necessary but not sufficient -- the token's claims (role, device
trust score) are re-checked against policy on every single call.

Policy is intentionally expressed as data (policies.json-equivalent dict
below) rather than buried in if/else chains, so policies can be reviewed,
diffed, and extended without touching the enforcement code in gateway/.
"""
import time

from common.config import RESOURCES, ROLE_LEVELS

# Optional extra dimension: resources can be restricted to a time window.
# Disabled for both demo resources by default (see RESOURCES in
# common/config.py) but implemented here to show the engine is extensible
# beyond role + device trust, e.g. for shift-based access.
BUSINESS_HOURS = (0, 24)  # (start_hour, end_hour), 24 = disabled/no restriction


def _within_business_hours() -> bool:
    start, end = BUSINESS_HOURS
    if end >= 24:
        return True
    hour = time.localtime().tm_hour
    return start <= hour < end


def evaluate(claims: dict, resource_name: str) -> tuple:
    """Return (allow: bool, reason: str).

    `reason` is always populated (even on allow) so the gateway can write a
    single structured audit line without extra branching, and so a denial
    can be explained precisely -- which specific policy dimension failed --
    rather than a generic "access denied".
    """
    resource = RESOURCES.get(resource_name)
    if resource is None:
        return False, "unknown_resource"

    role = claims.get("role")
    role_level = ROLE_LEVELS.get(role, 0)
    if role_level < resource["min_role_level"]:
        return False, (
            f"insufficient_role (has={role}:{role_level}, "
            f"needs>={resource['min_role_level']})"
        )

    trust = claims.get("device_trust_score", 0)
    if not isinstance(trust, (int, float)) or trust < resource["min_device_trust"]:
        return False, (
            f"insufficient_device_trust (has={trust}, "
            f"needs>={resource['min_device_trust']})"
        )

    # Cryptographic device attestation is a SEPARATE, stronger dimension
    # from the self-reported trust score above -- a resource can demand
    # proof of key possession regardless of how healthy the device claims
    # to be, since the score itself is just a self-report an agent could
    # lie about. See idp/device_registry.py and docs/DEVICE_ATTESTATION.md.
    if resource.get("require_attestation") and not claims.get("attested"):
        return False, "attestation_required"

    if resource.get("business_hours_only") and not _within_business_hours():
        return False, "outside_business_hours"

    return True, "policy_match"


def describe_policy(resource_name: str) -> dict:
    """Expose the active policy for a resource -- used by the dashboard and
    by `docs/EVALUATION.md` generation so the report can cite the exact
    thresholds enforced, not just describe them in prose."""
    return dict(RESOURCES.get(resource_name, {}))
