"""
Policy Decision Point (PDP) -- the Attribute-Based Access Control (ABAC)
brain of the ZTNA system.

The Gateway calls `evaluate()` on EVERY request (not just at login) with the
claims from the caller's current access token and the resource being
requested. This is what makes the system "zero trust": possessing a valid
token is necessary but not sufficient -- the token's claims (role, device
trust score, attestation) are re-checked against policy on every single
call.

Hardening revision (see docs/HARDENING.md): policy thresholds now live in
`pdp/policies.json` (data), loaded once at import time and reloadable via
`reload_policies()` without restarting the process. This replaces reading
policy directly out of `common.config.RESOURCES` (still used as a
fallback/default for anything the JSON file doesn't override), so a policy
change no longer requires touching Python source -- policies can be
reviewed, diffed, and updated by someone who isn't a developer.
"""
import json
import os
import time
import threading

from common.config import RESOURCES, ROLE_LEVELS, POLICIES_FILE, STEP_UP_ENABLED

_lock = threading.Lock()
_policy_cache = {}
_business_hours_cache = (0, 24)


def _load_policies_from_disk() -> dict:
    """Merge pdp/policies.json over common.config.RESOURCES. A resource
    present only in RESOURCES (not in the JSON file) still works using its
    config.py defaults -- the JSON file only needs to contain overrides."""
    merged = {name: dict(policy) for name, policy in RESOURCES.items()}
    business_hours = (0, 24)

    if os.path.exists(POLICIES_FILE):
        try:
            with open(POLICIES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            for name, overrides in data.get("resources", {}).items():
                merged.setdefault(name, {})
                merged[name].update({k: v for k, v in overrides.items() if not k.startswith("_")})
            bh = data.get("business_hours")
            if bh:
                business_hours = (bh.get("start_hour", 0), bh.get("end_hour", 24))
        except (json.JSONDecodeError, OSError) as e:
            print(f"[pdp] WARNING: failed to load {POLICIES_FILE} ({e}) -- "
                  f"falling back to common.config.RESOURCES only")

    return merged, business_hours


def reload_policies() -> None:
    """Re-read pdp/policies.json from disk. Call this after editing the
    file to apply changes without restarting the Gateway process."""
    global _policy_cache, _business_hours_cache
    with _lock:
        _policy_cache, _business_hours_cache = _load_policies_from_disk()


reload_policies()  # populate on first import


def _within_business_hours() -> bool:
    start, end = _business_hours_cache
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
    with _lock:
        resource = _policy_cache.get(resource_name)

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

    if resource.get("require_attestation") and not claims.get("attested"):
        return False, "attestation_required"

    # Step-up authentication (production-readiness revision).
    #
    # Distinct from token expiry. A token can be freshly minted -- valid
    # `exp`, valid signature -- while the human behind it last proved who
    # they were hours ago, because tokens get refreshed and sessions get
    # resumed. `auth_time` records the latter. A high-sensitivity resource
    # can therefore demand "you authenticated within the last N seconds",
    # which is what every bank means by re-entering your password before a
    # transfer, and is why OpenID Connect specifies `auth_time` separately
    # from `iat`.
    #
    # Tokens minted before this revision have no auth_time. They are treated
    # as failing the check rather than passing it: defaulting to "fresh"
    # would mean an old token silently bypasses every step-up policy.
    max_auth_age = resource.get("max_auth_age_seconds")
    if STEP_UP_ENABLED and max_auth_age:
        auth_time = claims.get("auth_time")
        if not isinstance(auth_time, (int, float)):
            return False, "step_up_required (token predates auth_time tracking)"
        age = time.time() - auth_time
        if age > max_auth_age:
            return False, (
                f"step_up_required (authenticated {int(age)}s ago, "
                f"needs<={int(max_auth_age)}s)"
            )

    # Required authentication methods, e.g. ["pwd", "otp", "device"].
    # Lets policy demand *how* the user authenticated, not merely that they
    # did -- a device-attested login is a stronger claim than password+OTP.
    required_amr = resource.get("required_amr")
    if required_amr:
        presented = set(claims.get("amr") or [])
        missing = [m for m in required_amr if m not in presented]
        if missing:
            return False, f"insufficient_auth_method (missing={','.join(missing)})"

    if resource.get("business_hours_only") and not _within_business_hours():
        return False, "outside_business_hours"

    return True, "policy_match"


def describe_policy(resource_name: str) -> dict:
    """Expose the active (post-merge) policy for a resource -- used by the
    dashboard and by report generation so the report can cite the exact
    thresholds enforced, not just describe them in prose."""
    with _lock:
        return dict(_policy_cache.get(resource_name, {}))
