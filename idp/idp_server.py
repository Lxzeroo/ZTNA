"""
Identity Provider (IdP) -- the authentication authority of the ZTNA system.

Responsibilities:
  1. Verify username + password (bcrypt-hashed at rest), via a pluggable
     auth backend (this hardening revision -- idp/auth_backends.py; local
     directory by default, LDAP-backed optionally).
  2. Verify a TOTP one-time code (RFC 6238 second factor) -- real MFA.
  3. Rate-limit repeated failed login attempts (this hardening revision --
     common/rate_limiter.py; the original design had no brute-force
     protection on this endpoint).
  4. Accept a self-reported device trust score and embed it, alongside
     the user's role, in a short-lived RS256-signed JWT (this hardening
     revision -- common/jwt_utils.py).
  5. Optionally verify a cryptographic device-attestation signature
     (idp/device_registry.py) and embed the resulting `attested` boolean.
  6. Log every authentication attempt (success AND failure) to the
     tamper-evident audit trail (common/audit_log.py).

The IdP does NOT decide whether a user may reach a given resource -- that is
the Policy Decision Point's job (pdp/policy_engine.py), invoked per-request
by the Gateway.

Run:
    python -m idp.idp_server
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.http_utils import JSONRequestHandler, serve
from common.config import (IDP_HOST, IDP_PORT, IDP_BIND_HOST, ROLE_LEVELS,
                            TOKEN_BINDING_ENABLED)
from common.jwt_utils import issue_token
from common.audit_log import log_event
from common.totp import verify_totp
from common import rate_limiter, obs
from idp.auth_backends import get_backend
from idp import device_registry


class IdPHandler(JSONRequestHandler):
    routes = {
        ("POST", "/login"): "handle_login",
        ("POST", "/enroll"): "handle_enroll",
        ("POST", "/challenge"): "handle_challenge",
        ("GET", "/health"): "handle_health",
    }

    def handle_health(self, params, body):
        return 200, {"status": "ok", "service": "idp"}

    def handle_enroll(self, params, body):
        client_ip = self.client_address[0]
        device_id = body.get("device_id", "")
        public_key_pem = body.get("public_key_pem", "")
        if not device_id or not public_key_pem:
            return 400, {"error": "device_id_and_public_key_required"}

        try:
            record = device_registry.register_device(device_id, public_key_pem)
        except ValueError as e:
            # Malformed key material -- reject rather than storing something
            # unusable that fails confusingly at attestation time instead.
            log_event(event="device_enrollment", device_id=device_id, source_ip=client_ip,
                      decision="deny", reason="invalid_public_key")
            return 400, {"error": "invalid_public_key", "detail": str(e)}

        status = record["status"]
        # An enrollment that lands in `pending` is NOT a success from the
        # caller's point of view, and reporting 200 "enrolled" would let an
        # agent believe it is attested when it is not -- precisely the silent
        # security degradation docs/CHANGELOG.md warns about. 202 Accepted
        # says "received, not yet in force".
        log_event(event="device_enrollment", device_id=device_id, source_ip=client_ip,
                  decision="allow" if status == device_registry.STATUS_APPROVED else "pending",
                  reason=f"enrolled_{status}", thumbprint=record["thumbprint"][:16])

        if status == device_registry.STATUS_APPROVED:
            return 200, {"status": "enrolled", "device_id": device_id,
                         "approval_status": status, "thumbprint": record["thumbprint"]}
        return 202, {
            "status": "pending_approval",
            "device_id": device_id,
            "approval_status": status,
            "thumbprint": record["thumbprint"],
            "detail": ("Device enrolled but awaiting administrator approval. "
                       "Attested logins are refused until then. "
                       "An administrator approves with: "
                       f"python -m tools.manage_devices --approve {device_id}"),
        }

    def handle_challenge(self, params, body):
        device_id = body.get("device_id", "")
        if not device_id:
            return 400, {"error": "device_id_required"}
        if not device_registry.is_enrolled(device_id):
            return 404, {"error": "device_not_enrolled"}
        nonce_b64 = device_registry.issue_challenge(device_id)
        return 200, {"nonce": nonce_b64, "expires_in": device_registry.CHALLENGE_TTL_SECONDS}

    def handle_login(self, params, body):
        client_ip = self.client_address[0]
        username = body.get("username", "")
        password = body.get("password", "")
        otp = body.get("otp", "")
        device_trust_score = body.get("device_trust_score")
        device_id_override = body.get("device_id")
        attestation_signature = body.get("attestation_signature")  # base64, optional

        # 0) Rate limit / lockout check -- BEFORE touching credentials, so
        #    a locked-out account doesn't leak timing information about
        #    whether the password/OTP that follows would have been right.
        locked, retry_after = rate_limiter.is_locked_out(username)
        if locked:
            log_event(event="authentication", username=username, source_ip=client_ip,
                      decision="deny", reason="account_locked")
            return 429, {"error": "account_locked", "retry_after_seconds": round(retry_after, 1)}

        backend = get_backend()
        user = backend.get_user(username)

        # 1) Password check
        if not user or not backend.verify_password(username, password):
            rate_limiter.record_failure(username)
            log_event(event="authentication", username=username, source_ip=client_ip,
                      decision="deny", reason="invalid_credentials")
            return 401, {"error": "invalid_credentials"}

        # 2) MFA (TOTP) check
        if not verify_totp(user["totp_secret"], otp):
            rate_limiter.record_failure(username)
            log_event(event="authentication", username=username, source_ip=client_ip,
                      decision="deny", reason="invalid_otp")
            return 401, {"error": "invalid_otp"}

        # 3) Device posture must be present and numeric.
        if not isinstance(device_trust_score, (int, float)):
            log_event(event="authentication", username=username, source_ip=client_ip,
                      decision="deny", reason="missing_device_posture")
            return 400, {"error": "missing_device_posture"}

        rate_limiter.record_success(username)

        device_id = device_id_override or user.get("device_id") or f"unknown-{username}"
        role = user["role"]

        # 4) Optional cryptographic attestation.
        attested = False
        if attestation_signature:
            attested = device_registry.verify_and_consume(device_id, attestation_signature)

        # 5) Token binding: pin the token to this device's key, but only if
        #    the device is enrolled AND approved. Binding a token to a key
        #    the Gateway will not accept would lock the user out with a
        #    confusing error rather than failing at enrollment where the
        #    real problem is.
        cnf_jkt = None
        if TOKEN_BINDING_ENABLED:
            record = device_registry.get_device(device_id)
            if record and record.get("status") == device_registry.STATUS_APPROVED:
                cnf_jkt = record.get("thumbprint")

        amr = ["pwd", "otp"]
        if attested:
            amr.append("device")

        token_data = issue_token(
            username=username,
            role=role,
            device_id=device_id,
            device_trust_score=int(device_trust_score),
            attested=attested,
            cnf_jkt=cnf_jkt,
            amr=amr,
        )

        log_event(event="authentication", username=username, source_ip=client_ip,
                  decision="allow", reason="mfa_ok", role=role, role_level=ROLE_LEVELS.get(role, 0),
                  device_id=device_id, device_trust_score=int(device_trust_score), attested=attested,
                  jti=token_data["claims"]["jti"], token_bound=bool(cnf_jkt),
                  correlation_id=obs.get_correlation_id())

        return 200, token_data


if __name__ == "__main__":
    serve(IdPHandler, IDP_BIND_HOST, IDP_PORT, use_tls=True, service_name="idp",
          cert_sans=[IDP_HOST])
