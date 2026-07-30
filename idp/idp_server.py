"""
Identity Provider (IdP) -- the authentication authority of the ZTNA system.

Responsibilities:
  1. Verify username + password (bcrypt-hashed at rest).
  2. Verify a TOTP one-time code (RFC 6238 second factor) -- real MFA.
  3. Accept a self-reported device trust score from the client agent's
     posture check and embed it in a short-lived signed JWT, alongside the
     user's role.
  4. Optionally verify a cryptographic device-attestation signature
     (idp/device_registry.py) proving possession of the device's enrolled
     key, and embed the resulting `attested` boolean in the token -- a
     materially stronger guarantee than the self-reported score alone,
     since forging it requires the private key material itself, not just
     editing the agent script. See docs/DEVICE_ATTESTATION.md.
  5. Log every authentication attempt (success AND failure) to the audit
     trail.

The IdP does NOT decide whether a user may reach a given resource -- that is
the Policy Decision Point's job (pdp/policy_engine.py), invoked per-request
by the Gateway. Separating "who are you" (IdP) from "what can you do"
(PDP) is standard Zero Trust Architecture practice (NIST SP 800-207).

Run:
    python -m idp.idp_server
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.http_utils import JSONRequestHandler, serve
from common.config import IDP_HOST, IDP_PORT, ROLE_LEVELS
from common.jwt_utils import issue_token
from common.audit_log import log_event
from common.totp import verify_totp
from idp.users_db import verify_password, get_user
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
        """Register (or re-register) a device's attestation public key.
        Trust-on-first-use: the first enrollment for a device_id is
        accepted unconditionally, matching how SSH host keys and WebAuthn
        credentials are bootstrapped. See idp/device_registry.py for the
        threat-model discussion."""
        client_ip = self.client_address[0]
        device_id = body.get("device_id", "")
        public_key_pem = body.get("public_key_pem", "")
        if not device_id or not public_key_pem:
            return 400, {"error": "device_id_and_public_key_required"}
        device_registry.register_device(device_id, public_key_pem)
        log_event(event="device_enrollment", device_id=device_id, source_ip=client_ip,
                  decision="allow", reason="enrolled")
        return 200, {"status": "enrolled", "device_id": device_id}

    def handle_challenge(self, params, body):
        """Issue a single-use, short-lived nonce for a device to sign,
        proving possession of its enrolled private key."""
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

        user = get_user(username)

        # 1) Password check
        if not user or not verify_password(username, password):
            log_event(event="authentication", username=username, source_ip=client_ip,
                      decision="deny", reason="invalid_credentials")
            return 401, {"error": "invalid_credentials"}

        # 2) MFA (TOTP) check
        if not verify_totp(user["totp_secret"], otp):
            log_event(event="authentication", username=username, source_ip=client_ip,
                      decision="deny", reason="invalid_otp")
            return 401, {"error": "invalid_otp"}

        # 3) Device posture must be present and numeric -- ZTNA requires a
        #    context signal, not just "who you are".
        if not isinstance(device_trust_score, (int, float)):
            log_event(event="authentication", username=username, source_ip=client_ip,
                      decision="deny", reason="missing_device_posture")
            return 400, {"error": "missing_device_posture"}

        device_id = device_id_override or user["device_id"]
        role = user["role"]

        # 4) Optional cryptographic attestation: only set attested=True if a
        #    signature was actually submitted AND it verifies against this
        #    device's enrolled public key over the outstanding challenge.
        #    Absence of a signature is NOT an error -- it just means this
        #    login falls back to self-reported posture only, exactly like
        #    the original design. This is the graceful-degradation path
        #    documented in docs/DEVICE_ATTESTATION.md.
        attested = False
        if attestation_signature:
            attested = device_registry.verify_and_consume(device_id, attestation_signature)

        token_data = issue_token(
            username=username,
            role=role,
            device_id=device_id,
            device_trust_score=int(device_trust_score),
            attested=attested,
        )

        log_event(event="authentication", username=username, source_ip=client_ip,
                  decision="allow", reason="mfa_ok", role=role, role_level=ROLE_LEVELS.get(role, 0),
                  device_id=device_id, device_trust_score=int(device_trust_score), attested=attested)

        return 200, token_data


if __name__ == "__main__":
    serve(IdPHandler, IDP_HOST, IDP_PORT, use_tls=True)
