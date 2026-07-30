"""
Identity Provider (IdP) -- the authentication authority of the ZTNA system.

Responsibilities:
  1. Verify username + password (bcrypt-hashed at rest).
  2. Verify a TOTP one-time code (RFC 6238 second factor) -- real MFA.
  3. Accept a self-reported device trust score from the client agent's
     posture check and embed it in a short-lived signed JWT, alongside the
     user's role.
  4. Log every authentication attempt (success AND failure) to the audit
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


class IdPHandler(JSONRequestHandler):
    routes = {
        ("POST", "/login"): "handle_login",
        ("GET", "/health"): "handle_health",
    }

    def handle_health(self, params, body):
        return 200, {"status": "ok", "service": "idp"}

    def handle_login(self, params, body):
        client_ip = self.client_address[0]
        username = body.get("username", "")
        password = body.get("password", "")
        otp = body.get("otp", "")
        device_trust_score = body.get("device_trust_score")
        device_id_override = body.get("device_id")

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

        token_data = issue_token(
            username=username,
            role=role,
            device_id=device_id,
            device_trust_score=int(device_trust_score),
        )

        log_event(event="authentication", username=username, source_ip=client_ip,
                  decision="allow", reason="mfa_ok", role=role, role_level=ROLE_LEVELS.get(role, 0),
                  device_id=device_id, device_trust_score=int(device_trust_score))

        return 200, token_data


if __name__ == "__main__":
    serve(IdPHandler, IDP_HOST, IDP_PORT, use_tls=True)
