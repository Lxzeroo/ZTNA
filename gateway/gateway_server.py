"""
Gateway -- the Policy Enforcement Point (PEP) of the ZTNA system.

This is the ONLY component a client is ever allowed to talk to over the
network. Protected resources (resources/finance_app.py, resources/docs_app.py)
bind exclusively to 127.0.0.1 and are fronted by this gateway, which:

  1. Requires a valid, non-expired, correctly-signed (RS256) JWT on every
     request (Authorization: Bearer <token>).
  2. Checks the token hasn't been explicitly revoked (this hardening
     revision -- common/revocation.py; see docs/HARDENING.md).
  3. Re-evaluates the request against the Policy Decision Point
     (pdp/policy_engine.py) using the token's role + device_trust_score +
     attested claims -- NOT just at login, on every single call.
  4. Proxies the request to the real backend over mutual TLS (this
     hardening revision -- only the Gateway holds a client cert signed by
     the internal CA, so this is what actually enforces "only the Gateway
     may reach these resources" at the TLS layer, not just firewall
     isolation) only after both checks pass.
  5. Writes a structured, hash-chained audit line for every allow AND deny
     decision.

Run:
    python -m gateway.gateway_server
"""
import http.client
import json
import os
import ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.http_utils import JSONRequestHandler, serve
from common.config import (GATEWAY_HOST, GATEWAY_PORT, GATEWAY_BIND_HOST, RESOURCES,
                            MTLS_ENABLED, GATEWAY_CLIENT_CERT_CN)
from common.jwt_utils import verify_token, TokenError
from common.audit_log import log_event
from common.tls_utils import build_client_ssl_context
from common import revocation
from pdp.policy_engine import evaluate

# Built once at import time: the Gateway's own mTLS client identity for
# calling docs-app/finance-app, and a no-client-cert context for any
# resource that has require_mtls disabled.
_MTLS_CLIENT_CTX = build_client_ssl_context(GATEWAY_CLIENT_CERT_CN) if MTLS_ENABLED else None
_PLAIN_TLS_CLIENT_CTX = build_client_ssl_context()


def _proxy_to_backend(resource: dict, method: str = "GET"):
    require_mtls = MTLS_ENABLED and resource.get("require_mtls", False)
    ctx = _MTLS_CLIENT_CTX if require_mtls else _PLAIN_TLS_CLIENT_CTX
    conn = http.client.HTTPSConnection(resource["host"], resource["port"], timeout=5, context=ctx)
    try:
        conn.request(method, "/data")
        resp = conn.getresponse()
        raw = resp.read()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            payload = {"raw": raw.decode("utf-8", errors="replace")}
        return resp.status, payload
    finally:
        conn.close()


class GatewayHandler(JSONRequestHandler):
    routes = {
        ("GET", "/access/{resource}"): "handle_access",
        ("GET", "/health"): "handle_health",
    }

    def handle_health(self, params, body):
        return 200, {"status": "ok", "service": "gateway"}

    def handle_access(self, params, body):
        resource_name = params["resource"]
        client_ip = self.client_address[0]
        auth_header = self.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            log_event(event="access", resource=resource_name, source_ip=client_ip,
                      decision="deny", reason="missing_bearer_token")
            return 401, {"error": "missing_bearer_token"}

        token = auth_header[len("Bearer "):].strip()

        try:
            claims = verify_token(token)
        except TokenError as e:
            log_event(event="access", resource=resource_name, source_ip=client_ip,
                      decision="deny", reason=str(e))
            return 401, {"error": str(e)}

        if revocation.is_revoked(claims.get("jti")):
            log_event(event="access", resource=resource_name, source_ip=client_ip,
                      decision="deny", reason="token_revoked",
                      username=claims.get("sub"), device_id=claims.get("device_id"))
            return 401, {"error": "token_revoked"}

        allow, reason = evaluate(claims, resource_name)

        log_event(
            event="access", resource=resource_name, source_ip=client_ip,
            decision="allow" if allow else "deny", reason=reason,
            username=claims.get("sub"), role=claims.get("role"),
            device_id=claims.get("device_id"),
            device_trust_score=claims.get("device_trust_score"),
        )

        if not allow:
            return 403, {"error": "access_denied", "reason": reason}

        resource = RESOURCES[resource_name]
        try:
            status, payload = _proxy_to_backend(resource, "GET")
        except (ConnectionRefusedError, OSError, ssl.SSLError) as e:
            log_event(event="access", resource=resource_name, source_ip=client_ip,
                      decision="error", reason=f"backend_unreachable:{e}",
                      username=claims.get("sub"))
            return 502, {"error": "backend_unreachable", "detail": str(e)}

        return status, payload


if __name__ == "__main__":
    serve(GatewayHandler, GATEWAY_BIND_HOST, GATEWAY_PORT, use_tls=True,
          service_name="gateway", cert_sans=[GATEWAY_HOST])
