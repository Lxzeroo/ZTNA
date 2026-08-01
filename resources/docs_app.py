"""
Low-sensitivity protected resource: an internal documentation portal.

Binds ONLY to 127.0.0.1 -- see docs/WINDOWS_SETUP.md for the Windows
Firewall rule that blocks any inbound connection to this port from
anywhere except the gateway process's own loopback call.

Hardening revision (see docs/HARDENING.md): now also serves TLS and
requires a client certificate signed by the internal CA (mutual TLS) --
see common/tls_utils.py, common/ca_utils.py. This means network-level
isolation (firewall/loopback binding) is no longer the ONLY thing
preventing a non-Gateway caller from reaching this resource: even a host
that reaches this port cannot complete a TLS handshake without the
Gateway's issued client certificate.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.http_utils import JSONRequestHandler, serve
from common.config import RESOURCES, MTLS_ENABLED


class DocsAppHandler(JSONRequestHandler):
    routes = {
        ("GET", "/data"): "handle_data",
        ("GET", "/health"): "handle_health",
    }

    def handle_health(self, params, body):
        return 200, {"status": "ok", "service": "docs-app"}

    def handle_data(self, params, body):
        return 200, {
            "resource": "docs-app",
            "sensitivity": RESOURCES["docs-app"]["sensitivity"],
            "content": "Internal engineering wiki: onboarding guide, VPN retirement "
                       "notice, and the Q3 architecture review notes.",
        }


if __name__ == "__main__":
    cfg = RESOURCES["docs-app"]
    require_mtls = MTLS_ENABLED and cfg.get("require_mtls", False)
    serve(DocsAppHandler, cfg["host"], cfg["port"], use_tls=True,
          service_name="docs-app", require_client_cert=require_mtls)
