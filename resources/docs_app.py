"""
Low-sensitivity protected resource: an internal documentation portal.

Binds ONLY to 127.0.0.1 -- see docs/WINDOWS_SETUP.md for the Windows
Firewall rule that blocks any inbound connection to this port from
anywhere except the gateway process's own loopback call. It is never
addressable from the client directly; every request must go through
gateway/gateway_server.py, which is the only component that enforces
identity + policy checks.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.http_utils import JSONRequestHandler, serve
from common.config import RESOURCES


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
    serve(DocsAppHandler, cfg["host"], cfg["port"], use_tls=False)
