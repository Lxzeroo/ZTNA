"""
High-sensitivity protected resource: internal financial reporting API.

Same isolation model as docs_app.py -- loopback-only, reachable exclusively
through the gateway, and (this hardening revision) additionally requires
mutual TLS with the internal CA -- see docs/HARDENING.md. This resource
requires BOTH a higher role (finance_manager+) AND a higher device trust
score (see common/config.py / pdp/policies.json), which is what the
"compromised device" demo scenario exercises.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.http_utils import JSONRequestHandler, serve
from common.config import RESOURCES, MTLS_ENABLED


class FinanceAppHandler(JSONRequestHandler):
    routes = {
        ("GET", "/data"): "handle_data",
        ("GET", "/health"): "handle_health",
    }

    def handle_health(self, params, body):
        return 200, {"status": "ok", "service": "finance-app"}

    def handle_data(self, params, body):
        return 200, {
            "resource": "finance-app",
            "sensitivity": RESOURCES["finance-app"]["sensitivity"],
            "content": "CONFIDENTIAL Q3 financial report: revenue $4.2M, "
                       "payroll ledger, and unreleased earnings figures.",
        }


if __name__ == "__main__":
    cfg = RESOURCES["finance-app"]
    require_mtls = MTLS_ENABLED and cfg.get("require_mtls", False)
    # Bind to bind_host (often 0.0.0.0 on a multi-host deployment) but put the
    # dial address in the certificate, so a remote Gateway's TLS hostname
    # verification succeeds. See docs/MULTI_HOST_LAB.md.
    serve(FinanceAppHandler,
          cfg.get("bind_host", cfg["host"]), cfg["port"], use_tls=True,
          service_name="finance-app", require_client_cert=require_mtls,
          cert_sans=[cfg["host"]])
