"""
High-sensitivity protected resource: internal financial reporting API.

Same isolation model as docs_app.py -- loopback-only, reachable exclusively
through the gateway. This resource requires BOTH a higher role
(finance_manager+) AND a higher device trust score (see common/config.py),
which is what the "compromised device" demo scenario in
tests/test_ztna.py and agent/client_agent.py exercises.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.http_utils import JSONRequestHandler, serve
from common.config import RESOURCES


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
    serve(FinanceAppHandler, cfg["host"], cfg["port"], use_tls=False)
