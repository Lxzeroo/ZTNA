"""
Integration test suite proving the ZTNA implementation actually enforces
the properties a Zero Trust Network Access system is supposed to guarantee.

This spins up all four services (IdP, Gateway, docs-app, finance-app) as
real subprocesses listening on real (loopback) sockets and drives them over
real HTTPS/HTTP requests -- it is deliberately NOT a set of mocked unit
tests, so a passing run is direct evidence the system works end to end,
not just that individual functions return the right value in isolation.

Run:
    python -m unittest tests.test_ztna -v
    (or, if pytest is installed:  pytest tests/test_ztna.py -v)
"""
import json
import os
import subprocess
import sys
import time
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# Short TTL so the token-expiry test doesn't need to sleep long.
os.environ.setdefault("ZTNA_TOKEN_TTL_SECONDS", "3")

import requests
import urllib3
urllib3.disable_warnings()

from common.totp import current_totp
from common.tls_utils import scheme as _tls_scheme
from idp.users_db import USERS

# Use whatever scheme the services actually come up on -- see the same fix
# in agent/client_agent.py for why this can't be hardcoded to "https".
_SCHEME = _tls_scheme()
IDP_URL = f"{_SCHEME}://127.0.0.1:9000"
GATEWAY_URL = f"{_SCHEME}://127.0.0.1:9200"

_procs = {}


def _start(mod):
    return subprocess.Popen(
        [sys.executable, "-u", "-m", mod],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env=os.environ.copy(),
    )


def _wait_ready(url, tries=40):
    for _ in range(tries):
        try:
            r = requests.get(url, verify=False, timeout=1)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


def setUpModule():
    # Fresh audit log for this test run.
    log_path = os.path.join(PROJECT_ROOT, "logs", "access_log.jsonl")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    open(log_path, "w").close()

    _procs["idp"] = _start("idp.idp_server")
    _procs["gateway"] = _start("gateway.gateway_server")
    _procs["docs"] = _start("resources.docs_app")
    _procs["finance"] = _start("resources.finance_app")

    ready = (
        _wait_ready(f"{IDP_URL}/health")
        and _wait_ready(f"{GATEWAY_URL}/health")
        and _wait_ready("http://127.0.0.1:9101/health")
        and _wait_ready("http://127.0.0.1:9102/health")
    )
    if not ready:
        tearDownModule()
        raise RuntimeError("one or more ZTNA services failed to start within the timeout")


def tearDownModule():
    for p in _procs.values():
        p.terminate()
    time.sleep(0.3)
    for p in _procs.values():
        try:
            p.communicate(timeout=3)
        except Exception:
            p.kill()
            p.communicate()


def login(username, password, device_trust_score, otp=None):
    code = otp if otp is not None else current_totp(USERS[username]["totp_secret"])
    return requests.post(f"{IDP_URL}/login", json={
        "username": username, "password": password, "otp": code,
        "device_trust_score": device_trust_score,
    }, verify=False, timeout=5)


def access(resource, token):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.get(f"{GATEWAY_URL}/access/{resource}", headers=headers, verify=False, timeout=5)


class TestAuthentication(unittest.TestCase):

    def test_valid_credentials_and_mfa_issue_token(self):
        r = login("alice", "Intern#2026", 90)
        self.assertEqual(r.status_code, 200)
        self.assertIn("access_token", r.json())

    def test_wrong_password_rejected(self):
        r = login("alice", "WrongPassword!", 90)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "invalid_credentials")

    def test_wrong_otp_rejected(self):
        r = login("alice", "Intern#2026", 90, otp="000000")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "invalid_otp")

    def test_unknown_user_rejected(self):
        r = login("mallory", "whatever", 90, otp="000000")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "invalid_credentials")


class TestLeastPrivilegeAccessControl(unittest.TestCase):
    """Role-based least privilege: a low-privilege identity must never reach
    a resource that requires a higher role, even with a perfectly healthy
    device."""

    def test_intern_can_reach_low_sensitivity_resource(self):
        token = login("alice", "Intern#2026", 95).json()["access_token"]
        r = access("docs-app", token)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["resource"], "docs-app")

    def test_intern_cannot_reach_high_sensitivity_resource(self):
        token = login("alice", "Intern#2026", 95).json()["access_token"]
        r = access("finance-app", token)
        self.assertEqual(r.status_code, 403)
        self.assertIn("insufficient_role", r.json()["reason"])

    def test_finance_manager_with_healthy_device_reaches_finance_app(self):
        token = login("bob", "Manager#2026", 95).json()["access_token"]
        r = access("finance-app", token)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["resource"], "finance-app")


class TestContextAwareAccessControl(unittest.TestCase):
    """The key ZTNA property that a plain RBAC/VPN system lacks: identical
    role does not guarantee access if the device context is untrusted."""

    def test_correct_role_but_compromised_device_is_still_denied(self):
        # carol has the SAME role as bob (finance_manager) but a low
        # device trust score -- this must be denied despite the role match.
        token = login("carol", "Manager#2026", 35).json()["access_token"]
        r = access("finance-app", token)
        self.assertEqual(r.status_code, 403)
        self.assertIn("insufficient_device_trust", r.json()["reason"])

    def test_low_trust_device_denied_even_for_low_sensitivity_resource(self):
        token = login("carol", "Manager#2026", 35).json()["access_token"]
        r = access("docs-app", token)
        self.assertEqual(r.status_code, 403)
        self.assertIn("insufficient_device_trust", r.json()["reason"])


class TestTokenIntegrityAndContinuousVerification(unittest.TestCase):

    def test_missing_token_rejected(self):
        r = access("docs-app", None)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "missing_bearer_token")

    def test_tampered_token_rejected(self):
        token = login("alice", "Intern#2026", 95).json()["access_token"]
        tampered = token[:-4] + "abcd"
        r = access("docs-app", tampered)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "token_signature_invalid")

    def test_token_expires_and_is_rejected_after_ttl(self):
        """Proves the system re-verifies on every call instead of trusting
        a session indefinitely after the initial login (continuous
        verification), by showing the SAME token that worked a moment ago
        is refused once its short TTL elapses."""
        token = login("bob", "Manager#2026", 95).json()["access_token"]
        r1 = access("finance-app", token)
        self.assertEqual(r1.status_code, 200)

        ttl = int(os.environ.get("ZTNA_TOKEN_TTL_SECONDS", "3"))
        time.sleep(ttl + 1.5)

        r2 = access("finance-app", token)
        self.assertEqual(r2.status_code, 401)
        self.assertEqual(r2.json()["error"], "token_expired")


class TestUnknownResource(unittest.TestCase):

    def test_request_for_undefined_resource_is_rejected(self):
        token = login("admin", "Admin#2026", 95).json()["access_token"]
        r = access("does-not-exist", token)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["reason"], "unknown_resource")


class TestAuditTrail(unittest.TestCase):
    """Visibility/logging is a required ZTNA pillar (NIST SP 800-207) --
    every allow AND deny decision must be recorded."""

    def test_every_decision_is_logged(self):
        log_path = os.path.join(PROJECT_ROOT, "logs", "access_log.jsonl")

        with open(log_path) as f:
            before = f.readlines()

        token = login("alice", "Intern#2026", 95).json()["access_token"]
        access("docs-app", token)
        access("finance-app", token)  # will be denied, must still be logged

        with open(log_path) as f:
            after = f.readlines()

        self.assertGreater(len(after), len(before))
        new_events = [json.loads(l) for l in after[len(before):]]
        decisions = [e["decision"] for e in new_events if e.get("event") == "access"]
        self.assertIn("allow", decisions)
        self.assertIn("deny", decisions)


if __name__ == "__main__":
    unittest.main(verbosity=2)
