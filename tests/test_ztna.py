"""
Integration test suite proving the ZTNA implementation actually enforces
the properties a Zero Trust Network Access system is supposed to guarantee.

This spins up all four services (IdP, Gateway, docs-app, finance-app) as
real subprocesses listening on real (loopback) sockets and drives them over
real HTTPS requests -- it is deliberately NOT a set of mocked unit tests.

Hardening revision (see docs/HARDENING.md): the original 19 tests are
preserved unchanged in intent (same scenarios, same expected outcomes);
what changed underneath is RS256 signing, mTLS-protected resources, and
the new TestHardenedTokens / TestTokenRevocation / TestRateLimiting /
TestAuditLogIntegrity / TestPolicyExternalization / TestMTLSIsolation
classes added at the bottom of this file.

Run:
    python -m unittest tests.test_ztna -v
    (or, if pytest is installed:  pytest tests/test_ztna.py -v)
"""
import json
import os
import socket
import ssl
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
from common.config import GATEWAY_CLIENT_CERT_CN, RESOURCES, CA_CERT_PATH
from idp.users_db import USERS

_SCHEME = _tls_scheme()
IDP_URL = f"{_SCHEME}://127.0.0.1:9000"
GATEWAY_URL = f"{_SCHEME}://127.0.0.1:9200"

_procs = {}
_gateway_client_cert = None  # (cert_path, key_path), built once services can generate it


def _start(mod):
    return subprocess.Popen(
        [sys.executable, "-u", "-m", mod],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env=os.environ.copy(),
    )


def _wait_ready_idp_gateway(url, tries=40):
    for _ in range(tries):
        try:
            r = requests.get(url, verify=False, timeout=1)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


def _wait_ready_resource(host, port, tries=40):
    """Resources require an mTLS client cert as of this hardening
    revision -- a plain requests.get without `cert=` would fail the TLS
    handshake before ever reaching /health. Uses the same client cert the
    Gateway itself uses."""
    cert_path, key_path = _gateway_client_cert
    url = f"https://{host}:{port}/health"
    for _ in range(tries):
        try:
            r = requests.get(url, verify=False, cert=(cert_path, key_path), timeout=1)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


def setUpModule():
    global _gateway_client_cert

    # Fresh audit log for this test run.
    log_path = os.path.join(PROJECT_ROOT, "logs", "access_log.jsonl")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    open(log_path, "w").close()

    # Also start fresh on revocation/token-store state between full runs.
    # Overwrite rather than delete -- some sandboxed/managed filesystems
    # (e.g. a locked-down CI workspace) permit truncating a file's
    # contents but not removing the file itself; this achieves the same
    # "fresh state" goal either way.
    for fname in ("revoked_tokens.json", "issued_tokens.json"):
        p = os.path.join(PROJECT_ROOT, "logs", fname)
        if os.path.exists(p):
            with open(p, "w", encoding="utf-8") as f:
                f.write("{}" if fname == "revoked_tokens.json" else "[]")

    # Build (or reuse) the CA + the Gateway's mTLS client cert directly in
    # THIS process so the test suite can talk to docs-app/finance-app the
    # same way the Gateway does, for readiness checks and the mTLS
    # isolation test below.
    from common import ca_utils
    _gateway_client_cert = ca_utils.issue_cert(GATEWAY_CLIENT_CERT_CN, is_client=True)[::-1]
    # issue_cert returns (key_path, cert_path); readiness helper wants (cert_path, key_path)

    _procs["idp"] = _start("idp.idp_server")
    _procs["gateway"] = _start("gateway.gateway_server")
    _procs["docs"] = _start("resources.docs_app")
    _procs["finance"] = _start("resources.finance_app")

    ready = (
        _wait_ready_idp_gateway(f"{IDP_URL}/health")
        and _wait_ready_idp_gateway(f"{GATEWAY_URL}/health")
        and _wait_ready_resource("127.0.0.1", 9101)
        and _wait_ready_resource("127.0.0.1", 9102)
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


def login(username, password, device_trust_score, otp=None, device_id=None, attestation_signature=None):
    code = otp if otp is not None else current_totp(USERS[username]["totp_secret"])
    body = {
        "username": username, "password": password, "otp": code,
        "device_trust_score": device_trust_score,
    }
    if device_id is not None:
        body["device_id"] = device_id
    if attestation_signature is not None:
        body["attestation_signature"] = attestation_signature
    return requests.post(f"{IDP_URL}/login", json=body, verify=False, timeout=5)


def enroll_and_sign(device_id):
    from agent import device_attestation
    info = device_attestation.ensure_enrolled(device_id)
    requests.post(f"{IDP_URL}/enroll", json={
        "device_id": device_id, "public_key_pem": info["public_key_pem"],
    }, verify=False, timeout=5)
    chal = requests.post(f"{IDP_URL}/challenge", json={"device_id": device_id},
                          verify=False, timeout=5).json()
    sig = device_attestation.sign_nonce(device_id, chal["nonce"], info["hardware_backed"])
    return info["public_key_pem"], sig


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
        r = login("mallory-nonexistent", "whatever", 90, otp="000000")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "invalid_credentials")


class TestLeastPrivilegeAccessControl(unittest.TestCase):

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
        device_id = f"test-device-role-{id(self)}"
        _, signature = enroll_and_sign(device_id)
        token = login("bob", "Manager#2026", 95, device_id=device_id,
                       attestation_signature=signature).json()["access_token"]
        r = access("finance-app", token)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["resource"], "finance-app")


class TestContextAwareAccessControl(unittest.TestCase):

    def test_correct_role_but_compromised_device_is_still_denied(self):
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
        device_id = f"test-device-ttl-{id(self)}"
        _, signature = enroll_and_sign(device_id)
        token = login("bob", "Manager#2026", 95, device_id=device_id,
                       attestation_signature=signature).json()["access_token"]
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


class TestDeviceAttestation(unittest.TestCase):

    def test_high_trust_correct_role_but_no_attestation_is_denied(self):
        token = login("bob", "Manager#2026", 95).json()["access_token"]
        r = access("finance-app", token)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["reason"], "attestation_required")

    def test_valid_attestation_signature_is_accepted(self):
        device_id = f"test-device-{id(self)}"
        _, signature = enroll_and_sign(device_id)
        resp = login("bob", "Manager#2026", 95, device_id=device_id, attestation_signature=signature)
        self.assertTrue(resp.json()["claims"]["attested"])
        token = resp.json()["access_token"]
        r = access("finance-app", token)
        self.assertEqual(r.status_code, 200)

    def test_forged_attestation_signature_is_rejected(self):
        device_id = f"test-device-forge-{id(self)}"
        _, signature = enroll_and_sign(device_id)
        tampered = signature[:-4] + ("AAAA" if signature[-4:] != "AAAA" else "BBBB")
        resp = login("bob", "Manager#2026", 95, device_id=device_id, attestation_signature=tampered)
        self.assertFalse(resp.json()["claims"]["attested"])
        token = resp.json()["access_token"]
        r = access("finance-app", token)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["reason"], "attestation_required")

    def test_attestation_signature_cannot_be_replayed(self):
        device_id = f"test-device-replay-{id(self)}"
        _, signature = enroll_and_sign(device_id)

        first = login("bob", "Manager#2026", 95, device_id=device_id, attestation_signature=signature)
        self.assertTrue(first.json()["claims"]["attested"])

        second = login("bob", "Manager#2026", 95, device_id=device_id, attestation_signature=signature)
        self.assertFalse(second.json()["claims"]["attested"])

    def test_unenrolled_device_gets_unattested_not_an_error(self):
        resp = login("bob", "Manager#2026", 95, device_id="never-enrolled-device",
                      attestation_signature="bm90LWEtcmVhbC1zaWduYXR1cmU=")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["claims"]["attested"])


class TestAuditTrail(unittest.TestCase):

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


# ---------------------------------------------------------------------------
# New in this hardening revision -- see docs/HARDENING.md
# ---------------------------------------------------------------------------

class TestHardenedTokens(unittest.TestCase):
    """RS256 asymmetric signing (docs/HARDENING.md item 1)."""

    def test_token_is_signed_with_rs256(self):
        import jwt as pyjwt
        token = login("alice", "Intern#2026", 95).json()["access_token"]
        header = pyjwt.get_unverified_header(token)
        self.assertEqual(header["alg"], "RS256")

    def test_token_carries_a_unique_jti(self):
        r1 = login("alice", "Intern#2026", 95).json()
        r2 = login("alice", "Intern#2026", 95).json()
        self.assertIn("jti", r1["claims"])
        self.assertNotEqual(r1["claims"]["jti"], r2["claims"]["jti"])


class TestTokenRevocation(unittest.TestCase):
    """Explicit revocation (docs/HARDENING.md item 3)."""

    def test_revoked_token_is_denied_even_though_still_unexpired(self):
        from common import revocation

        resp = login("alice", "Intern#2026", 95).json()
        token = resp["access_token"]
        jti = resp["claims"]["jti"]

        # Works before revocation.
        r1 = access("docs-app", token)
        self.assertEqual(r1.status_code, 200)

        revocation.revoke(jti, reason="test_revocation")

        # Same still-unexpired token is now denied.
        r2 = access("docs-app", token)
        self.assertEqual(r2.status_code, 401)
        self.assertEqual(r2.json()["error"], "token_revoked")

    def test_revoke_by_username_finds_active_jti(self):
        from common import revocation, token_store

        resp = login("alice", "Intern#2026", 95).json()
        jti = resp["claims"]["jti"]

        active = token_store.active_jtis_for_user("alice")
        self.assertIn(jti, active)

        for j in active:
            revocation.revoke(j, reason="test_bulk_revocation")
        self.assertTrue(revocation.is_revoked(jti))


class TestRateLimiting(unittest.TestCase):
    """Login rate limiting / lockout (docs/HARDENING.md item 2). Uses a
    disposable username so it can't lock out alice/bob/carol/admin used by
    every other test class sharing this same IdP process."""

    def test_repeated_failed_logins_trigger_lockout(self):
        username = f"ratelimit-test-user-{id(self)}"
        last = None
        for _ in range(6):  # default ZTNA_LOGIN_MAX_ATTEMPTS=5
            last = login(username, "wrong-password-always", 90, otp="000000")
        self.assertEqual(last.status_code, 429)
        self.assertEqual(last.json()["error"], "account_locked")
        self.assertIn("retry_after_seconds", last.json())


class TestAuditLogIntegrity(unittest.TestCase):
    """Hash-chained audit log (docs/HARDENING.md item 6)."""

    def test_current_log_chain_is_intact(self):
        from common.audit_log import verify_chain
        # Generate at least one fresh event so there's something to check.
        token = login("alice", "Intern#2026", 95).json()["access_token"]
        access("docs-app", token)

        ok, details = verify_chain()
        self.assertTrue(ok, details)
        self.assertGreater(details["count"], 0)

    def test_tampering_with_a_historical_line_is_detected(self):
        from common.audit_log import read_events, verify_events_chain

        events = read_events()
        self.assertGreater(len(events), 0)

        tampered = [dict(e) for e in events]
        # Mutate a field in the middle of the chain, WITHOUT recomputing
        # hashes -- simulating exactly the kind of after-the-fact edit the
        # hash chain exists to catch. Appending a marker (rather than
        # setting a fixed value) guarantees the content actually changes
        # regardless of what the original value happened to be.
        mid = len(tampered) // 2
        tampered[mid]["reason"] = str(tampered[mid].get("reason", "")) + "_TAMPERED"

        ok, details = verify_events_chain(tampered)
        self.assertFalse(ok)
        self.assertIn("break_line", details)


class TestPolicyExternalization(unittest.TestCase):
    """PDP policy loaded from pdp/policies.json (docs/HARDENING.md item 7)."""

    def test_editing_policy_file_changes_enforcement_after_reload(self):
        import json as _json
        import tempfile
        import pdp.policy_engine as pe

        original_file = pe.POLICIES_FILE
        original_cache = dict(pe._policy_cache)
        try:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
            _json.dump({
                "resources": {
                    "docs-app": {
                        "min_role_level": 1,
                        "min_device_trust": 999,  # impossibly high -- everyone denied
                        "require_attestation": False,
                        "require_mtls": True,
                    }
                }
            }, tmp)
            tmp.close()

            pe.POLICIES_FILE = tmp.name
            pe.reload_policies()

            allow, reason = pe.evaluate({"role": "admin", "device_trust_score": 100}, "docs-app")
            self.assertFalse(allow)
            self.assertIn("insufficient_device_trust", reason)
        finally:
            pe.POLICIES_FILE = original_file
            pe._policy_cache = original_cache
            os.unlink(tmp.name)


class TestMTLSIsolation(unittest.TestCase):
    """mTLS between Gateway and resources (docs/HARDENING.md item 5)."""

    def test_direct_resource_connection_without_client_cert_is_refused(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we don't care about the server's
                                          # identity for this test -- we're
                                          # checking that the SERVER refuses
                                          # US for not presenting a client cert
        raised = False
        try:
            with socket.create_connection(("127.0.0.1", 9101), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as tls_sock:
                    tls_sock.send(b"GET /data HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                    tls_sock.recv(100)
        except (ssl.SSLError, ConnectionResetError, ConnectionAbortedError, OSError):
            raised = True
        self.assertTrue(raised, "expected the resource to refuse a connection with no client certificate")


if __name__ == "__main__":
    unittest.main(verbosity=2)
