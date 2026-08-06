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
import atexit
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
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
_service_logs = {}  # module name -> captured stdout/stderr file path
_log_handles = []   # kept alive so the OS handles outlive the subprocesses
_gateway_client_cert = None  # (cert_path, key_path), built once services can generate it


def _start(mod):
    """Launch a service subprocess.

    stdout/stderr go to a temporary FILE, not a PIPE. This is not cosmetic.
    A pipe nobody reads has a finite buffer -- about 4 KB on Windows, 64 KB
    on Linux -- and once it fills, the child blocks forever inside write().
    The service simply stops answering, and every subsequent request fails
    with a connection timeout pointing at the network rather than at the
    real cause. A file has no such limit, and unlike DEVNULL it keeps the
    output available for diagnosing a service that failed to start.
    """
    fd, path = tempfile.mkstemp(prefix="ztna-test-",
                                suffix=f"-{mod.replace('.', '_')}.log")
    os.close(fd)
    _service_logs[mod] = path
    # Open a plain file object we control the lifetime of. NamedTemporaryFile
    # would be garbage-collected the moment this function returns, closing the
    # handle and emitting a ResourceWarning.
    log_handle = open(path, "w", encoding="utf-8", errors="replace")
    _log_handles.append(log_handle)
    proc = subprocess.Popen(
        [sys.executable, "-u", "-m", mod],
        cwd=PROJECT_ROOT,
        stdout=log_handle, stderr=subprocess.STDOUT, text=True,
        env=os.environ.copy(),
    )
    proc._ztna_log_path = path
    return proc


def _assert_ports_free(ports):
    """Refuse to run if a previous run left services holding our ports.

    Without this the suite is actively misleading. On Windows a fresh
    service can bind a port that a stale process already holds (see
    common/http_utils._ExclusiveThreadingHTTPServer), so requests get split
    between the new process and the old one and the run fails intermittently
    somewhere unrelated. Better to stop here and say exactly what is wrong.
    """
    busy = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                busy.append(port)
    if busy:
        ports_list = ", ".join(str(p) for p in busy)
        raise RuntimeError(
            f"\n\nPort(s) already in use: {ports_list}\n"
            f"A PyZTNA service from an earlier run is still running -- most likely\n"
            f"that run was interrupted with Ctrl+C before it could shut down.\n\n"
            f"Windows:\n"
            f"  Get-Process python | Stop-Process        # or, more surgically:\n"
            f"  Get-NetTCPConnection -LocalPort {busy[0]} | Select-Object OwningProcess\n"
            f"  Stop-Process -Id <pid>\n\n"
            f"Linux/macOS:\n"
            f"  lsof -ti :{busy[0]} | xargs kill\n"
        )


def _dump_service_logs():
    """Print captured service output. Called when startup fails, since the
    reason is almost always in there (a preflight refusal, a port already in
    use, a missing certificate)."""
    for mod, path in _service_logs.items():
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
        except OSError:
            continue
        if content:
            print(f"\n----- {mod} output -----\n{content}", file=sys.stderr)


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

    # Check BEFORE starting anything -- a stale service on one of these ports
    # would otherwise silently serve some of our requests.
    _assert_ports_free([9000, 9200, 9101, 9102])

    # Ctrl+C during a long run must not orphan the services; without this the
    # next run inherits four zombies holding the ports.
    atexit.register(tearDownModule)

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
        _dump_service_logs()
        tearDownModule()
        raise RuntimeError("one or more ZTNA services failed to start within the timeout "
                           "-- see the captured service output above")


def tearDownModule():
    """Stop every service and release its port.

    Registered with atexit as well as being called by unittest, because a
    Ctrl+C during a long run otherwise leaves four services holding ports
    9000/9200/9101/9102 -- which then breaks the *next* run in a way that
    looks nothing like the actual cause. Idempotent, so being called twice
    is harmless.
    """
    for p in list(_procs.values()):
        if p.poll() is not None:
            continue
        try:
            p.terminate()
        except OSError:
            pass
    time.sleep(0.3)
    for p in list(_procs.values()):
        try:
            p.communicate(timeout=3)
        except Exception:
            try:
                p.kill()
                p.communicate(timeout=3)
            except Exception:
                pass
    _procs.clear()

    for handle in _log_handles:
        try:
            handle.close()
        except OSError:
            pass
    _log_handles.clear()

    for path in list(_service_logs.values()):
        try:
            os.remove(path)
        except OSError:
            pass
    _service_logs.clear()


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


def enroll_only(device_id):
    """Enroll a device WITHOUT approving it. Returns (public_key_pem, response).

    Separated from enroll_and_sign() so tests can exercise the pending state
    on its own -- an enrolled-but-unapproved device is now a distinct,
    security-relevant condition rather than an intermediate step nobody sees.
    """
    from agent import device_attestation
    info = device_attestation.ensure_enrolled(device_id)
    resp = requests.post(f"{IDP_URL}/enroll", json={
        "device_id": device_id, "public_key_pem": info["public_key_pem"],
    }, verify=False, timeout=5)
    return info, resp


def approve(device_id):
    """Perform the administrator approval step (tools/manage_devices.py).

    Called directly rather than over HTTP because approval is deliberately
    NOT an network-exposed endpoint -- if a remote caller could approve its
    own device, the control would be worthless. The IdP subprocess sees the
    change because the device registry is shared through common/storage.py.
    """
    from idp import device_registry
    return device_registry.approve_device(device_id, approved_by="test-suite")


def enroll_and_sign(device_id, do_approve=True):
    """Enroll, approve, and produce a valid attestation signature.

    `do_approve` defaults True so existing tests read as before; the
    approval step is what a real administrator does out of band after
    confirming the device thumbprint.
    """
    from agent import device_attestation
    info, _ = enroll_only(device_id)
    if do_approve:
        approve(device_id)
    chal = requests.post(f"{IDP_URL}/challenge", json={"device_id": device_id},
                          verify=False, timeout=5).json()
    sig = device_attestation.sign_nonce(device_id, chal["nonce"], info["hardware_backed"])
    return info["public_key_pem"], sig


def device_proof_headers(token, method="GET", path=""):
    """Build X-Device-Proof headers for a bound token, as the agent does."""
    import base64 as _b64
    import json as _json
    import secrets as _secrets
    import time as _time
    from agent import device_attestation
    from common import token_binding

    payload_part = token.split(".")[1]
    payload_part += "=" * (-len(payload_part) % 4)
    claims = _json.loads(_b64.urlsafe_b64decode(payload_part))
    if not claims.get("cnf"):
        return {}

    device_id = claims["device_id"]
    info = device_attestation.ensure_enrolled(device_id)
    nonce = _secrets.token_hex(16)
    ts = int(_time.time())
    payload = token_binding.build_proof_payload(claims["jti"], method, path, ts, nonce)
    sig = device_attestation.sign_bytes(device_id, payload, info["hardware_backed"])
    return {
        token_binding.PROOF_HEADER: _b64.b64encode(sig).decode("ascii"),
        token_binding.PROOF_DATA_HEADER: _b64.b64encode(payload).decode("ascii"),
    }


def access(resource, token, with_proof=True):
    """Call the Gateway. Attaches a device proof when the token is bound.

    `with_proof=False` simulates an attacker who has stolen the token string
    but does not hold the device key.
    """
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    path = f"/access/{resource}"
    if token and with_proof:
        headers.update(device_proof_headers(token, "GET", path))
    return requests.get(f"{GATEWAY_URL}{path}", headers=headers, verify=False, timeout=5)


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


class TestDeviceApproval(unittest.TestCase):
    """Trust-on-first-use closure (production-readiness revision).

    Previously the first enrollment for any device_id was accepted
    unconditionally, so anyone who could reach /enroll could register their
    own key and thereafter produce valid attestations. The cryptography was
    never the weak part -- the binding to a device anyone had actually
    vouched for was.
    """

    def test_enrollment_lands_in_pending_not_approved(self):
        device_id = f"test-pending-{id(self)}"
        _, resp = enroll_only(device_id)
        self.assertEqual(resp.status_code, 202,
                         "a device awaiting approval must not report 200 OK")
        self.assertEqual(resp.json()["approval_status"], "pending")

    def test_unapproved_device_cannot_attest(self):
        from agent import device_attestation
        device_id = f"test-unapproved-{id(self)}"
        info, _ = enroll_only(device_id)  # deliberately NOT approved
        chal = requests.post(f"{IDP_URL}/challenge", json={"device_id": device_id},
                              verify=False, timeout=5).json()
        sig = device_attestation.sign_nonce(device_id, chal["nonce"], info["hardware_backed"])
        resp = login("bob", "Manager#2026", 95, device_id=device_id,
                     attestation_signature=sig)
        # The signature is cryptographically perfect. It is refused anyway,
        # because nobody approved this device.
        self.assertFalse(resp.json()["claims"]["attested"])

    def test_unapproved_device_is_denied_the_gated_resource(self):
        from agent import device_attestation
        device_id = f"test-unapproved-gate-{id(self)}"
        info, _ = enroll_only(device_id)
        chal = requests.post(f"{IDP_URL}/challenge", json={"device_id": device_id},
                              verify=False, timeout=5).json()
        sig = device_attestation.sign_nonce(device_id, chal["nonce"], info["hardware_backed"])
        token = login("bob", "Manager#2026", 95, device_id=device_id,
                      attestation_signature=sig).json()["access_token"]
        r = access("finance-app", token)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["reason"], "attestation_required")

    def test_approval_then_attestation_succeeds(self):
        device_id = f"test-approved-{id(self)}"
        _, signature = enroll_and_sign(device_id)  # enrolls AND approves
        resp = login("bob", "Manager#2026", 95, device_id=device_id,
                     attestation_signature=signature)
        self.assertTrue(resp.json()["claims"]["attested"])

    def test_reenrolling_with_a_different_key_resets_approval(self):
        """Otherwise approval is trivially bypassable: enroll honestly, get
        approved, then swap in any key you like."""
        from idp import device_registry
        device_id = f"test-rekey-{id(self)}"
        enroll_and_sign(device_id)
        self.assertTrue(device_registry.is_approved(device_id))

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        attacker_pem = attacker_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        requests.post(f"{IDP_URL}/enroll", json={
            "device_id": device_id, "public_key_pem": attacker_pem,
        }, verify=False, timeout=5)

        self.assertFalse(device_registry.is_approved(device_id),
                         "swapping the key must force re-approval")


class TestTokenBinding(unittest.TestCase):
    """A stolen token must be useless without the device key."""

    def test_token_for_approved_device_carries_cnf_claim(self):
        device_id = f"test-cnf-{id(self)}"
        _, signature = enroll_and_sign(device_id)
        claims = login("bob", "Manager#2026", 95, device_id=device_id,
                       attestation_signature=signature).json()["claims"]
        self.assertIn("cnf", claims)
        self.assertTrue(claims["cnf"].get("jkt"))

    def test_bound_token_without_proof_is_rejected(self):
        """The core exfiltration scenario: attacker has the token string
        (from a log, a dump, a proxy) but not the device's private key."""
        device_id = f"test-steal-{id(self)}"
        _, signature = enroll_and_sign(device_id)
        token = login("bob", "Manager#2026", 95, device_id=device_id,
                      attestation_signature=signature).json()["access_token"]

        self.assertEqual(access("finance-app", token).status_code, 200)

        stolen = access("finance-app", token, with_proof=False)
        self.assertEqual(stolen.status_code, 401)
        self.assertEqual(stolen.json()["error"], "device_proof_missing")

    def test_proof_cannot_be_replayed(self):
        device_id = f"test-replay-{id(self)}"
        _, signature = enroll_and_sign(device_id)
        token = login("bob", "Manager#2026", 95, device_id=device_id,
                      attestation_signature=signature).json()["access_token"]

        headers = {"Authorization": f"Bearer {token}"}
        headers.update(device_proof_headers(token, "GET", "/access/finance-app"))

        first = requests.get(f"{GATEWAY_URL}/access/finance-app", headers=headers,
                             verify=False, timeout=5)
        self.assertEqual(first.status_code, 200)

        replayed = requests.get(f"{GATEWAY_URL}/access/finance-app", headers=headers,
                                verify=False, timeout=5)
        self.assertEqual(replayed.status_code, 401)
        self.assertEqual(replayed.json()["error"], "device_proof_replayed")

    def test_proof_for_one_resource_cannot_be_used_for_another(self):
        device_id = f"test-crossuse-{id(self)}"
        _, signature = enroll_and_sign(device_id)
        token = login("bob", "Manager#2026", 95, device_id=device_id,
                      attestation_signature=signature).json()["access_token"]

        headers = {"Authorization": f"Bearer {token}"}
        headers.update(device_proof_headers(token, "GET", "/access/docs-app"))
        r = requests.get(f"{GATEWAY_URL}/access/finance-app", headers=headers,
                         verify=False, timeout=5)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "device_proof_wrong_request")


class TestStepUpAuthentication(unittest.TestCase):
    """`auth_time` freshness, distinct from token expiry."""

    def test_token_carries_auth_time_and_amr(self):
        claims = login("alice", "Intern#2026", 90).json()["claims"]
        self.assertIsInstance(claims.get("auth_time"), int)
        self.assertIn("pwd", claims.get("amr", []))
        self.assertIn("otp", claims.get("amr", []))

    def test_stale_auth_time_triggers_step_up(self):
        from pdp import policy_engine
        claims = {
            "role": "finance_manager", "device_trust_score": 95, "attested": True,
            "auth_time": int(time.time()) - 9999, "amr": ["pwd", "otp", "device"],
        }
        allow, reason = policy_engine.evaluate(claims, "finance-app")
        self.assertFalse(allow)
        self.assertTrue(reason.startswith("step_up_required"), reason)

    def test_fresh_auth_time_passes(self):
        from pdp import policy_engine
        claims = {
            "role": "finance_manager", "device_trust_score": 95, "attested": True,
            "auth_time": int(time.time()), "amr": ["pwd", "otp", "device"],
        }
        allow, reason = policy_engine.evaluate(claims, "finance-app")
        self.assertTrue(allow, reason)

    def test_token_without_auth_time_fails_closed(self):
        """A token predating this feature must NOT bypass step-up policy."""
        from pdp import policy_engine
        claims = {
            "role": "finance_manager", "device_trust_score": 95, "attested": True,
            "amr": ["pwd", "otp", "device"],
        }
        allow, reason = policy_engine.evaluate(claims, "finance-app")
        self.assertFalse(allow)
        self.assertIn("step_up_required", reason)

    def test_missing_required_auth_method_is_denied(self):
        from pdp import policy_engine
        claims = {
            "role": "finance_manager", "device_trust_score": 95, "attested": True,
            "auth_time": int(time.time()), "amr": ["pwd"],  # no OTP
        }
        allow, reason = policy_engine.evaluate(claims, "finance-app")
        self.assertFalse(allow)
        self.assertIn("insufficient_auth_method", reason)


class TestOperationalEndpoints(unittest.TestCase):

    def test_health_endpoint_reports_liveness(self):
        for url in (IDP_URL, GATEWAY_URL):
            r = requests.get(f"{url}/health", verify=False, timeout=5)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["status"], "ok")

    def test_ready_endpoint_reports_dependency_state(self):
        r = requests.get(f"{GATEWAY_URL}/ready", verify=False, timeout=5)
        self.assertIn(r.status_code, (200, 503))
        body = r.json()
        self.assertIn("checks", body)
        self.assertIn("state_store", body["checks"])

    def test_correlation_id_is_echoed_back(self):
        from common.config import CORRELATION_HEADER
        sent = "test-correlation-abc123"
        r = requests.get(f"{GATEWAY_URL}/health", headers={CORRELATION_HEADER: sent},
                         verify=False, timeout=5)
        self.assertEqual(r.headers.get(CORRELATION_HEADER), sent)

    def test_correlation_id_is_generated_when_absent(self):
        from common.config import CORRELATION_HEADER
        r = requests.get(f"{GATEWAY_URL}/health", verify=False, timeout=5)
        generated = r.headers.get(CORRELATION_HEADER)
        self.assertTrue(generated and generated != "-")


class TestStorageBackend(unittest.TestCase):

    def test_file_backend_round_trip_and_health(self):
        import tempfile
        from common.storage import FileBackend
        with tempfile.TemporaryDirectory() as tmp:
            backend = FileBackend(tmp)
            backend.set("ns", "key", {"value": 1})
            self.assertEqual(backend.get("ns", "key"), {"value": 1})
            backend.delete("ns", "key")
            self.assertIsNone(backend.get("ns", "key"))
            ok, _ = backend.health()
            self.assertTrue(ok)

    def test_atomic_write_retries_transient_windows_lock(self):
        """Regression: os.replace fails with PermissionError (WinError 5) when
        a cloud-sync client (OneDrive/Dropbox/Drive) momentarily holds the
        destination open. This is not hypothetical -- this project's own
        working folder is OneDrive-synced, and it broke device approval.
        The lock is released within milliseconds, so we retry."""
        import tempfile as _tf
        import common.storage as _storage

        real_replace = os.replace
        attempts = {"n": 0}

        def flaky_replace(src, dst):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise PermissionError(5, "Access is denied")
            return real_replace(src, dst)

        os.replace = flaky_replace
        try:
            with _tf.TemporaryDirectory() as tmp:
                target = os.path.join(tmp, "state.json")
                _storage.atomic_write_json(target, {"survived": True})
                with open(target, encoding="utf-8") as f:
                    self.assertEqual(json.load(f), {"survived": True})
        finally:
            os.replace = real_replace

        self.assertEqual(attempts["n"], 3, "should have retried past the transient lock")

    def test_atomic_write_gives_up_with_an_actionable_error(self):
        """A permanent lock must not retry forever, and the error must name
        the likely cause rather than surfacing a bare 'Access is denied'."""
        import tempfile as _tf
        import common.storage as _storage

        real_replace = os.replace

        def always_locked(src, dst):
            raise PermissionError(5, "Access is denied")

        os.replace = always_locked
        try:
            with _tf.TemporaryDirectory() as tmp:
                with self.assertRaises(OSError) as ctx:
                    _storage.atomic_write_json(os.path.join(tmp, "s.json"), {"a": 1})
                self.assertIn("cloud-sync", str(ctx.exception))
                leftovers = [f for f in os.listdir(tmp) if f.endswith(".tmp")]
                self.assertEqual(leftovers, [], "temp file should be cleaned up on failure")
        finally:
            os.replace = real_replace

    def test_corrupt_state_file_does_not_crash_the_service(self):
        """It must degrade to empty rather than raise -- but see
        common/storage.py: this is logged loudly because for the revocation
        namespace 'empty' means 'nothing is revoked'."""
        import tempfile, os as _os
        from common.storage import FileBackend
        with tempfile.TemporaryDirectory() as tmp:
            backend = FileBackend(tmp)
            backend.set("ns", "k", 1)
            with open(_os.path.join(tmp, "ns.json"), "w", encoding="utf-8") as f:
                f.write("{not json")
            self.assertEqual(backend.all("ns"), {})


class TestPreflightValidation(unittest.TestCase):

    def test_preflight_reports_findings_without_raising(self):
        from common.preflight import collect_findings
        findings = collect_findings("gateway")
        self.assertIsInstance(findings, list)
        for f in findings:
            self.assertIn(f["severity"], ("ERROR", "WARN"))
            self.assertTrue(f["detail"])

    def test_missing_policy_file_is_a_blocking_error(self):
        """A malformed or absent policy file must stop startup, not be
        silently ignored -- an authorization system that cannot read its
        policy has no business accepting requests."""
        import common.preflight as preflight
        original = preflight.POLICIES_FILE
        try:
            preflight.POLICIES_FILE = "/nonexistent/policies.json"
            findings = preflight.collect_findings("gateway")
            checks = [f["check"] for f in findings if f["severity"] == "ERROR"]
            self.assertIn("policies_missing", checks)
        finally:
            preflight.POLICIES_FILE = original


if __name__ == "__main__":
    unittest.main(verbosity=2)
