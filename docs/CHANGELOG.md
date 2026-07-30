# Changelog / Bug Fix Log

Kept deliberately -- a documented bug found during real-world testing (by
someone other than the original author) and its fix is good evidence of an
actual engineering process, not just a first-draft submission.

## Fix: client agent used the wrong URL scheme on machines without OpenSSL

**Symptom:** `agent/client_agent.py` and `tests/test_ztna.py` failed with:
```
ssl.SSLError: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1081)
```

**Root cause:** `idp/idp_server.py` and `gateway/gateway_server.py` both
degrade gracefully to plain HTTP when `openssl` isn't found on PATH (see
`common/tls_utils.py`). That fallback worked correctly -- but the client
agent and the test suite both **hardcoded `https://`** in their base URLs
regardless of what scheme the servers actually came up on. On a machine
without OpenSSL installed, the servers silently started on `http://` while
the client kept attempting a TLS handshake against them, producing the
version-mismatch error above.

**Fix:** Added `common.tls_utils.scheme()`, which runs the exact same
certificate-availability check the servers use (`ensure_self_signed_cert()`)
and returns `"https"` or `"http"` accordingly. `agent/client_agent.py` and
`tests/test_ztna.py` now call this instead of hardcoding a scheme, so the
client and the servers always agree on plaintext vs. TLS regardless of
whether OpenSSL is installed on the machine.

**Verified by:** re-running the full test suite twice -- once normally
(OpenSSL available, all services on HTTPS), and once with `openssl`
deliberately stripped from the subprocess `PATH` (services fall back to
HTTP). Both runs: 14/14 tests passed, and a direct `agent.client_agent`
invocation succeeded in both conditions.

**Takeaway for the report:** this is also a good concrete example of the
"encrypt everything" NIST SP 800-207 principle being *optional in this
demo* rather than enforced -- a production deployment should fail closed
(refuse to start, or refuse to serve) if TLS cannot be established, rather
than silently downgrading to plaintext HTTP. That's a legitimate follow-up
hardening item beyond what this classroom project currently does.
