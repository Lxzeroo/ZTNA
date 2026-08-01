# PyZTNA Architecture

## 1. Goal

Implement the core mechanics of Zero Trust Network Access described in the
project's reference papers -- primarily *"Fortifying Linux Server and
Implementing a Zero Trust Network Access (ZTNA) for Enhanced Security"*
(MDPI, 2025) -- from scratch, rather than configuring an off-the-shelf
product (Tailscale, OpenZiti, Pomerium).

## 2. Components

```
                         +-------------------+
                         |  Identity Provider|
                         |   (idp/) :9000    |
                         |  password + TOTP  |
                         |  -> RS256 JWT      |
                         +---------+---------+
                                   |
                    (1) login       | JWT { sub, role, jti,
                                    |       device_trust_score, exp }
                                   v
   +----------+          +--------------------+           +----------------+
   |  Client  | -- (2) -->|      Gateway       |-- (3) --->|  docs-app      |
   |  Agent   |  Bearer   |   (gateway/) :9200 |   mTLS    |  (low sens.)   |
   | (agent/) |  <token>  |  PEP + calls PDP   |  only     |  :9101         |
   +----------+          |  per request;       |           +----------------+
                         |  checks revocation   |           +----------------+
                         |  logs every decision |-- (3) --->|  finance-app   |
                         +----------+----------+   mTLS    |  (high sens.)  |
                                    |                       |  :9102         |
                                    v                       +----------------+
                         +--------------------+
                         | Policy Decision    |
                         | Point (pdp/)        |
                         | role level +        |
                         | device trust vs.     |
                         | per-resource policy  |
                         | (loaded from         |
                         |  pdp/policies.json)  |
                         +--------------------+
```

- **Identity Provider (`idp/idp_server.py`)** -- verifies password (bcrypt
  hash) + TOTP one-time code, rate-limits repeated failed logins, accepts a
  self-reported device trust score, optionally verifies a device
  attestation signature, and issues a signed JWT with a 45-second TTL.
- **Policy Decision Point (`pdp/policy_engine.py`)** -- pure function,
  ABAC. Policy data now lives in `pdp/policies.json`, hot-reloadable.
- **Gateway (`gateway/gateway_server.py`)** -- the only network-facing
  Policy Enforcement Point. Validates the JWT signature (RS256 public key)
  and expiry, checks the token hasn't been revoked, calls the PDP, proxies
  to the backend over mTLS only on allow, and writes a structured,
  hash-chained audit line for every allow/deny/error.
- **Protected resources (`resources/docs_app.py`, `resources/finance_app.py`)**
  -- bind to `127.0.0.1` only, now serve HTTPS and require a client
  certificate signed by the internal CA (mTLS) -- see `docs/HARDENING.md`.
- **Client agent (`agent/client_agent.py` + `agent/device_posture.py`)** --
  runs the local posture check, logs in, and calls the gateway.
- **Audit log (`common/audit_log.py`, `logs/access_log.jsonl`)** --
  append-only, hash-chained JSON lines.
- **Dashboard (`dashboard/generate_dashboard.py`)** -- renders the audit
  log as a static HTML report.

## 3. How this satisfies the core ZTNA principles (NIST SP 800-207)

| NIST SP 800-207 principle | Where it's implemented |
|---|---|
| All communication secured regardless of network location | IdP + Gateway + (as of this revision) resource<->gateway hop all serve TLS; the latter is mutually authenticated |
| Access is granted per-session, not per-network-perimeter | Gateway checks every individual request against the PDP and the revocation list |
| Access determined by dynamic policy, incl. device state | PDP checks `device_trust_score`, `attested`, and per-resource policy loaded from `pdp/policies.json` |
| Strong, verifiable subject/device identity | Optional cryptographic device attestation; JWTs are asymmetrically signed so only the IdP can mint them |
| Continuous monitoring and verification | Short-lived tokens, explicit revocation, and a tamper-evident audit log |
| Strict least privilege | Per-resource `min_role_level` / `min_device_trust` thresholds, data-driven |

## 4. Design decisions and trade-offs (original)

- **Standard-library HTTP servers instead of Flask/FastAPI** -- kept in
  this revision; a reverse proxy (see `deploy/`) is recommended in front
  of the Gateway in any real deployment to add request-size limits and
  edge rate-limiting that a framework/WAF would otherwise provide.
- **JWT with RS256 (as of this revision)** -- see `docs/HARDENING.md` for
  the migration from the original shared-secret HS256 design.
- **Internal CA-issued TLS certificates (as of this revision)** -- see
  `docs/HARDENING.md`; replaces the original single self-signed cert per
  service.
- **Short TTL (45s default) plus explicit revocation (as of this
  revision)** -- see `docs/HARDENING.md`.

## 5. What would change for a multi-machine deployment

`common/config.py` is the single place to change `IDP_HOST`,
`GATEWAY_HOST`, and each resource's `host`/`port` from `127.0.0.1` to real
machine addresses. See `docs/WINDOWS_SETUP.md` Section 5 for firewall
rules, and `deploy/README.md` (added in this revision) for reverse-proxy
and multi-instance Gateway guidance.

## 6. Hardening pass (this revision)

See `docs/HARDENING.md` for a full, itemized mapping of every gap
identified in Section 4 (and the README's "Known limitations") to what was
implemented, how to exercise it, and what remains explicitly out of scope.
