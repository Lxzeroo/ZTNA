# PyZTNA Architecture

## 1. Goal

Implement the core mechanics of Zero Trust Network Access described in the
project's reference papers -- primarily *"Fortifying Linux Server and
Implementing a Zero Trust Network Access (ZTNA) for Enhanced Security"*
(MDPI, 2025) -- from scratch, rather than configuring an off-the-shelf
product (Tailscale, OpenZiti, Pomerium). Building each control-plane
component by hand demonstrates understanding of *why* ZTNA works, not just
that it can be turned on.

## 2. Components

```
                         +-------------------+
                         |  Identity Provider|
                         |   (idp/) :9000    |
                         |  password + TOTP  |
                         |  -> short-lived JWT|
                         +---------+---------+
                                   |
                    (1) login       | JWT { sub, role,
                                    |       device_trust_score, exp }
                                   v
   +----------+          +--------------------+           +----------------+
   |  Client  | -- (2) -->|      Gateway       |-- (3) --->|  docs-app      |
   |  Agent   |  Bearer   |   (gateway/) :9200 |  loopback |  (low sens.)   |
   | (agent/) |  <token>  |  PEP + calls PDP   |  only     |  :9101         |
   +----------+          |  per request        |           +----------------+
                         |  logs every decision |           +----------------+
                         +----------+----------+-- (3) --->|  finance-app   |
                                    |                       |  (high sens.)  |
                                    v                       |  :9102         |
                         +--------------------+             +----------------+
                         | Policy Decision    |
                         | Point (pdp/)        |
                         | role level +        |
                         | device trust vs.     |
                         | per-resource policy  |
                         +--------------------+
```

- **Identity Provider (`idp/idp_server.py`)** -- verifies password (bcrypt
  hash) + TOTP one-time code (RFC 6238, implemented from scratch in
  `common/totp.py`), accepts a self-reported device trust score from the
  agent, and issues a signed JWT with a **45-second TTL** (configurable via
  `ZTNA_TOKEN_TTL_SECONDS`).
- **Policy Decision Point (`pdp/policy_engine.py`)** -- pure function,
  Attribute-Based Access Control: `evaluate(claims, resource) -> (allow, reason)`.
  Checks role level against the resource's minimum, and device trust score
  against the resource's minimum. Kept separate from the gateway so policy
  logic is unit-testable in isolation and auditable as a single file.
- **Gateway (`gateway/gateway_server.py`)** -- the only network-facing
  Policy Enforcement Point. Validates the JWT (signature + expiry) on
  **every** request, calls the PDP, proxies to the backend only on allow,
  and writes a structured audit line for every allow/deny/error.
- **Protected resources (`resources/docs_app.py`, `resources/finance_app.py`)**
  -- bind to `127.0.0.1` only; never reachable except via the gateway's
  loopback proxy call. `docs-app` models a low-sensitivity resource
  (role >= `intern`, trust >= 50). `finance-app` models a high-sensitivity
  one (role >= `finance_manager`, trust >= 80).
- **Client agent (`agent/client_agent.py` + `agent/device_posture.py`)** --
  runs the local posture check (Defender/BitLocker/Firewall on Windows,
  graceful degradation elsewhere), logs in, and calls the gateway.
- **Audit log (`common/audit_log.py`, `logs/access_log.jsonl`)** --
  append-only JSON lines for every authentication and access decision.
- **Dashboard (`dashboard/generate_dashboard.py`)** -- renders the audit
  log as a static HTML report (no server, no external CDN).

## 3. How this satisfies the core ZTNA principles (NIST SP 800-207)

| NIST SP 800-207 principle | Where it's implemented |
|---|---|
| All communication secured regardless of network location | IdP + Gateway serve HTTPS with a generated cert (`common/tls_utils.py`) |
| Access is granted per-session, not per-network-perimeter | Gateway checks every individual request against the PDP, not just at "connect time" |
| Access determined by dynamic policy, incl. device state | PDP checks `device_trust_score`, not just identity/role |
| Continuous monitoring and verification | Short-lived tokens force periodic re-authentication; every decision is logged |
| Strict least privilege | Per-resource `min_role_level` / `min_device_trust` thresholds; `alice` (intern) is provably blocked from `finance-app` even though she's a valid authenticated user |

## 4. Design decisions and trade-offs

- **Standard-library HTTP servers instead of Flask/FastAPI** -- keeps the
  dependency list to 4 packages (PyJWT, bcrypt, requests, psutil), all of
  which install cleanly on a bare Windows Python without a C build toolchain.
  Trade-off: less mature routing/middleware than a real framework; acceptable
  for a project scoped around demonstrating ZTNA mechanics rather than
  building a general-purpose web framework.
- **JWT with HS256 (shared secret)** rather than asymmetric RS256 -- simpler
  to run without a PKI, but means the IdP and Gateway must share
  `JWT_SECRET`. In a distributed deployment (IdP and Gateway on separate
  hosts) this secret would need to move to a proper secrets manager and
  ideally switch to RS256 so the gateway only needs a public key.
- **Self-signed TLS certificates** -- sufficient to prove the "encrypt
  everything" principle end-to-end; a production rollout would use an
  internal CA or public certs (Let's Encrypt) so clients don't need
  `verify=False`.
- **Device trust score is self-reported by the agent.** This is the
  single most important limitation to call out: a fully compromised
  endpoint could tamper with `agent/device_posture.py` to report a high
  score. Real ZTNA products solve this with remote attestation / MDM
  integration (e.g., the endpoint's compliance state is asserted by an
  external management platform the gateway also trusts, not by the
  endpoint itself). Documented as future work in `docs/EVALUATION.md`.
- **Short TTL (45s default) instead of a token-revocation list** -- avoids
  needing a shared revocation store, at the cost of up to 45 seconds of
  residual access after a device is flagged compromised. A production
  system would add both: short TTLs *and* an explicit revocation check.

## 5. What would change for a multi-machine deployment

Everything here is coded to run distributed already -- `common/config.py`
is the single place to change `IDP_HOST`, `GATEWAY_HOST`, and each
resource's `host`/`port` from `127.0.0.1` to real machine addresses. The
only additional step is the Windows Firewall rules in
`docs/WINDOWS_SETUP.md` Section 5, which stop the resource machines from
accepting connections from anything other than the gateway machine.
