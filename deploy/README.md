# Deployment configs (this hardening revision)

These files address two gaps named in `docs/ARCHITECTURE.md` Section 4 /
`docs/HARDENING.md`: the stdlib HTTP servers have no WAF-level request
protection, and there's no built-in high-availability story.

## Reverse proxy (nginx.conf / Caddyfile)

Put either in front of the IdP and Gateway in any real (non-loopback-only)
deployment. What this buys you that the Python services don't do
themselves:

- Request size limits and header/connection timeouts.
- Edge-level rate limiting BY SOURCE IP on `/login`, in addition to (not
  instead of) the IdP's own per-username lockout
  (`common/rate_limiter.py`) -- the two catch different attack shapes: a
  distributed credential-stuffing attempt across many usernames from one
  source, versus repeated guesses against one account from anywhere.
- A place to terminate PUBLIC-facing TLS with a real CA-issued cert
  (Let's Encrypt / your org's enterprise CA) if the IdP/Gateway need to be
  reachable from outside a trusted internal network -- keep the PyZTNA
  internal CA (`common/ca_utils.py`) for service-to-service trust only,
  don't try to get end-user devices to trust it.

Pick nginx if you want mature, widely-documented rate-limiting directives
out of the box; pick Caddy if you want automatic Let's Encrypt certificate
issuance/renewal with less config.

Neither of these replaces the Gateway's own JWT verification, revocation
check, or PDP call -- they sit in front of it. If you skip the reverse
proxy, the system still works (as in `docs/WINDOWS_SETUP.md`'s single-host
walkthrough); you just lose the edge-level protections above.

## High availability (documented, not implemented)

The Gateway is close to horizontally scalable as-is: JWT verification is
stateless (RS256 public key, no shared secret to synchronize) and the PDP
is a pure function over `pdp/policies.json`. Two things currently prevent
just running N Gateway instances behind the nginx `upstream` block above
without further changes:

1. **The revocation store** (`common/revocation.py`) is a local JSON file.
   Multiple Gateway instances on different hosts would each have their own
   view of what's revoked unless they share a filesystem (e.g., an NFS
   mount) or the store is swapped for something like Redis. Swapping the
   storage backend is a small, contained change (the module's public
   interface -- `revoke()` / `is_revoked()` -- wouldn't need to change),
   but hasn't been done in this revision; noted here rather than silently
   assumed away.
2. **The audit log's hash chain** (`common/audit_log.py`) assumes a single
   writer appending to one file in order -- concurrent writers on separate
   hosts would need either a shared append-only store or a per-instance
   chain that gets merged/reconciled, neither of which is implemented
   here.

The IdP is harder to scale out as-is: `idp/device_registry.py` (device
enrollment/challenges) and `common/rate_limiter.py` (login lockout state)
are both in-memory per-process. Multiple IdP instances would each have a
different view of "is this device enrolled" / "is this account locked
out." Moving both to a shared store (Redis, or a small database) is the
natural next step if IdP HA is required -- scoped out of this revision
along with the revocation-store change above, for the same reason: doing
it without a real multi-host environment to test failover against would
produce unverified code, and this project's whole ethos (see
`docs/DEVICE_ATTESTATION.md` Section 4) is not shipping unverified claims
as if they were tested results.
