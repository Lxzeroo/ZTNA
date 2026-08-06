# Key Rotation Runbook

## Why this document exists

This project already demonstrated, by accident, why rotation needs to be a
procedure rather than an event.

Five service private keys were committed to git history in an earlier
revision:

```
certs/services/{idp,gateway,docs-app,finance-app,ztna-gateway-client}_key.pem
```

They remain recoverable from commit `700c7ec`, which is on the public
`origin/main`. They are inert **today** only because the internal CA was
regenerated at some later point, so certificates signed by the old CA no
longer validate against the current one. Verify that for yourself:

```bash
git show 700c7ec:certs/services/ztna-gateway-client_cert.pem > /tmp/leaked.pem
openssl verify -CAfile certs/ca/ca_cert.pem /tmp/leaked.pem
# -> certificate signature failure
```

Nobody planned that outcome. The exposure was closed by luck, and luck is
not a control. Had the CA not been regenerated, the leaked
`ztna-gateway-client` key would still authenticate to `docs-app` and
`finance-app` over mTLS — which is precisely the control that makes
"only the Gateway may reach these resources" true.

The most important consequence: **the leaked keys are still public.** If you
ever restore an old CA from `certs/archive/`, you re-arm them.

## What key material exists

| Material | Path | Rotation cost | Blast radius if leaked |
|---|---|---|---|
| Internal CA key | `certs/ca/ca_key.pem` | High — every service cert must be reissued | Total. An attacker can mint a client cert and reach every protected resource. |
| Service TLS keys | `certs/services/*_key.pem` | Low — reissue + restart | That service can be impersonated. The `ztna-gateway-client` key is the worst: it *is* the mTLS identity that resource servers trust. |
| JWT signing keypair | `certs/jwt_keys/jwt_private.pem` | Medium — invalidates live tokens | Total. An attacker can forge any token, for any user, with any role and trust score. |
| Device attestation keys | TPM (Windows) or `certs/device_keys/` | Per device, re-enroll | That one device can be impersonated. TPM-backed keys are non-exportable and cannot leak this way. |

The JWT private key and the CA key are the two that end the game. Neither has
ever been committed — confirmed by scanning every reachable commit:

```bash
git log --all --name-only --pretty=format: | sort -u | grep -E 'ca_key|jwt_private'
# -> (no output)
```

## Scheduled rotation

Check status at any time:

```bash
python -m tools.rotate_keys --check
```

Recommended cadence:

| Material | Cadence | Rationale |
|---|---|---|
| Service certs | 90 days | Default validity (`ZTNA_SERVICE_CERT_VALIDITY_DAYS`). Frequent enough that the procedure stays exercised. |
| JWT keypair | 180 days | With a 45s token TTL, rotation costs a 45-second window. There is no reason to hold a signing key for years. |
| Internal CA | 825 days | Matches the CA/Browser Forum limit. Plan it; do not discover it. |

`common/preflight.py` warns at startup when anything is within
`ZTNA_CERT_EXPIRY_WARN_DAYS` (default 21) of expiry, and refuses to start on
an already-expired certificate. That refusal is deliberate: an expired CA
otherwise surfaces as an opaque TLS handshake error at request time, which
is a miserable thing to debug under pressure.

### Rotating service certificates

```bash
python -m tools.rotate_keys --what service-certs
# restart all services
```

Old material is archived to `certs/archive/<timestamp>-service-certs/`, so a
botched rotation can be backed out.

### Rotating the JWT keypair

```bash
python -m tools.rotate_keys --what jwt
# restart the IdP and Gateway
```

Every live access token becomes invalid immediately — they were signed by
the old private key. Clients simply log in again. Multi-host deployments
must redistribute the **public** key to the Gateway:

```bash
python -m tools.provision_certs --host gateway
```

Note the Gateway receives only the public key. Preflight warns if it finds a
private key on a Gateway host, because that quietly undoes the entire reason
RS256 replaced HS256.

### Rotating the CA

The disruptive one. Every service certificate must be reissued from the new
CA, and mTLS fails until every service has restarted with its new cert.

```bash
python -m tools.rotate_keys --what ca
# multi-host: python -m tools.provision_certs --host <name>   (for each host)
# then restart ALL services
```

On a multi-host deployment, distribute the new bundles **before** restarting
anything, or you will have a mixed fleet where half trusts the old CA.

## Emergency: suspected compromise

Assume the key is being used right now. Order matters.

1. **Revoke live sessions first.** Rotation alone does not kill tokens
   already issued.
   ```bash
   python -m tools.revoke_token --user <username>      # specific user
   python -m tools.manage_devices --revoke <device_id> # device + its tokens
   ```

2. **Rotate the compromised material**, per the sections above. If you do
   not know *which* key leaked, rotate the CA — it implies everything else.

3. **Preserve the evidence before it ages out.**
   ```bash
   python -m tools.backup_audit_log --backup
   python -m tools.verify_audit_log
   ```
   Do this early. The audit log is the only forensic record, and a hash
   chain proves nothing if the file is gone.

4. **Re-approve devices.** After a CA rotation, confirm the device registry
   still reflects reality:
   ```bash
   python -m tools.manage_devices --list
   ```

5. **If the material reached a public repository**, rotation is necessary
   but not sufficient — the key is public forever. Purge it from history so
   it cannot be revived:
   ```bash
   pip install git-filter-repo
   git filter-repo --path certs/ --invert-paths
   git push --force --all
   ```
   This rewrites published history. Every collaborator must re-clone.
   Coordinate first. Note that forks and GitHub's cached views may retain
   the blobs regardless, which is why rotation — not deletion — is the
   control that actually matters.

## Preventing recurrence

`tools/check_no_secrets.py` fails CI if key material is ever tracked by git
again. It checks both filename patterns and file content, respects
`.gitignore` so locally generated keys do not create noise, and runs as the
`secrets-guard` job in `.github/workflows/ci.yml`.

```bash
python -m tools.check_no_secrets          # tracked files
python -m tools.check_no_secrets --all    # working tree too
```

## What is still not solved

- **No automated rotation.** Every path above is a human running a command.
  A production deployment would drive this from cert-manager, ACME, or a
  cloud KMS with scheduled rotation.
- **No key versioning / overlap window.** JWT rotation is a hard cutover;
  there is no period where tokens signed by the old *and* new key both
  verify. Publishing a JWKS with a `kid` per key would allow zero-downtime
  rotation. This is the single highest-value improvement to this area.
- **Archived keys stay on the same host.** `certs/archive/` is a rollback
  convenience, not secure storage. Real deployments put retired key material
  in a vault or destroy it.
- **No hardware protection for the CA or JWT keys.** Both sit on disk as
  PEM files. An HSM or cloud KMS would make them non-exportable, the way the
  device attestation keys already are on TPM-equipped Windows hosts.
