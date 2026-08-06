"""
Explicit token revocation (this hardening revision -- see docs/HARDENING.md).

The original design relied solely on the short (45s) token TTL to bound
the damage of a compromised session -- documented as a known limitation
("no explicit token revocation list"). This module adds an actual
revocation store so a specific token, or every currently-live token for a
specific user, can be killed immediately rather than waiting out the TTL.

File-based (JSON) rather than in-memory because the Gateway and the
`tools/revoke_token.py` CLI run as SEPARATE processes -- an in-memory set
in the Gateway process would never see a revocation issued from a CLI
invocation. This mirrors how the audit log already works
(common/audit_log.py) and keeps the "no external services required"
philosophy of the project intact (no Redis needed for the classroom
scale this is built for -- see docs/HARDENING.md "known remaining gaps"
for the HA/multi-instance follow-up this implies).
"""
import json
import os
import threading
import time

from common.config import REVOCATION_LIST_PATH, LOG_DIR

_lock = threading.Lock()


def _load() -> dict:
    if not os.path.exists(REVOCATION_LIST_PATH):
        return {}
    try:
        with open(REVOCATION_LIST_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    # Uses the shared atomic writer so the cloud-sync retry (OneDrive et al.
    # briefly lock files, making os.replace fail with WinError 5) lives in
    # one place -- see common/storage.py:atomic_write_json. Losing a write
    # here means a revoked token stays usable, so it is worth retrying.
    from common.storage import atomic_write_json
    os.makedirs(LOG_DIR, exist_ok=True)
    atomic_write_json(REVOCATION_LIST_PATH, data)


def revoke(jti: str, exp: float = None, reason: str = "manual_revocation") -> None:
    """Mark a token id as revoked. `exp` (unix timestamp) lets cleanup()
    drop the entry once the token would have expired naturally anyway --
    if not supplied, keeps it for LOGIN 24h as a safe default."""
    with _lock:
        data = _load()
        data[jti] = {
            "revoked_at": time.time(),
            "expires_at": exp if exp is not None else time.time() + 86400,
            "reason": reason,
        }
        _save(data)


def is_revoked(jti: str) -> bool:
    if not jti:
        return False
    with _lock:
        data = _load()
    return jti in data


def cleanup_expired() -> int:
    """Drop revocation entries whose underlying token would have expired
    anyway -- keeps the file from growing unbounded. Returns count removed."""
    now = time.time()
    with _lock:
        data = _load()
        before = len(data)
        data = {k: v for k, v in data.items() if v.get("expires_at", 0) > now}
        _save(data)
        return before - len(data)
