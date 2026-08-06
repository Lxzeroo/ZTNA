"""
Lightweight record of recently-issued token ids per user (this hardening
revision -- see docs/HARDENING.md).

Purely to support "revoke every session currently open for user X"
(`tools/revoke_token.py --user bob`) without needing a full session
database -- the IdP appends {jti, username, exp} on every successful
login; the revoke CLI reads this file, finds every jti for that username
that hasn't expired yet, and revokes each one via common/revocation.py.

Entries are pruned of anything already expired whenever a new one is
recorded, so this file stays small under normal operation.
"""
import json
import os
import threading
import time

from common.config import ISSUED_TOKENS_PATH, LOG_DIR

_lock = threading.Lock()


def _load() -> list:
    if not os.path.exists(ISSUED_TOKENS_PATH):
        return []
    try:
        with open(ISSUED_TOKENS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save(records: list) -> None:
    # Shared atomic writer -- see common/storage.py:atomic_write_json for the
    # Windows cloud-sync locking problem it works around.
    from common.storage import atomic_write_json
    os.makedirs(LOG_DIR, exist_ok=True)
    atomic_write_json(ISSUED_TOKENS_PATH, records)


def record_issued(jti: str, username: str, exp: float, device_id: str = None) -> None:
    now = time.time()
    with _lock:
        records = _load()
        records = [r for r in records if r.get("exp", 0) > now]  # prune expired
        records.append({"jti": jti, "username": username, "exp": exp,
                        "issued_at": now, "device_id": device_id})
        _save(records)


def active_jtis_for_user(username: str) -> list:
    now = time.time()
    with _lock:
        records = _load()
    return [r["jti"] for r in records if r.get("username") == username and r.get("exp", 0) > now]


def active_jtis_for_device(device_id: str) -> list:
    """Live token ids issued to a specific device.

    Needed so revoking a device (tools/manage_devices.py --revoke) can also
    kill its in-flight sessions. Blocking a stolen laptop from logging in
    again while its current token keeps working for another 45 seconds is
    not much of a revocation.
    """
    now = time.time()
    with _lock:
        records = _load()
    return [r["jti"] for r in records
            if r.get("device_id") == device_id and r.get("exp", 0) > now]


def load_all() -> list:
    """All non-expired issued-token records."""
    now = time.time()
    with _lock:
        records = _load()
    return [r for r in records if r.get("exp", 0) > now]
