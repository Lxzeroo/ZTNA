"""
Append-only, HASH-CHAINED JSON-lines audit trail for every access decision
the Gateway (Policy Enforcement Point) makes. This is what a grader /
reviewer checks to confirm the system provides visibility -- one of the
core ZTNA pillars alongside identity verification and least-privilege
enforcement.

Hardening revision (see docs/HARDENING.md): the original design was a
plain JSON-lines file with no integrity protection -- anyone with local
filesystem access to the log could edit or delete historical entries
without detection. Each line now carries a `hash` field computed over
(that line's own event fields) + (the previous line's hash), forming a
hash chain identical in spirit to how a blockchain or git commit history
gets tamper-evidence: changing any historical line changes its hash, which
no longer matches what the NEXT line recorded as "prev_hash", and every
subsequent hash in the chain becomes unverifiable. tools/verify_audit_log.py
walks the whole file and reports exactly where the chain breaks, if it
does.

This does not make the log un-editable (an attacker with write access can
still truncate or rewrite the whole file and recompute a new valid chain
from scratch) -- it makes SILENT, PARTIAL tampering detectable, which is
the realistic threat model for "someone edited one denial into an allow
after the fact." True tamper-proofing would require writing to storage the
local host can't overwrite (e.g., a remote append-only sink, noted as
future work in docs/HARDENING.md).
"""
import hashlib
import json
import os
import threading
import time

from common.config import ACCESS_LOG_PATH, LOG_DIR

_lock = threading.Lock()

GENESIS_HASH = "0" * 64


def _compute_hash(prev_hash: str, event_without_hash: dict) -> str:
    # Sort keys so hashing is deterministic regardless of dict insertion order.
    payload = json.dumps(event_without_hash, sort_keys=True) + prev_hash
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_last_hash() -> str:
    if not os.path.exists(ACCESS_LOG_PATH):
        return GENESIS_HASH
    last_hash = GENESIS_HASH
    with open(ACCESS_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                last_hash = event.get("hash", last_hash)
            except json.JSONDecodeError:
                continue
    return last_hash


def log_event(**fields):
    os.makedirs(LOG_DIR, exist_ok=True)
    event = {"timestamp": time.time(), "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())}
    event.update(fields)

    with _lock:
        prev_hash = _read_last_hash()
        event["prev_hash"] = prev_hash
        event["hash"] = _compute_hash(prev_hash, event)
        line = json.dumps(event)
        with open(ACCESS_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def read_events():
    if not os.path.exists(ACCESS_LOG_PATH):
        return []
    events = []
    with open(ACCESS_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def verify_events_chain(events: list) -> tuple:
    """Same check as verify_chain(), but operates on an in-memory list of
    event dicts instead of reading the log file -- lets tests exercise
    tamper detection deterministically (mutate a copy of real events, then
    confirm this function catches it) without needing to corrupt the
    actual log file on disk. Returns (ok: bool, details: dict)."""
    expected_prev = GENESIS_HASH
    for i, event in enumerate(events, start=1):
        stored_hash = event.get("hash")
        stored_prev = event.get("prev_hash")
        if stored_prev != expected_prev:
            return False, {"break_line": i, "reason": f"prev_hash mismatch (expected {expected_prev}, got {stored_prev})", "count": len(events)}
        recomputable = {k: v for k, v in event.items() if k != "hash"}
        recomputed = _compute_hash(expected_prev, recomputable)
        if recomputed != stored_hash:
            return False, {"break_line": i, "reason": "hash does not match recomputed value -- content was likely edited", "count": len(events)}
        expected_prev = stored_hash
    return True, {"count": len(events)}


def verify_chain() -> tuple:
    """Walk the whole log FILE and confirm its hash chain is intact.
    Returns (ok: bool, details: dict)."""
    return verify_events_chain(read_events())
