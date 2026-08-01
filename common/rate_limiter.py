"""
Login rate limiting / lockout for the Identity Provider (this hardening
revision -- see docs/HARDENING.md). The original design had no protection
against repeated password/OTP guessing on /login -- documented as a known
limitation.

In-memory (per IdP process) rather than file-based, unlike
common/revocation.py -- the IdP is a single process, so there's no
cross-process visibility problem to solve, and keeping this out of a file
avoids a disk write on every failed login attempt (which would itself be a
mild DoS amplification vector).

Keyed on username only (not username+IP) deliberately: locking a specific
account after repeated failures protects that account regardless of which
source IP the attempts come from (an attacker rotating IPs shouldn't reset
the counter), and it keeps the test suite's account isolation simple (see
tests/test_ztna.py::TestRateLimiting, which uses a disposable username so
it can't lock out alice/bob/carol/admin used by other tests).
"""
import threading
import time

from common.config import LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS, LOGIN_LOCKOUT_SECONDS

_lock = threading.Lock()

# username -> {"failures": [timestamp, ...], "locked_until": float or None}
_state = {}


def _get(username: str) -> dict:
    return _state.setdefault(username, {"failures": [], "locked_until": None})


def is_locked_out(username: str) -> tuple:
    """Returns (locked: bool, retry_after_seconds: float)."""
    with _lock:
        entry = _get(username)
        locked_until = entry["locked_until"]
        if locked_until is None:
            return False, 0.0
        now = time.time()
        if now >= locked_until:
            entry["locked_until"] = None
            entry["failures"] = []
            return False, 0.0
        return True, locked_until - now


def record_failure(username: str) -> None:
    with _lock:
        entry = _get(username)
        now = time.time()
        entry["failures"] = [t for t in entry["failures"] if now - t < LOGIN_WINDOW_SECONDS]
        entry["failures"].append(now)
        if len(entry["failures"]) >= LOGIN_MAX_ATTEMPTS:
            entry["locked_until"] = now + LOGIN_LOCKOUT_SECONDS


def record_success(username: str) -> None:
    """Reset the counter on a successful login -- a legitimate user who
    fat-fingered their password twice shouldn't stay one step from
    lockout forever."""
    with _lock:
        entry = _get(username)
        entry["failures"] = []
        entry["locked_until"] = None


def reset_all() -> None:
    """Test-only helper to reset state between test runs."""
    with _lock:
        _state.clear()
