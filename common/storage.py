"""
Pluggable state backend.

Why this exists
---------------
Three pieces of PyZTNA state are read or written on the request path:

  * revocation list      (common/revocation.py)
  * login failure counts (common/rate_limiter.py)
  * issued-token index   (common/token_store.py)
  * device registry      (idp/device_registry.py)

Each grew its own storage strategy for locally sound reasons -- the
revocation list went to a file so a separate CLI process could write to it,
the rate limiter stayed in memory to avoid a disk write per failed login.
Both choices are correct for a single instance and both break the moment a
second instance exists:

  * in-memory rate limiting means an attacker rotating across N IdP
    instances gets N times the allowed attempts;
  * file-backed revocation means a token revoked on host A is still
    accepted by the Gateway on host B.

This module puts one interface in front of that state so the storage
decision becomes a deployment choice rather than something welded into each
module. The default backend preserves today's exact behaviour, so nothing
changes for the single-host demo.

Backends
--------
  memory  -- process-local dict. Fastest, no durability, no sharing.
  file    -- JSON on local disk, atomic replace, cross-process on one host.
             The default, and what the demo has always effectively used.
  redis   -- NOT IMPLEMENTED. The interface below is deliberately shaped so
             it can be written without touching callers: every operation is
             a key/value get-set-delete or a small atomic counter, which is
             what a Redis (or DynamoDB, or Postgres) backend would need.
             See docs/HARDENING.md before implementing -- a shared backend
             changes the failure model, and the fail-open/fail-closed
             decision has to be made explicitly rather than inherited.

Select with ZTNA_STATE_BACKEND=memory|file (default file).
"""
import json
import os
import threading
import time

_lock = threading.RLock()


def atomic_write_json(path: str, data) -> None:
    """Write JSON to `path` atomically, retrying transient Windows locks.

    Shared by every JSON state file in the project (this backend,
    common/revocation.py, common/token_store.py) so the cloud-sync
    workaround exists in exactly one place. See FileBackend._save for why
    the retry is necessary.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)

    delay = 0.02
    last_error = None
    for _ in range(6):
        try:
            os.replace(tmp, path)
            return
        except PermissionError as e:  # WinError 5 / 32 -- sync client holds the file
            last_error = e
            time.sleep(delay)
            delay *= 2
        except OSError as e:
            last_error = e
            break

    try:
        os.remove(tmp)
    except OSError:
        pass

    raise OSError(
        f"Could not atomically update {path} after several attempts: {last_error}. "
        f"On Windows this is usually a cloud-sync client (OneDrive, Dropbox, "
        f"Google Drive) holding the file open. Move the project outside the synced "
        f"folder, exclude it from syncing, or point ZTNA_STATE_DIR at a local path "
        f"such as %LOCALAPPDATA%\\pyztna\\state."
    ) from last_error


class StorageBackend:
    """Minimal key/value contract. Values must be JSON-serialisable."""

    def get(self, namespace: str, key: str, default=None):
        raise NotImplementedError

    def set(self, namespace: str, key: str, value) -> None:
        raise NotImplementedError

    def delete(self, namespace: str, key: str) -> None:
        raise NotImplementedError

    def all(self, namespace: str) -> dict:
        raise NotImplementedError

    def replace_namespace(self, namespace: str, mapping: dict) -> None:
        raise NotImplementedError

    def health(self) -> tuple:
        """Returns (ok: bool, detail: str). Used by /ready so a service with
        an unusable state store reports unready instead of failing later on
        the request path."""
        raise NotImplementedError


class MemoryBackend(StorageBackend):
    def __init__(self):
        self._data = {}

    def get(self, namespace, key, default=None):
        with _lock:
            return self._data.get(namespace, {}).get(key, default)

    def set(self, namespace, key, value):
        with _lock:
            self._data.setdefault(namespace, {})[key] = value

    def delete(self, namespace, key):
        with _lock:
            self._data.get(namespace, {}).pop(key, None)

    def all(self, namespace):
        with _lock:
            return dict(self._data.get(namespace, {}))

    def replace_namespace(self, namespace, mapping):
        with _lock:
            self._data[namespace] = dict(mapping)

    def health(self):
        return True, "memory backend (process-local; not shared across instances)"


class FileBackend(StorageBackend):
    """One JSON file per namespace, written via atomic replace.

    Atomic replace (os.replace) matters more than it looks: without it a
    crash mid-write leaves a truncated revocation list, and a revocation
    list that fails to parse is indistinguishable from an empty one --
    i.e. a crash would silently un-revoke every token. _load() treating a
    corrupt file as empty is the same hazard, so it is logged loudly rather
    than swallowed.
    """

    def __init__(self, directory: str):
        self.directory = directory
        os.makedirs(self.directory, exist_ok=True)

    def _path(self, namespace: str) -> str:
        safe = "".join(c for c in namespace if c.isalnum() or c in "-_")
        return os.path.join(self.directory, f"{safe}.json")

    def _load(self, namespace: str) -> dict:
        path = self._path(namespace)
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError) as e:
            # Loud, because "treat as empty" is a security-relevant
            # degradation for the revocation namespace specifically.
            print(f"[storage] WARNING: {path} unreadable ({e}); treating as empty. "
                  f"If this is the revocation namespace, previously-revoked "
                  f"tokens are no longer being rejected.")
            return {}

    def _save(self, namespace: str, data: dict) -> None:
        """Write a namespace atomically, retrying transient Windows locks.

        os.replace() is atomic on both POSIX and Windows, which is what makes
        a crash mid-write safe. On Windows it can nonetheless fail with
        PermissionError (WinError 5 / WinError 32) when *another process*
        holds the destination open -- and cloud sync clients do exactly that,
        briefly, whenever they notice a file change. OneDrive, Dropbox and
        Google Drive all cause this, and a project checked out inside a synced
        folder hits it constantly.

        The failure is transient by nature: the sync client releases the
        handle within milliseconds. So retry with a short backoff rather than
        propagating, because the alternative is a request path that fails at
        random for reasons that have nothing to do with the request. Only
        after exhausting the retries do we raise, with an error that names the
        real cause instead of leaving the caller to guess at "Access is
        denied".
        """
        atomic_write_json(self._path(namespace), data)

    def get(self, namespace, key, default=None):
        with _lock:
            return self._load(namespace).get(key, default)

    def set(self, namespace, key, value):
        with _lock:
            data = self._load(namespace)
            data[key] = value
            self._save(namespace, data)

    def delete(self, namespace, key):
        with _lock:
            data = self._load(namespace)
            if key in data:
                del data[key]
                self._save(namespace, data)

    def all(self, namespace):
        with _lock:
            return self._load(namespace)

    def replace_namespace(self, namespace, mapping):
        with _lock:
            self._save(namespace, dict(mapping))

    def health(self):
        probe_key = "__health__"
        try:
            self.set("_healthcheck", probe_key, time.time())
            self.delete("_healthcheck", probe_key)
            return True, f"file backend at {self.directory} (single host only)"
        except OSError as e:
            return False, f"file backend unwritable at {self.directory}: {e}"


_backend = None


def get_backend() -> StorageBackend:
    global _backend
    if _backend is None:
        from common.config import STATE_BACKEND, STATE_DIR
        kind = (STATE_BACKEND or "file").lower()
        if kind == "memory":
            _backend = MemoryBackend()
        elif kind == "file":
            _backend = FileBackend(STATE_DIR)
        else:
            raise ValueError(
                f"Unknown ZTNA_STATE_BACKEND={kind!r}. Supported: 'file', 'memory'. "
                f"'redis' is described in common/storage.py but not implemented."
            )
    return _backend


def set_backend(backend: StorageBackend) -> None:
    """Test hook -- lets a test swap in a MemoryBackend without touching disk."""
    global _backend
    _backend = backend


def reset_backend() -> None:
    global _backend
    _backend = None
