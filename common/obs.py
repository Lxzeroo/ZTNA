"""
Structured logging and request correlation.

Two problems this solves.

1. The audit log (common/audit_log.py) records *decisions*. It is
   deliberately narrow -- it answers "was this allowed, and why" and is
   hash-chained so that answer is tamper-evident. It is the wrong place for
   operational detail (timings, backend errors, startup warnings), and
   polluting it with that detail would weaken it as evidence.

   So operational events go here instead, as JSON lines on stdout, which is
   what a log shipper (Fluent Bit, Vector, Windows Event Forwarding) expects
   to consume. The audit log stays clean.

2. A single user request currently touches three processes -- agent -> IdP
   for a token, agent -> Gateway, Gateway -> resource over mTLS. When
   something fails there is no way to line those up. Every request now
   carries a correlation id: generated at the edge if absent, echoed in the
   response, and forwarded on the internal hop. One id, one story.

Human-readable output stays the default so the demo console is unchanged;
set ZTNA_JSON_LOGS=1 for machine-readable output.
"""
import json
import os
import sys
import threading
import time
import uuid

from common.config import JSON_LOGS, LOG_LEVEL, CORRELATION_HEADER

_LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
_MIN_LEVEL = _LEVELS.get(LOG_LEVEL, 20)

_write_lock = threading.Lock()

# Correlation id for the request this thread is currently serving. Thread-local
# rather than a parameter because it has to be reachable from deep inside call
# stacks (storage errors, TLS failures) without threading an id through every
# signature. ThreadingHTTPServer gives each request its own thread, so this is
# safe here; an async rewrite would need a contextvar instead.
_local = threading.local()


def new_correlation_id() -> str:
    return uuid.uuid4().hex[:16]


def set_correlation_id(value: str) -> str:
    value = (value or "").strip()[:64] or new_correlation_id()
    _local.correlation_id = value
    return value


def get_correlation_id() -> str:
    return getattr(_local, "correlation_id", None) or "-"


def clear_correlation_id() -> None:
    _local.correlation_id = None


def correlation_header_name() -> str:
    return CORRELATION_HEADER


def log(level: str, service: str, event: str, **fields):
    """Emit one operational log record.

    Never raises -- a logging failure must not take down a request path.

    A note on volume, learned the hard way: per-request logging is emitted at
    DEBUG, not INFO. A parent process that captures a service's stdout through
    a pipe and does not drain it will deadlock the service once the pipe
    buffer fills -- roughly 4 KB on Windows. The service blocks in write() and
    silently stops answering requests, which presents as connection timeouts
    with no error anywhere. Chatty INFO-level output turns that from a
    theoretical hazard into a reliable failure.
    """
    level = level.upper()
    if _LEVELS.get(level, 20) < _MIN_LEVEL:
        return
    try:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
            "level": level,
            "service": service,
            "event": event,
            "correlation_id": get_correlation_id(),
            "pid": os.getpid(),
        }
        record.update(fields)

        if JSON_LOGS:
            line = json.dumps(record, default=str, sort_keys=True)
        else:
            extras = " ".join(
                f"{k}={v}" for k, v in fields.items() if v is not None
            )
            cid = record["correlation_id"]
            line = f"[{service}] {level:<7} {event}" + (f" ({extras})" if extras else "")
            if cid != "-":
                line += f" cid={cid}"

        with _write_lock:
            stream = sys.stderr if _LEVELS.get(level, 20) >= 40 else sys.stdout
            print(line, file=stream, flush=True)
    except Exception:  # noqa: BLE001 - logging must never break the caller
        pass


def debug(service, event, **f):
    log("DEBUG", service, event, **f)


def info(service, event, **f):
    log("INFO", service, event, **f)


def warning(service, event, **f):
    log("WARNING", service, event, **f)


def error(service, event, **f):
    log("ERROR", service, event, **f)


def critical(service, event, **f):
    log("CRITICAL", service, event, **f)
