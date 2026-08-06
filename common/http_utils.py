"""
Small stdlib-only JSON HTTP server toolkit shared by the Identity Provider,
Gateway, and protected resource apps.

Deliberately built on `http.server` (Python standard library) rather than
Flask/FastAPI so the whole project runs on a bare Windows Python install
with a minimal dependency list -- no virtualenv-breaking native build
steps, no version drift between components. In a real deployment, put a
reverse proxy (see deploy/nginx.conf, deploy/Caddyfile -- added in this
hardening revision) in front for request-size limits and edge rate
limiting that a full framework/WAF would otherwise provide.
"""
import json
import os
import signal
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from common import obs
from common.config import SHUTDOWN_GRACE_SECONDS, CORRELATION_HEADER


class _ServiceState:
    """Liveness/readiness state for the process.

    The distinction matters to a load balancer and is not cosmetic:

      live  -- the process is running and its event loop responds. If this
               goes false the orchestrator should RESTART the container.
      ready -- the process can correctly serve requests right now. If this
               goes false the load balancer should stop SENDING traffic but
               must NOT restart: the process may be draining on purpose, or
               waiting on a dependency that is itself recovering.

    Conflating them causes restart storms during a dependency outage --
    every instance fails its healthcheck, every instance gets killed, and
    the dependency now also has a thundering-herd reconnect problem.
    """

    def __init__(self, service_name):
        self.service_name = service_name
        self.started_at = time.time()
        self.live = True
        self.ready = False          # flipped true once serving begins
        self.draining = False
        self.inflight = 0
        self._lock = threading.Lock()

    def enter_request(self):
        with self._lock:
            self.inflight += 1

    def exit_request(self):
        with self._lock:
            self.inflight = max(0, self.inflight - 1)

    def readiness(self):
        """Returns (ready: bool, detail: dict)."""
        checks = {}
        ok = self.ready and not self.draining

        if self.draining:
            checks["draining"] = "shutting down; not accepting new work"

        try:
            from common.storage import get_backend
            store_ok, store_detail = get_backend().health()
            checks["state_store"] = store_detail
            ok = ok and store_ok
        except Exception as e:  # noqa: BLE001
            checks["state_store"] = f"unavailable: {e}"
            ok = False

        return ok, {
            "service": self.service_name,
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "inflight_requests": self.inflight,
            "checks": checks,
        }


class _ExclusiveThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that refuses to share a port.

    `http.server.HTTPServer` sets `allow_reuse_address = 1`, which means
    SO_REUSEADDR. On Unix that only permits rebinding a socket stuck in
    TIME_WAIT -- harmless and convenient. On Windows it means something
    materially different: a socket may bind to a port that is *actively in
    use* by another process, and which of the two receives any given
    incoming connection is not defined.

    The practical consequence, observed on real hardware: a service left
    running by an interrupted test run keeps port 9000. The next run starts
    a fresh IdP, which binds "successfully", and requests are then split
    arbitrarily between the new process and the stale one. Some requests are
    served correctly, others hit the old process and hang. The symptom is an
    intermittent timeout that looks like a network fault and is reproducible
    only by accident.

    Refusing the bind converts that into an immediate, obvious error naming
    the real problem. A port collision should never be silent in a system
    whose whole job is enforcing a single point of policy.
    """

    # Unix keeps SO_REUSEADDR (TIME_WAIT rebinding is genuinely useful and
    # safe there); Windows must not, for the reason above.
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt":
            # Belt and braces: SO_EXCLUSIVEADDRUSE makes the exclusivity
            # explicit rather than relying on the absence of SO_REUSEADDR.
            exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
            if exclusive is not None:
                try:
                    self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)
                except OSError:
                    pass
        super().server_bind()


class JSONRequestHandler(BaseHTTPRequestHandler):
    """Subclass and define `routes = {("METHOD", "/path"): handler_name}`.

    Each handler is called as `self.handler_name(params: dict, body: dict) -> (status, dict)`
    where `params` contains any `{name}` path segments captured by the route,
    and `body` is the parsed JSON request body (empty dict if none/invalid).

    `/health` and `/ready` are provided automatically to every service unless
    a subclass defines its own route for them.
    """

    routes = {}          # {("GET", "/access/{resource}"): "handle_access"}
    server_version = "PyZTNA/2.1"
    service_state = None  # injected by serve()

    def log_message(self, fmt, *args):
        # Quiet the default stderr access log; each service does its own
        # structured logging where it matters (see gateway audit log).
        pass

    # --- built-in operational endpoints -------------------------------

    def _builtin_health(self):
        state = self.service_state
        if state is None:
            return 200, {"status": "ok"}
        return (200 if state.live else 503), {
            "status": "ok" if state.live else "unhealthy",
            "service": state.service_name,
            "uptime_seconds": round(time.time() - state.started_at, 1),
        }

    def _builtin_ready(self):
        state = self.service_state
        if state is None:
            return 200, {"status": "ready"}
        ready, detail = state.readiness()
        detail["status"] = "ready" if ready else "not_ready"
        return (200 if ready else 503), detail

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Echo the correlation id so a client (and anything reading a packet
        # capture or proxy log) can tie its request to our logs.
        self.send_header(CORRELATION_HEADER, obs.get_correlation_id())
        self.end_headers()
        self.wfile.write(body)

    def _match_route(self, method: str, path: str):
        """Very small path matcher supporting a single {token} segment."""
        for (m, pattern), handler_name in self.routes.items():
            if m != method:
                continue
            p_parts = pattern.strip("/").split("/")
            u_parts = path.strip("/").split("/")
            if len(p_parts) != len(u_parts):
                continue
            params = {}
            ok = True
            for pp, up in zip(p_parts, u_parts):
                if pp.startswith("{") and pp.endswith("}"):
                    params[pp[1:-1]] = up
                elif pp != up:
                    ok = False
                    break
            if ok:
                return handler_name, params
        return None, None

    def _dispatch(self, method: str):
        # Adopt the caller's correlation id if it sent one, otherwise mint a
        # new one. Either way every log line from this thread now carries it.
        obs.set_correlation_id(self.headers.get(CORRELATION_HEADER, ""))
        state = self.service_state
        service = state.service_name if state else "service"
        started = time.time()
        if state:
            state.enter_request()

        try:
            path = self.path.split("?", 1)[0]

            # Operational endpoints are served even while draining, so an
            # orchestrator can still observe the shutdown it asked for.
            if method == "GET" and path == "/health" and ("GET", "/health") not in self.routes:
                status, payload = self._builtin_health()
                self._send_json(status, payload)
                return
            if method == "GET" and path == "/ready" and ("GET", "/ready") not in self.routes:
                status, payload = self._builtin_ready()
                self._send_json(status, payload)
                return

            # Refuse new work once draining -- 503 tells a load balancer to
            # retry elsewhere, which is the correct answer during a rollout.
            if state and state.draining:
                self._send_json(503, {"error": "server_shutting_down"})
                return

            handler_name, params = self._match_route(method, path)
            if handler_name is None:
                self._send_json(404, {"error": "not_found", "path": path})
                return

            body = self._read_json_body() if method in ("POST", "PUT") else {}
            handler = getattr(self, handler_name)
            try:
                status, payload = handler(params, body)
            except Exception as e:  # noqa: BLE001
                # Log the real error with the correlation id; return a generic
                # message. Echoing exception text to an unauthenticated caller
                # is an information leak (paths, versions, SQL, key filenames).
                obs.error(service, "unhandled_handler_exception",
                          path=path, method=method, error=repr(e))
                status, payload = 500, {"error": "internal_error",
                                        "correlation_id": obs.get_correlation_id()}
            self._send_json(status, payload)

            # DEBUG, not INFO: one line per request is high volume, and it
            # duplicates the audit log for anything security-relevant. At INFO
            # it also deadlocks any parent that pipes our stdout without
            # draining it -- see the note in common/obs.py:log().
            if path not in ("/health", "/ready"):
                obs.debug(service, "request", method=method, path=path,
                          status=status, duration_ms=round((time.time() - started) * 1000, 1))
        finally:
            if state:
                state.exit_request()
            obs.clear_correlation_id()

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


def serve(handler_cls, host: str, port: int, use_tls: bool = True,
          service_name: str = None, require_client_cert: bool = False,
          cert_sans=None, preflight: bool = True):
    """Start a ThreadingHTTPServer, optionally upgraded to HTTPS in-place.

    `service_name` (this hardening revision) selects which CA-issued
    certificate to serve -- defaults to the handler class name if omitted.
    `require_client_cert=True` enables mTLS: the server refuses any
    connection that doesn't present a client cert signed by the internal
    CA (see common/tls_utils.py, common/ca_utils.py). Used by
    resources/docs_app.py and resources/finance_app.py so that only the
    Gateway (the sole holder of an issued client cert) can connect at all.
    """
    from common.tls_utils import wrap_server_socket

    name = service_name or handler_cls.__name__.replace("Handler", "").lower()

    # Validate configuration BEFORE binding a port. A service that binds
    # first and validates later spends a window advertising itself as
    # available while being unable to do its job.
    if preflight:
        from common.preflight import run_preflight
        run_preflight(name, strict=True)

    state = _ServiceState(name)
    handler_cls.service_state = state

    try:
        httpd = _ExclusiveThreadingHTTPServer((host, port), handler_cls)
    except OSError as e:
        # Fail loudly and specifically. Silently sharing a port with a stale
        # process is far worse than refusing to start -- see the class docstring.
        obs.critical(name, "bind_failed", host=host, port=port, error=str(e))
        raise SystemExit(
            f"\n[{name}] cannot bind {host}:{port} -- {e}\n\n"
            f"Another process is already listening there, most likely a service\n"
            f"left over from an earlier run that was interrupted.\n\n"
            f"Windows:  Get-NetTCPConnection -LocalPort {port} | "
            f"Select-Object OwningProcess\n"
            f"          Stop-Process -Id <pid>\n"
            f"Linux/macOS:  lsof -ti :{port} | xargs kill\n"
        ) from e
    # Let worker threads finish rather than being killed at interpreter exit;
    # this is what makes draining meaningful.
    httpd.daemon_threads = False

    scheme = "http"
    if use_tls:
        wrap_server_socket(httpd, name, require_client_cert=require_client_cert,
                           cert_sans=cert_sans)
        scheme = "https"

    mtls_note = " (mTLS client cert required)" if require_client_cert else ""
    print(f"[{handler_cls.__name__}] listening on {scheme}://{host}:{port}{mtls_note}")
    obs.info(name, "service_started", scheme=scheme, host=host, port=port,
             mtls_required=require_client_cert)

    state.ready = True

    def _drain_and_stop(signum, _frame):
        """Stop accepting new work, let in-flight requests finish, then exit.

        Ordering is the whole point. Flipping `draining` first means /ready
        starts returning 503 immediately, so the load balancer removes this
        instance BEFORE the listener disappears. Closing the socket first
        instead would drop requests already in flight toward us -- the exact
        failure a rolling deploy is supposed to avoid.
        """
        if state.draining:
            return  # second signal: let the default behaviour take over
        state.draining = True
        state.ready = False
        obs.info(name, "shutdown_started", signal=signum,
                 inflight=state.inflight, grace_seconds=SHUTDOWN_GRACE_SECONDS)

        deadline = time.time() + SHUTDOWN_GRACE_SECONDS
        while state.inflight > 0 and time.time() < deadline:
            time.sleep(0.05)

        if state.inflight > 0:
            obs.warning(name, "shutdown_forced",
                        abandoned_requests=state.inflight,
                        detail="grace period expired with requests still in flight")
        else:
            obs.info(name, "shutdown_drained")

        state.live = False
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    for sig_name in ("SIGTERM", "SIGINT", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue  # SIGBREAK is Windows-only; SIGTERM handling varies
        try:
            signal.signal(sig, _drain_and_stop)
        except (ValueError, OSError):
            # Not the main thread (e.g. the test suite starts servers in
            # background threads) -- graceful shutdown is simply unavailable
            # there, which is fine because the test harness stops them directly.
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        _drain_and_stop("KeyboardInterrupt", None)
    finally:
        httpd.server_close()
        obs.info(name, "service_stopped")
