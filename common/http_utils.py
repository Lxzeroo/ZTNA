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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class JSONRequestHandler(BaseHTTPRequestHandler):
    """Subclass and define `routes = {("METHOD", "/path"): handler_name}`.

    Each handler is called as `self.handler_name(params: dict, body: dict) -> (status, dict)`
    where `params` contains any `{name}` path segments captured by the route,
    and `body` is the parsed JSON request body (empty dict if none/invalid).
    """

    routes = {}          # {("GET", "/access/{resource}"): "handle_access"}
    server_version = "PyZTNA/2.0"

    def log_message(self, fmt, *args):
        # Quiet the default stderr access log; each service does its own
        # structured logging where it matters (see gateway audit log).
        pass

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
        path = self.path.split("?", 1)[0]
        handler_name, params = self._match_route(method, path)
        if handler_name is None:
            self._send_json(404, {"error": "not_found", "path": path})
            return
        body = self._read_json_body() if method in ("POST", "PUT") else {}
        handler = getattr(self, handler_name)
        try:
            status, payload = handler(params, body)
        except Exception as e:  # noqa: BLE001
            status, payload = 500, {"error": "internal_error", "detail": str(e)}
        self._send_json(status, payload)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


def serve(handler_cls, host: str, port: int, use_tls: bool = True,
          service_name: str = None, require_client_cert: bool = False,
          cert_sans=None):
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

    httpd = ThreadingHTTPServer((host, port), handler_cls)
    scheme = "http"
    if use_tls:
        name = service_name or handler_cls.__name__.replace("Handler", "").lower()
        wrap_server_socket(httpd, name, require_client_cert=require_client_cert,
                           cert_sans=cert_sans)
        scheme = "https"

    mtls_note = " (mTLS client cert required)" if require_client_cert else ""
    print(f"[{handler_cls.__name__}] listening on {scheme}://{host}:{port}{mtls_note}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
