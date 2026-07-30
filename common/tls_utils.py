"""
Self-signed TLS certificate generation so every ZTNA control-plane service
(Identity Provider, Gateway) can serve HTTPS instead of plaintext HTTP.

NIST SP 800-207 (Zero Trust Architecture) requires all communication to be
secured regardless of network location -- "never trust the network". This
module makes that easy to satisfy in the demo: on first run it shells out to
the `openssl` CLI (present on Linux/macOS and available on Windows via Git
for Windows / OpenSSL for Windows) to generate a throwaway self-signed
cert+key pair under certs/. If openssl is not on PATH, services fall back to
plain HTTP and print a warning so the gap is visible rather than silent.
"""
import os
import shutil
import ssl
import subprocess

from common.config import CERT_DIR

CERT_FILE = os.path.join(CERT_DIR, "ztna_selfsigned.crt")
KEY_FILE = os.path.join(CERT_DIR, "ztna_selfsigned.key")


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def ensure_self_signed_cert() -> bool:
    """Generate certs/ztna_selfsigned.{crt,key} if they don't already exist.

    Returns True if a usable cert+key pair exists afterwards, False if TLS
    is unavailable and the caller should fall back to plain HTTP.
    """
    os.makedirs(CERT_DIR, exist_ok=True)
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return True
    if not openssl_available():
        return False
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", KEY_FILE, "-out", CERT_FILE,
        "-days", "365", "-nodes",
        "-subj", "/CN=ztna-demo.local/O=PyZTNA/C=US",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return False
    return os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)


def wrap_server_socket(httpd):
    """Wrap an http.server socket in TLS in-place, if a cert is available.

    Returns True if the server is now HTTPS, False if it remains plain HTTP.
    """
    if not ensure_self_signed_cert():
        return False
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return True
