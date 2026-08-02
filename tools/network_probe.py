#!/usr/bin/env python3
"""
Network probe -- captures the NEGATIVE-CONTROL evidence that a multi-host
PyZTNA deployment actually enforces what it claims.

A demo that only shows successful access proves very little: a system that
allows everything would pass it. The interesting evidence is what is
REFUSED, and specifically that different attempts fail for different,
identifiable reasons at different layers:

  layer 1  network   -- a firewall drops the packet; nothing answers
  layer 2  TLS       -- the port answers but refuses the handshake because
                        no client certificate was presented (mTLS)
  layer 3  policy    -- the handshake succeeds but the Gateway denies the
                        request on role / device-trust / attestation grounds

Three different failures at three different layers is exactly the
defence-in-depth story; one blanket "connection failed" is not.

Run this from EACH machine in the lab -- the expected results differ by
role, which is itself the point:

    # from the client/agent machine (and from a rogue host)
    python -m tools.network_probe --role agent \\
        --gateway-host 192.168.1.11 --resource-host 192.168.1.12 --resource-port 9101

    # from the Gateway machine (the only host holding a client certificate)
    python -m tools.network_probe --role gateway \\
        --gateway-host 192.168.1.11 --resource-host 192.168.1.12 --resource-port 9101

Exit code 0 if every check matched its expected outcome, 1 otherwise.
"""
import argparse
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.config import CA_CERT_PATH, GATEWAY_CLIENT_CERT_CN

TIMEOUT = 4


def _tcp_connect(host, port):
    """Can we open a bare TCP connection at all?"""
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True, f"connected in {1000*(time.time()-t0):.0f} ms"
    except socket.timeout:
        return False, "timed out (consistent with a firewall DROP)"
    except ConnectionRefusedError:
        return False, "connection refused (nothing listening, or a REJECT rule)"
    except OSError as e:
        return False, f"{type(e).__name__}: {e}"


def _tls_connect(host, port, client_cert=None, verify=True, do_io=True):
    """Attempt a TLS handshake, optionally presenting a client certificate.

    IMPORTANT (TLS 1.3): a successful `wrap_socket()` is NOT proof that the
    server accepted us. Under TLS 1.3 the client-certificate exchange happens
    *after* the client considers the handshake finished, so a server that
    requires mTLS will complete the handshake and only then tear the
    connection down -- the rejection surfaces on the first read or write.
    Under TLS 1.2 it failed during the handshake itself.

    This probe therefore performs a real request/response round trip by
    default. Reporting on handshake completion alone would have produced a
    false "allowed" result and, worse, false evidence that mTLS was not being
    enforced when in fact it was.
    """
    try:
        if verify and os.path.exists(CA_CERT_PATH):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(cafile=CA_CERT_PATH)
            ctx.check_hostname = True
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        if client_cert:
            ctx.load_cert_chain(certfile=client_cert[1], keyfile=client_cert[0])

        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                peer = tls.getpeercert()
                cn = ""
                if peer:
                    for rdn in peer.get("subject", ()):
                        for k, v in rdn:
                            if k == "commonName":
                                cn = v
                version = tls.version()

                if do_io:
                    tls.send(b"GET /health HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                             % host.encode())
                    data = tls.recv(64)
                    if not data:
                        return False, ("handshake completed but the server closed the "
                                       "connection without responding -- rejected after "
                                       "TLS 1.3 post-handshake client auth")
                    return True, f"request answered (peer CN={cn or 'unknown'}, {version})"

                return True, f"handshake OK (peer CN={cn or 'unknown'}, {version})"

    except ssl.SSLCertVerificationError as e:
        return False, f"certificate verification failed: {e.verify_message}"
    except ssl.SSLError as e:
        msg = getattr(e, "reason", None) or str(e)
        return False, f"TLS refused: {msg}"
    except (ConnectionResetError, ConnectionAbortedError) as e:
        return False, (f"connection reset after handshake ({type(e).__name__}) -- "
                       f"server required a client certificate we could not supply")
    except socket.timeout:
        return False, "timed out (consistent with a firewall DROP)"
    except OSError as e:
        return False, f"{type(e).__name__}: {e}"


def main():
    ap = argparse.ArgumentParser(description="PyZTNA multi-host enforcement probe")
    ap.add_argument("--role", choices=["agent", "gateway"], default="agent",
                    help="where you are running this from; changes what counts as a PASS")
    ap.add_argument("--gateway-host", required=True)
    ap.add_argument("--gateway-port", type=int, default=9200)
    ap.add_argument("--idp-host")
    ap.add_argument("--idp-port", type=int, default=9000)
    ap.add_argument("--resource-host", required=True)
    ap.add_argument("--resource-port", type=int, default=9101)
    args = ap.parse_args()

    client_cert = None
    if args.role == "gateway":
        try:
            from common import ca_utils
            client_cert = ca_utils.issue_cert(GATEWAY_CLIENT_CERT_CN, is_client=True)
        except Exception as e:  # noqa: BLE001
            print(f"[warn] could not load the Gateway client certificate: {e}")

    checks = []

    ok, note = _tls_connect(args.gateway_host, args.gateway_port)
    checks.append(("Gateway reachable over TLS", ok, True, note,
                   "the single entry point is up and its cert chains to the internal CA"))

    if args.idp_host:
        ok, note = _tls_connect(args.idp_host, args.idp_port)
        checks.append(("IdP reachable over TLS", ok, True, note,
                       "clients can authenticate"))

    ok, note = _tcp_connect(args.resource_host, args.resource_port)
    expect_tcp = (args.role == "gateway")
    checks.append(("Direct TCP to protected resource", ok, expect_tcp, note,
                   "LAYER 1 (network): the firewall should permit only the Gateway host"))

    ok, note = _tls_connect(args.resource_host, args.resource_port, client_cert=None)
    checks.append(("TLS to resource WITHOUT client cert", ok, False, note,
                   "LAYER 2 (mTLS): must fail from every host, including the Gateway"))

    if args.role == "gateway" and client_cert:
        ok, note = _tls_connect(args.resource_host, args.resource_port, client_cert=client_cert)
        checks.append(("TLS to resource WITH client cert", ok, True, note,
                       "LAYER 2 (mTLS): only the Gateway holds a valid client certificate"))

    width = 38
    print()
    print(f"PyZTNA network probe  --  running as: {args.role}")
    print("=" * 100)
    print(f"{'CHECK':<{width}} {'RESULT':<10} {'EXPECTED':<10} VERDICT")
    print("-" * 100)
    failures = 0
    for name, actual, expected, note, why in checks:
        verdict = "PASS" if actual == expected else "UNEXPECTED"
        if actual != expected:
            failures += 1
        a = "allowed" if actual else "blocked"
        e = "allowed" if expected else "blocked"
        print(f"{name:<{width}} {a:<10} {e:<10} {verdict}")
        print(f"{'':<{width}}   {note}")
        print(f"{'':<{width}}   {why}")
        print()
    print("=" * 100)
    if failures:
        print(f"{failures} check(s) did not match expectations -- see docs/MULTI_HOST_LAB.md section 7.")
        sys.exit(1)
    print("All checks matched expectations.")
    print("\nCapture this output for the report: it is the negative-control evidence that")
    print("access is refused at the network layer AND independently at the TLS layer,")
    print("before application policy is even consulted.")
    sys.exit(0)


if __name__ == "__main__":
    main()
