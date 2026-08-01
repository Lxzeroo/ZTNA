"""
Minimal internal Certificate Authority for PyZTNA (this hardening
revision -- see docs/HARDENING.md).

The original design generated ONE ad-hoc self-signed cert per service by
shelling out to the openssl CLI, which meant every service's cert was
independently untrusted -- clients had to run with TLS verification
disabled (`verify=False`) everywhere, and there was no way to distinguish
"a real PyZTNA service" from "anything presenting a self-signed cert" at
the TLS layer.

This module replaces that with a proper (if minimal) two-tier trust model:
one root CA key+cert generated once (certs/ca/), and every service gets
its OWN leaf certificate signed BY that CA. This unlocks two things the
original design couldn't do:

  1. A client that trusts the CA cert can verify the IdP/Gateway's identity
     for real instead of disabling verification.
  2. Mutual TLS: docs-app/finance-app can require that the CONNECTING
     client also present a certificate signed by the same CA, which is
     what actually enforces "only the Gateway may reach these resources"
     at the TLS layer -- see resources/docs_app.py, resources/finance_app.py,
     gateway/gateway_server.py.

Uses the `cryptography` library (already a required dependency) rather
than shelling out to openssl -- this also removes the "install OpenSSL for
Windows" step from docs/WINDOWS_SETUP.md that the original design needed.
"""
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from common.config import CA_DIR, CA_KEY_PATH, CA_CERT_PATH, SERVICE_CERT_DIR

_ONE_DAY = datetime.timedelta(days=1)


def _generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


def ensure_ca() -> None:
    """Generate the root CA keypair+cert if it doesn't exist yet. Idempotent."""
    os.makedirs(CA_DIR, exist_ok=True)
    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        return

    key = _generate_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "PyZTNA Internal CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyZTNA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - _ONE_DAY)
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )

    with open(CA_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    try:
        os.chmod(CA_KEY_PATH, 0o600)
    except Exception:
        pass
    with open(CA_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _load_ca():
    ensure_ca()
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return ca_key, ca_cert


def issue_cert(name: str, dns_names=None, is_client: bool = False) -> tuple:
    """Issue (or reuse) a leaf cert signed by the internal CA for `name`.
    `is_client=True` marks it for client authentication (mTLS) rather than
    server authentication -- used for the Gateway's client identity when
    calling docs-app/finance-app. Returns (key_path, cert_path)."""
    os.makedirs(SERVICE_CERT_DIR, exist_ok=True)
    key_path = os.path.join(SERVICE_CERT_DIR, f"{name}_key.pem")
    cert_path = os.path.join(SERVICE_CERT_DIR, f"{name}_cert.pem")
    if os.path.exists(key_path) and os.path.exists(cert_path):
        return key_path, cert_path

    ca_key, ca_cert = _load_ca()
    key = _generate_key()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyZTNA"),
    ])

    san_entries = [x509.DNSName("localhost")]
    for dn in (dns_names or []):
        san_entries.append(x509.DNSName(dn))
    san_entries.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    eku = ExtendedKeyUsageOID.CLIENT_AUTH if is_client else ExtendedKeyUsageOID.SERVER_AUTH

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - _ONE_DAY)
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key_path, cert_path
