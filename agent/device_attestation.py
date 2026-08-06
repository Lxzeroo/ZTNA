"""
Device attestation for the ZTNA client agent -- proves possession of a
device-bound private key via challenge-response signing, instead of just
self-reporting a posture score (see agent/device_posture.py, which this
module complements rather than replaces).

Two implementations, selected automatically:

  1. REAL (Windows, TPM-backed): creates an RSA-2048 key pair using the
     "Microsoft Platform Crypto Provider" Key Storage Provider, which
     generates and holds the private key INSIDE the machine's TPM 2.0 chip
     and marks it non-exportable at the CNG level. Signing happens by
     asking the TPM to sign, without the key material ever entering
     process memory in plaintext. This is done by shelling out to
     PowerShell / .NET's X509Certificate2 + RSACertificateExtensions APIs,
     since Python has no first-class TPM/CNG binding on Windows.

  2. FALLBACK (any OS, including this Linux/macOS dev environment): an
     ordinary RSA-2048 key pair generated with the `cryptography` library
     and stored as a local PEM file. This is NOT hardware-backed -- it is
     provided so the enrollment/challenge/signature protocol can be
     developed and tested end-to-end on any machine, and so the system
     degrades to *something* rather than refusing to run on non-Windows or
     non-TPM hardware. Every function that uses this path returns
     hardware_backed=False so callers (and the audit log) can tell the two
     apart -- this distinction is reported honestly, not hidden.

IMPORTANT (documented deliberately for the project report, see
docs/DEVICE_ATTESTATION.md): the Windows/TPM code path below has been
written against the documented .NET/CNG APIs and reviewed carefully, but
could not be executed against a real TPM during development (this project
was built in a Linux sandbox). It MUST be verified on a real Windows 10/11
machine with TPM 2.0 enabled before being cited as a working hardware
attestation result. The fallback path, and the full
enroll -> challenge -> sign -> verify -> policy-gate protocol around it,
HAS been fully tested end to end (see tests/test_ztna.py).
"""
import base64
import os
import platform
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

FALLBACK_KEY_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "certs", "device_keys"
)
_DEVICE_ID_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "certs", "device_id.txt"
)

# Set ZTNA_ATTESTATION_DEBUG=1 to see the raw PowerShell output when the
# TPM path fails. Without this the failure is silent (it degrades to a
# software key), which made a real .NET API-compatibility bug very hard to
# diagnose -- see docs/DEVICE_ATTESTATION.md Section 4.
_DEBUG = os.environ.get("ZTNA_ATTESTATION_DEBUG", "") not in ("", "0", "false", "False")


def _debug(msg):
    if _DEBUG:
        print(f"[attestation:debug] {msg}")


def get_local_device_id() -> str:
    """Return this machine's persistent device identifier, creating one on
    first run. Deliberately independent of *which user* is logging in --
    the device identity (and its attestation key) belongs to the physical
    machine, matching how real device-bound attestation works: the same
    laptop keeps the same hardware identity across different user logins.
    Stored locally so repeated runs re-use the same enrolled key instead of
    generating (and re-enrolling) a new identity every time.
    """
    import uuid
    os.makedirs(os.path.dirname(_DEVICE_ID_FILE), exist_ok=True)
    if os.path.exists(_DEVICE_ID_FILE):
        with open(_DEVICE_ID_FILE, "r") as f:
            existing = f.read().strip()
            if existing:
                return existing
    device_id = f"{platform.node() or 'device'}-{uuid.uuid4().hex[:8]}"
    with open(_DEVICE_ID_FILE, "w") as f:
        f.write(device_id)
    return device_id


def _cert_subject(device_id: str) -> str:
    # Sanitize -- CNG/PowerShell subjects don't tolerate arbitrary characters.
    safe_id = "".join(c for c in device_id if c.isalnum() or c in "-_")
    return f"CN=PyZTNA-{safe_id}"


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _run_powershell(script: str, timeout: int = 20):
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Windows / TPM path
# ---------------------------------------------------------------------------

def _windows_ensure_and_export_public_key(device_id: str):
    """Create the TPM-backed cert if it doesn't exist, and return its public
    key as a standard SubjectPublicKeyInfo PEM string.

    IMPORTANT (.NET compatibility): an earlier version of this function
    called `RSA.ExportSubjectPublicKeyInfo()` inside PowerShell. That method
    only exists on .NET Core 3.0+ / .NET 5+ -- it is NOT present in .NET
    Framework 4.x, which is what Windows PowerShell 5.1 (the `powershell.exe`
    shipped with every Windows 10/11) runs on. The result was that the
    certificate was created successfully in the TPM, the export line then
    threw a MethodNotFound error, the script exited non-zero, and this
    function returned None -- silently degrading a perfectly good TPM to a
    software key on hardware that fully supported it.

    We now export the raw certificate bytes (`$cert.RawData`), which is
    available on every PowerShell version, and derive the public key on the
    Python side with the `cryptography` library instead. Returns None on any
    failure -- caller falls back to software mode.
    """
    subject = _cert_subject(device_id)
    # NOTE: no backtick line-continuations here either. Backticks are fragile
    # when a multi-line script is passed as a single -Command argument via
    # subprocess; each command is kept on one line instead.
    script = f'''
$ErrorActionPreference = "Stop"
try {{
    $subject = "{subject}"
    $cert = Get-ChildItem Cert:\\CurrentUser\\My | Where-Object {{ $_.Subject -eq $subject }} | Select-Object -First 1
    if (-not $cert) {{
        $cert = New-SelfSignedCertificate -Subject $subject -CertStoreLocation Cert:\\CurrentUser\\My -Provider "Microsoft Platform Crypto Provider" -KeyAlgorithm RSA -KeyLength 2048 -KeyUsage DigitalSignature -NotAfter (Get-Date).AddYears(10)
    }}
    Write-Output "CERT_B64:$([Convert]::ToBase64String($cert.RawData))"
}} catch {{
    Write-Output "ERROR:$($_.Exception.Message)"
    exit 1
}}
'''
    try:
        result = _run_powershell(script)
    except Exception as e:  # noqa: BLE001
        _debug(f"powershell invocation raised: {e}")
        return None

    if result.returncode != 0:
        _debug(f"powershell exited {result.returncode}; stdout={result.stdout!r} stderr={result.stderr!r}")
        return None

    line = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if not line.startswith("CERT_B64:"):
        _debug(f"unexpected powershell output: {result.stdout!r}")
        return None

    try:
        from cryptography import x509
        cert_der = base64.b64decode(line[len("CERT_B64:"):])
        cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
        pem = cert_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("ascii")
    except Exception as e:  # noqa: BLE001
        _debug(f"failed to parse certificate returned by powershell: {e}")
        return None


def _windows_sign(device_id: str, nonce: bytes):
    """Sign `nonce` using the TPM-backed private key. Returns raw signature
    bytes, or None on any failure (device not enrolled, provider error,
    TPM unavailable, etc.)."""
    subject = _cert_subject(device_id)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    script = f'''
$ErrorActionPreference = "Stop"
try {{
    $subject = "{subject}"
    $cert = Get-ChildItem Cert:\\CurrentUser\\My | Where-Object {{ $_.Subject -eq $subject }} | Select-Object -First 1
    if (-not $cert) {{ throw "device key not enrolled" }}
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $data = [Convert]::FromBase64String("{nonce_b64}")
    $sig = $rsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    Write-Output "SIG_B64:$([Convert]::ToBase64String($sig))"
}} catch {{
    Write-Output "ERROR:$($_.Exception.Message)"
    exit 1
}}
'''
    try:
        result = _run_powershell(script)
    except Exception as e:  # noqa: BLE001
        _debug(f"powershell invocation raised during signing: {e}")
        return None
    if result.returncode != 0:
        _debug(f"signing powershell exited {result.returncode}; stdout={result.stdout!r} stderr={result.stderr!r}")
        return None
    line = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if not line.startswith("SIG_B64:"):
        _debug(f"unexpected signing output: {result.stdout!r}")
        return None
    return base64.b64decode(line[len("SIG_B64:"):])


# ---------------------------------------------------------------------------
# Cross-platform software fallback (NOT hardware-backed -- see module docstring)
# ---------------------------------------------------------------------------

def _fallback_key_paths(device_id: str):
    os.makedirs(FALLBACK_KEY_DIR, exist_ok=True)
    safe_id = "".join(c for c in device_id if c.isalnum() or c in "-_")
    priv = os.path.join(FALLBACK_KEY_DIR, f"{safe_id}_private.pem")
    return priv


def _fallback_ensure_key(device_id: str):
    priv_path = _fallback_key_paths(device_id)
    if not os.path.exists(priv_path):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(priv_path, "wb") as f:
            f.write(pem)
        try:
            os.chmod(priv_path, 0o600)  # best-effort; Windows ACLs differ, see docs
        except Exception:
            pass
    return priv_path


def _fallback_load_key(device_id: str):
    priv_path = _fallback_ensure_key(device_id)
    with open(priv_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def _fallback_public_key_pem(device_id: str) -> str:
    key = _fallback_load_key(device_id)
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("ascii")


def _fallback_sign(device_id: str, nonce: bytes) -> bytes:
    key = _fallback_load_key(device_id)
    return key.sign(nonce, padding.PKCS1v15(), hashes.SHA256())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ensure_enrolled(device_id: str) -> dict:
    """Idempotent: create the device's attestation key if it doesn't exist
    yet, trying the TPM-backed path first on Windows. Always returns a
    usable public key -- falls back to software mode rather than failing,
    but reports which mode was actually used."""
    if _is_windows() and shutil.which("powershell"):
        pem = _windows_ensure_and_export_public_key(device_id)
        if pem:
            return {"public_key_pem": pem, "hardware_backed": True, "mode": "tpm"}
        print("[attestation] WARNING: TPM-backed key unavailable "
              "(no TPM, provider missing, or PowerShell error) -- "
              "falling back to a SOFTWARE key. This device will not "
              "satisfy resources that specifically audit for hardware "
              "attestation strength; see docs/DEVICE_ATTESTATION.md.")

    pem = _fallback_public_key_pem(device_id)
    return {"public_key_pem": pem, "hardware_backed": False, "mode": "software_fallback"}


def sign_nonce(device_id: str, nonce_b64: str, hardware_backed: bool) -> str:
    """Sign the base64-encoded nonce and return a base64-encoded signature.
    `hardware_backed` should be whatever ensure_enrolled() reported, so
    signing uses the SAME key material that was actually enrolled."""
    nonce = base64.b64decode(nonce_b64)
    return base64.b64encode(sign_bytes(device_id, nonce, hardware_backed)).decode("ascii")


def sign_bytes(device_id: str, message: bytes, hardware_backed: bool) -> bytes:
    """Sign arbitrary bytes with the device key.

    Split out from sign_nonce() so token-binding proofs
    (common/token_binding.py) sign a structured payload rather than a
    server-issued nonce, while provably using the identical key and
    algorithm. Two separate signing implementations would eventually drift
    and fail as an unexplained "invalid signature".
    """
    if hardware_backed:
        sig = _windows_sign(device_id, message)
        if sig is not None:
            return sig
        raise RuntimeError("TPM signing failed after successful TPM enrollment; "
                            "re-run enrollment or check TPM/provider status")
    return _fallback_sign(device_id, message)


if __name__ == "__main__":
    info = ensure_enrolled("cli-test-device")
    print("enrolled:", info)
