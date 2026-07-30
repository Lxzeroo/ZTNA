"""
Device posture / trust scoring for the ZTNA client agent.

This is the "context" signal that makes access decisions attribute-based
rather than purely identity-based -- two users with the identical role can
get different outcomes depending on the health of the device they're
connecting from. That's a defining property of Zero Trust versus a
traditional VPN, which only checks "did you authenticate" once at connect
time.

Each sub-check is written to run for real on Windows (Defender status via
`sc query`, BitLocker via `manage-bde`, firewall via `netsh`) and degrades
gracefully everywhere else so the same code can be developed/tested on any
OS. Every check is wrapped so a missing tool or insufficient privilege
lowers the score instead of crashing the agent -- a device that CAN'T prove
it's compliant is treated the same as one that IS non-compliant, which is
the conservative (fail-closed) choice Zero Trust designs are supposed to make.

KNOWN LIMITATION (documented deliberately, not hidden): the score is
self-reported by the agent running on the endpoint. A fully compromised
endpoint could patch this module to lie. Production ZTNA products solve
this with remote attestation / MDM-verified posture signals rather than
client self-report -- noted as future work in docs/EVALUATION.md.
"""
import platform
import shutil
import subprocess

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

KNOWN_AV_PROCESS_NAMES = {
    "msmpeng.exe",       # Windows Defender
    "windefend",
    "avp.exe",           # Kaspersky
    "avastsvc.exe",      # Avast
    "avguard.exe",       # Avira
    "mcshield.exe",      # McAfee
    "ekrn.exe",          # ESET
}


def _run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def _check_os_supported() -> bool:
    system = platform.system()
    if system == "Windows":
        release = platform.release()
        return release in ("10", "11") or release.isdigit() and int(release) >= 10
    # Non-Windows dev/test environments: treat as supported so the
    # rest of the pipeline is exercisable outside Windows.
    return system in ("Linux", "Darwin")


def _check_antivirus_running() -> bool:
    if platform.system() == "Windows":
        result = _run(["sc", "query", "windefend"])
        if result and "RUNNING" in result.stdout.upper():
            return True
    if psutil is not None:
        try:
            for proc in psutil.process_iter(["name"]):
                name = (proc.info.get("name") or "").lower()
                if name in KNOWN_AV_PROCESS_NAMES:
                    return True
        except Exception:
            pass
    return False


def _check_disk_encryption() -> bool:
    if platform.system() == "Windows":
        result = _run(["manage-bde", "-status"])
        if result and "Protection On" in result.stdout:
            return True
        return False
    # Best-effort Linux proxy: LUKS-encrypted root is common on managed
    # laptops. Not checked by default to avoid false confidence; treated
    # as "unknown" -> no points, consistent with fail-closed scoring.
    return False


def _check_firewall_enabled() -> bool:
    if platform.system() == "Windows":
        result = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if result and result.stdout.upper().count("STATE                                 ON") >= 1:
            return True
        if result and "ON" in result.stdout.upper():
            return True
        return False
    if shutil.which("ufw"):
        result = _run(["ufw", "status"])
        return bool(result and "active" in result.stdout.lower())
    return False


def compute_trust_score(device_id: str = None, simulate_compromised: bool = False) -> dict:
    """Return {"score": int 0-100, "checks": {...}} -- never raises."""
    if simulate_compromised:
        return {
            "score": 20,
            "checks": {
                "os_supported": False,
                "antivirus_running": False,
                "disk_encryption": False,
                "firewall_enabled": False,
                "note": "SIMULATED COMPROMISE (--simulate-compromised): posture checks "
                        "forced to fail to demonstrate continuous, context-aware denial "
                        "even for an otherwise-authorized user/role.",
            },
        }

    checks = {
        "os_supported": _check_os_supported(),
        "antivirus_running": _check_antivirus_running(),
        "disk_encryption": _check_disk_encryption(),
        "firewall_enabled": _check_firewall_enabled(),
    }

    score = 40  # base score for successfully authenticating the agent at all
    score += 20 if checks["os_supported"] else 0
    score += 20 if checks["antivirus_running"] else 0
    score += 10 if checks["disk_encryption"] else 0
    score += 10 if checks["firewall_enabled"] else 0
    score = max(0, min(100, score))

    return {"score": score, "checks": checks}


if __name__ == "__main__":
    import json
    print(json.dumps(compute_trust_score(), indent=2))
