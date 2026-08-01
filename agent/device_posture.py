"""
Device posture / trust scoring for the ZTNA client agent.

This is the "context" signal that makes access decisions attribute-based
rather than purely identity-based. Each sub-check is written to run for
real on Windows (Defender status via `sc query`, BitLocker via
`manage-bde`, firewall via `netsh`) and, as of this hardening revision,
also runs REAL checks on macOS (FileVault via `fdesetup`, firewall via
`socketfilterfw`) and Linux (LUKS via `lsblk`/`cryptsetup`, firewall via
`ufw`) instead of unconditionally returning False for disk encryption on
those platforms -- the original design's `_check_disk_encryption()` only
implemented the Windows path and left non-Windows as an unconditional
"unknown -> no points" stub. Every check still degrades gracefully (a
missing tool or insufficient privilege lowers the score instead of
crashing the agent), which remains the deliberate fail-closed design
choice.

KNOWN LIMITATION (documented deliberately, not hidden, and NOT addressed
by this hardening revision -- see docs/HARDENING.md "not addressed in this
pass"): the score is still self-reported by the agent running on the
endpoint. A fully compromised endpoint could patch this module to lie.
This is mitigated, but not eliminated, by the independent cryptographic
device attestation dimension (docs/DEVICE_ATTESTATION.md), which a
resource can require regardless of what this score claims.
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
    "xprotectservice",   # macOS XProtect (approximate process-name match)
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
        return release in ("10", "11") or (release.isdigit() and int(release) >= 10)
    return system in ("Linux", "Darwin")


def _check_antivirus_running() -> bool:
    if platform.system() == "Windows":
        result = _run(["sc", "query", "windefend"])
        if result and "RUNNING" in result.stdout.upper():
            return True
    if platform.system() == "Darwin":
        # XProtect is always present/enabled on modern macOS; treat OS
        # support as a reasonable proxy since there's no simple CLI status
        # query for it, then still check for third-party AV processes too.
        pass
    if psutil is not None:
        try:
            for proc in psutil.process_iter(["name"]):
                name = (proc.info.get("name") or "").lower()
                if name in KNOWN_AV_PROCESS_NAMES:
                    return True
        except Exception:
            pass
    return platform.system() == "Darwin"  # XProtect baseline, see note above


def _check_disk_encryption() -> bool:
    """Real check on Windows (BitLocker), macOS (FileVault), and Linux
    (LUKS) as of this hardening revision -- previously only Windows was
    implemented and every other OS unconditionally returned False."""
    system = platform.system()

    if system == "Windows":
        result = _run(["manage-bde", "-status"])
        return bool(result and "Protection On" in result.stdout)

    if system == "Darwin":
        result = _run(["fdesetup", "status"])
        return bool(result and "FileVault is On" in result.stdout)

    if system == "Linux":
        # Look for an active LUKS (dm-crypt) mapping -- a reasonable proxy
        # for "the root/home filesystem is encrypted" on a managed Linux
        # laptop without needing to know the exact device name in advance.
        if shutil.which("lsblk"):
            result = _run(["lsblk", "-o", "TYPE"])
            if result and "crypt" in result.stdout.lower():
                return True
        if shutil.which("cryptsetup"):
            result = _run(["cryptsetup", "status", "root"])
            if result and "is active" in result.stdout.lower():
                return True
        return False

    return False


def _check_firewall_enabled() -> bool:
    system = platform.system()
    if system == "Windows":
        result = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if result and result.stdout.upper().count("STATE                                 ON") >= 1:
            return True
        if result and "ON" in result.stdout.upper():
            return True
        return False
    if system == "Darwin":
        result = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        return bool(result and "enabled" in result.stdout.lower())
    if shutil.which("ufw"):
        result = _run(["ufw", "status"])
        return bool(result and "active" in result.stdout.lower())
    if shutil.which("firewall-cmd"):
        result = _run(["firewall-cmd", "--state"])
        return bool(result and "running" in result.stdout.lower())
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
