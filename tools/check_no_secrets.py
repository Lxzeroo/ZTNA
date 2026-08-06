"""
Guard against committing key material.

Motivation (this is not hypothetical for this repository): five service
private keys were committed in an earlier revision and remain recoverable
from the public history --

    certs/services/{idp,gateway,docs-app,finance-app,ztna-gateway-client}_key.pem

They are inert today because the internal CA was subsequently rotated, so a
certificate signed by the old CA no longer validates against the current one.
But "we rotated afterwards" is a remediation, not a control. This script is
the control: it fails CI if key material is *tracked by git* again, so the
same mistake cannot silently recur.

Scope note: this checks the current tracked tree, not historical commits.
Purging the existing leak requires rewriting published history
(git filter-repo + force push) and is a deliberate, separate decision --
see docs/HARDENING.md.

Usage:
    python -m tools.check_no_secrets          # scan tracked files
    python -m tools.check_no_secrets --all    # scan working tree too

Exit code 0 = clean, 1 = secrets found.
"""
import argparse
import os
import re
import subprocess
import sys

# Filenames that must never be tracked, regardless of content.
FORBIDDEN_NAME_PATTERNS = [
    re.compile(r".*_key\.pem$"),
    re.compile(r".*\.key$"),
    re.compile(r"^certs/.*\.pem$"),
    re.compile(r".*device_id\.txt$"),
    re.compile(r"^\.env$"),
]

# Allowed despite matching the patterns above -- public material only.
# This script itself is listed because it necessarily contains the very
# marker strings it searches for.
ALLOWLIST = {
    "certs/.gitkeep",
    "tools/check_no_secrets.py",
}

# Content markers for private key material of any format.
CONTENT_MARKERS = [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
]

# Directories never worth scanning.
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist"}

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def tracked_files():
    """Files git currently tracks. Empty list if this isn't a git checkout."""
    try:
        out = subprocess.run(
            ["git", "ls-files"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def _drop_gitignored(paths):
    """Remove paths git is already ignoring.

    Locally generated key material (certs/, logs/) is *supposed* to exist on
    disk -- it is covered by .gitignore and will never be committed. Flagging
    it would make --all pure noise and train people to ignore this check.
    What --all is actually for is catching key material sitting in a path
    .gitignore does NOT cover, before it ever gets staged.
    """
    if not paths:
        return paths
    try:
        proc = subprocess.run(
            ["git", "check-ignore", "--stdin"],
            cwd=REPO_ROOT, input="\n".join(paths),
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        print("NOTE: git not found; cannot filter ignored paths. Locally generated "
              "key material under certs/ will be reported below even though "
              ".gitignore covers it.")
        return paths
    # Exit 0 = some ignored, 1 = none ignored, 128 = not a git repo.
    if proc.returncode not in (0, 1):
        # Without git we cannot tell "ignored local key" from "key about to be
        # committed", so we report everything. Say why, or the output looks
        # like 15 real findings in a tree that is actually clean.
        print("NOTE: not a git checkout, so .gitignore cannot be consulted. "
              "Everything matching a secret pattern is reported below, including "
              "locally generated certs/ material that a real checkout would ignore. "
              "Run without --all, or from a git checkout, for an accurate result.")
        return paths
    ignored = {line.strip().replace(os.sep, "/") for line in proc.stdout.splitlines() if line.strip()}
    return [p for p in paths if p not in ignored]


def working_tree_files():
    paths = []
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            paths.append(os.path.relpath(full, REPO_ROOT).replace(os.sep, "/"))
    return _drop_gitignored(paths)


def check_name(rel_path):
    if rel_path in ALLOWLIST:
        return None
    for pattern in FORBIDDEN_NAME_PATTERNS:
        if pattern.match(rel_path):
            return f"filename matches forbidden pattern {pattern.pattern!r}"
    return None


def check_content(rel_path):
    full = os.path.join(REPO_ROOT, rel_path)
    if not os.path.isfile(full):
        return None
    try:
        if os.path.getsize(full) > 2_000_000:
            return None
        with open(full, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(8192)
    except OSError:
        return None
    for marker in CONTENT_MARKERS:
        if marker in head:
            return f"contains private key marker {marker!r}"
    return None


def main():
    parser = argparse.ArgumentParser(description="Fail if key material is present.")
    parser.add_argument(
        "--all", action="store_true",
        help="scan the whole working tree, not just git-tracked files",
    )
    args = parser.parse_args()

    if args.all:
        paths = working_tree_files()
        scope = "working tree"
    else:
        paths = tracked_files()
        scope = "git-tracked files"
        if not paths:
            print("No git-tracked files found -- not a git checkout? Nothing to check.")
            return 0

    findings = []
    for rel_path in paths:
        # A tracked file may be listed but absent from disk; name check still applies.
        reason = check_name(rel_path)
        if reason:
            findings.append((rel_path, reason))
            continue
        if rel_path in ALLOWLIST:
            continue
        reason = check_content(rel_path)
        if reason:
            findings.append((rel_path, reason))

    if findings:
        print(f"FAIL: key material detected in {scope} ({len(findings)} finding(s)):\n")
        for rel_path, reason in sorted(findings):
            print(f"  {rel_path}\n      {reason}")
        print(
            "\nPrivate keys must never be committed. Generate them locally via\n"
            "  python -m tools.provision_certs\n"
            "and confirm .gitignore covers the path before staging."
        )
        return 1

    print(f"OK: no key material found in {scope} ({len(paths)} file(s) scanned).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
