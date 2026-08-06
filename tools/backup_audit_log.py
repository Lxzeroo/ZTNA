"""
Audit log backup, restore and verification.

The audit log is the only forensic record this system produces. It is
hash-chained (common/audit_log.py) so silent partial edits are detectable --
but it is a single append-only file on a single host's local disk. Delete
the file and the evidence is gone; the hash chain does not help, because
there is nothing left to check.

What this tool does
-------------------
  --backup   Copy the log to a timestamped file, verifying the chain BEFORE
             the copy and re-verifying the copy afterwards. A backup nobody
             verified is a backup you find out about at the worst moment.
             Writes a .manifest.json alongside recording the event count,
             the final chain hash, and the time -- so a later restore can
             prove it got back exactly what was taken.

  --verify   Check the chain of any log or backup.

  --restore  Put a backup back, refusing to clobber a log that is longer
             than the backup unless forced (that would destroy evidence).

  --list     Show available backups.

What this tool does NOT do
--------------------------
It does not make the log tamper-PROOF. An attacker with write access to
both the log and the backup directory can rewrite both and recompute a
valid chain. Genuine tamper-proofing needs an append-only sink the local
host cannot rewrite. Practical options, roughly in order of effort:

  * ship each line to a remote syslog/SIEM as it is written -- the copy
    off-host is the control, not the local file;
  * write backups to object storage with an object-lock / WORM retention
    policy (S3 Object Lock, Azure Blob immutable storage), so even the
    account that wrote them cannot delete them before the retention window
    expires;
  * periodically publish the chain head hash somewhere append-only. Anyone
    can then detect wholesale rewriting, because the recomputed head will
    not match a value that was already committed elsewhere.

The third costs almost nothing and is the natural next step for this
project -- see docs/HARDENING.md.

Usage
-----
    python -m tools.backup_audit_log --backup
    python -m tools.backup_audit_log --list
    python -m tools.backup_audit_log --verify logs/backups/access_log-20260804-221500.jsonl
    python -m tools.backup_audit_log --restore logs/backups/access_log-20260804-221500.jsonl
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import time

from common.config import ACCESS_LOG_PATH, LOG_DIR
from common.audit_log import read_events, verify_events_chain, GENESIS_HASH

BACKUP_DIR = os.path.join(LOG_DIR, "backups")


def _read_events_from(path):
    if not os.path.exists(path):
        return []
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def _file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_backup(args):
    if not os.path.exists(ACCESS_LOG_PATH):
        print(f"No audit log at {ACCESS_LOG_PATH} -- nothing to back up.", file=sys.stderr)
        return 1

    events = read_events()
    ok, details = verify_events_chain(events)

    if not ok:
        # Back it up anyway: a broken chain is exactly the state you most
        # want preserved for investigation. But never let it be mistaken
        # for a clean backup.
        print(f"WARNING: the audit log's hash chain is BROKEN at line "
              f"{details.get('break_line')} ({details.get('reason')}).")
        print("Backing up regardless -- a compromised log is evidence too --")
        print("but the manifest will record chain_intact=false.")
        if not args.yes:
            answer = input("Continue? [y/N]: ").strip().lower()
            if answer not in ("y", "yes"):
                print("Aborted.")
                return 1

    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(BACKUP_DIR, f"access_log-{stamp}.jsonl")
    shutil.copy2(ACCESS_LOG_PATH, dest)

    # Re-verify the COPY, not the original. Verifying the source and then
    # copying proves nothing about what actually landed on disk.
    copied_events = _read_events_from(dest)
    copy_ok, copy_details = verify_events_chain(copied_events)
    if len(copied_events) != len(events):
        print(f"ERROR: backup has {len(copied_events)} events but the source had "
              f"{len(events)}. Removing the bad copy.", file=sys.stderr)
        os.remove(dest)
        return 1

    head_hash = copied_events[-1].get("hash") if copied_events else GENESIS_HASH
    manifest = {
        "created_at": time.time(),
        "created_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": ACCESS_LOG_PATH,
        "backup": dest,
        "event_count": len(copied_events),
        "chain_intact": bool(copy_ok),
        "chain_detail": copy_details,
        "chain_head_hash": head_hash,
        "file_sha256": _file_sha256(dest),
    }
    manifest_path = dest + ".manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Backed up {len(copied_events)} event(s)")
    print(f"  file          : {dest}")
    print(f"  manifest      : {manifest_path}")
    print(f"  chain intact  : {copy_ok}")
    print(f"  chain head    : {head_hash[:32]}...")
    print(f"  sha256        : {manifest['file_sha256'][:32]}...")
    print("\nRecord the chain head hash somewhere outside this host. Comparing "
          "it later is what detects a wholesale rewrite of the log.")
    return 0 if copy_ok else 2


def cmd_verify(args):
    path = args.verify
    if not os.path.exists(path):
        print(f"No such file: {path}", file=sys.stderr)
        return 1
    events = _read_events_from(path)
    ok, details = verify_events_chain(events)
    print(f"File   : {path}")
    print(f"Events : {len(events)}")
    print(f"Chain  : {'INTACT' if ok else 'BROKEN'}")
    if not ok:
        print(f"  break at line : {details.get('break_line')}")
        print(f"  reason        : {details.get('reason')}")

    manifest_path = path + ".manifest.json"
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        actual = _file_sha256(path)
        match = actual == manifest.get("file_sha256")
        print(f"Manifest sha256 match : {match}")
        if not match:
            # The chain can still verify after a full rewrite; the manifest
            # hash is what catches that, provided the manifest itself is
            # trustworthy. Hence "store the head hash off-host".
            print("  The file differs from what was recorded at backup time.")
            return 1
    return 0 if ok else 1


def cmd_list(_args):
    if not os.path.isdir(BACKUP_DIR):
        print("No backups yet.")
        return 0
    names = sorted(n for n in os.listdir(BACKUP_DIR) if n.endswith(".jsonl"))
    if not names:
        print("No backups yet.")
        return 0
    print(f"{'BACKUP':<44} {'EVENTS':>7}  {'CHAIN':<8} CREATED")
    print("-" * 84)
    for name in names:
        path = os.path.join(BACKUP_DIR, name)
        manifest_path = path + ".manifest.json"
        count, chain, created = "?", "?", "?"
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    m = json.load(f)
                count = m.get("event_count", "?")
                chain = "intact" if m.get("chain_intact") else "BROKEN"
                created = m.get("created_at_iso", "?")
            except (ValueError, OSError):
                pass
        print(f"{name:<44} {str(count):>7}  {chain:<8} {created}")
    return 0


def cmd_restore(args):
    src = args.restore
    if not os.path.exists(src):
        print(f"No such backup: {src}", file=sys.stderr)
        return 1

    backup_events = _read_events_from(src)
    ok, details = verify_events_chain(backup_events)
    if not ok and not args.force:
        print(f"Refusing to restore: the backup's chain is broken at line "
              f"{details.get('break_line')} ({details.get('reason')}).", file=sys.stderr)
        print("Use --force if you understand you are restoring a log that "
              "cannot be trusted as evidence.", file=sys.stderr)
        return 1

    current_events = read_events()
    if len(current_events) > len(backup_events) and not args.force:
        print(f"Refusing to restore: the CURRENT log has {len(current_events)} events "
              f"but the backup has {len(backup_events)}.", file=sys.stderr)
        print("Restoring would destroy audit records that exist only in the "
              "current log. Back it up first:", file=sys.stderr)
        print("    python -m tools.backup_audit_log --backup", file=sys.stderr)
        print("then re-run with --force.", file=sys.stderr)
        return 1

    if os.path.exists(ACCESS_LOG_PATH):
        stamp = time.strftime("%Y%m%d-%H%M%S")
        os.makedirs(BACKUP_DIR, exist_ok=True)
        pre = os.path.join(BACKUP_DIR, f"access_log-pre-restore-{stamp}.jsonl")
        shutil.copy2(ACCESS_LOG_PATH, pre)
        print(f"Current log preserved at {pre}")

    shutil.copy2(src, ACCESS_LOG_PATH)
    restored = read_events()
    r_ok, _ = verify_events_chain(restored)
    print(f"Restored {len(restored)} event(s) to {ACCESS_LOG_PATH}")
    print(f"Chain after restore: {'INTACT' if r_ok else 'BROKEN'}")
    return 0 if r_ok else 1


def main():
    parser = argparse.ArgumentParser(
        description="Back up, verify and restore the PyZTNA audit log.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--backup", action="store_true", help="create a verified backup")
    group.add_argument("--list", action="store_true", help="list existing backups")
    group.add_argument("--verify", metavar="PATH", help="verify a log or backup file")
    group.add_argument("--restore", metavar="PATH", help="restore a backup")
    parser.add_argument("--force", action="store_true",
                        help="override refusal to destroy newer records / restore a broken chain")
    parser.add_argument("--yes", action="store_true", help="skip confirmation prompts")
    args = parser.parse_args()

    if args.backup:
        return cmd_backup(args)
    if args.list:
        return cmd_list(args)
    if args.verify:
        return cmd_verify(args)
    if args.restore:
        return cmd_restore(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
