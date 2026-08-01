#!/usr/bin/env python3
"""
Verify the hash chain on logs/access_log.jsonl (this hardening revision --
see common/audit_log.py and docs/HARDENING.md).

Each log line carries a `hash` field computed over its own content plus
the PREVIOUS line's hash, so any edit, deletion, or reordering of
historical entries breaks the chain from that point forward -- this is
what makes the audit trail tamper-evident rather than just append-only.

Usage:
    python -m tools.verify_audit_log
Exit code 0 if the chain is intact, 1 if a break was found.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.audit_log import verify_chain


def main():
    ok, details = verify_chain()
    if ok:
        print(f"OK -- {details['count']} log entries, hash chain intact.")
        sys.exit(0)
    else:
        print(f"TAMPER DETECTED -- chain broke at line {details['break_line']}: {details['reason']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
