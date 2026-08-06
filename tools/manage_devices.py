"""
Administrator CLI for the device registry.

Closes the trust-on-first-use gap named in docs/HARDENING.md: enrollment
puts a device in `pending`, and it stays there -- unable to produce an
attested login or use a bound token -- until a human approves it here.

    python -m tools.manage_devices --list
    python -m tools.manage_devices --show DESKTOP-ABC123
    python -m tools.manage_devices --approve DESKTOP-ABC123 --by "affan"
    python -m tools.manage_devices --revoke DESKTOP-ABC123 --reason "laptop stolen"

Approving a device means asserting, out of band, that the thumbprint shown
here belongs to the machine you think it does -- read it off the endpoint
with:

    python -m agent.device_attestation

and compare. That comparison is the entire security value of this step; an
administrator who approves without checking has reimplemented TOFU with
extra latency.
"""
import argparse
import sys
import time

from common import storage  # noqa: F401  (ensures backend config is loaded)
from idp import device_registry


def _fmt_time(ts):
    if not ts:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def cmd_list(args):
    devices = device_registry.list_devices()
    if not devices:
        print("No devices enrolled.")
        return 0

    rows = sorted(devices.values(), key=lambda d: d.get("enrolled_at", 0))
    if args.pending_only:
        rows = [r for r in rows if r.get("status") == device_registry.STATUS_PENDING]
        if not rows:
            print("No devices awaiting approval.")
            return 0

    print(f"{'DEVICE ID':<28} {'STATUS':<10} {'THUMBPRINT':<20} {'ENROLLED':<20}")
    print("-" * 82)
    for r in rows:
        print(f"{r.get('device_id', '?'):<28} "
              f"{r.get('status', '?'):<10} "
              f"{(r.get('thumbprint') or '')[:16]:<20} "
              f"{_fmt_time(r.get('enrolled_at')):<20}")

    pending = sum(1 for r in devices.values()
                  if r.get("status") == device_registry.STATUS_PENDING)
    if pending:
        print(f"\n{pending} device(s) awaiting approval. "
              f"Approve with: python -m tools.manage_devices --approve <device_id>")
    return 0


def cmd_show(args):
    record = device_registry.get_device(args.show)
    if not record:
        print(f"No such device: {args.show}", file=sys.stderr)
        return 1
    print(f"device_id      : {record.get('device_id')}")
    print(f"status         : {record.get('status')}")
    print(f"thumbprint     : {record.get('thumbprint')}")
    print(f"enrolled_at    : {_fmt_time(record.get('enrolled_at'))}")
    print(f"approved_at    : {_fmt_time(record.get('approved_at'))}")
    print(f"approved_by    : {record.get('approved_by') or '-'}")
    if record.get("previous_thumbprint"):
        # Worth surfacing prominently: a changed key on an existing device_id
        # is either a legitimate re-enrollment or an attempted takeover.
        print(f"\nNOTE: this device previously used a DIFFERENT key")
        print(f"  previous     : {record['previous_thumbprint'][:32]}...")
        print(f"  Confirm the change was expected before approving.")
    if record.get("status") == device_registry.STATUS_REVOKED:
        print(f"\nrevoked_at     : {_fmt_time(record.get('revoked_at'))}")
        print(f"revoked_by     : {record.get('revoked_by')}")
        print(f"revoked_reason : {record.get('revoked_reason') or '-'}")
    print("\npublic key:")
    print(record.get("public_key_pem", "").strip())
    return 0


def cmd_approve(args):
    device_id = args.approve
    record = device_registry.get_device(device_id)
    if not record:
        print(f"No such device: {device_id}", file=sys.stderr)
        print("Enrolled devices: " + (", ".join(device_registry.list_devices()) or "(none)"),
              file=sys.stderr)
        return 1

    if record.get("status") == device_registry.STATUS_APPROVED:
        print(f"Device {device_id} is already approved.")
        return 0

    print(f"Device     : {device_id}")
    print(f"Thumbprint : {record.get('thumbprint')}")
    if record.get("previous_thumbprint"):
        print(f"WARNING    : key CHANGED from {record['previous_thumbprint'][:16]}...")
    if not args.yes:
        answer = input("\nConfirm this thumbprint matches the physical device [y/N]: ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted -- device left pending.")
            return 1

    device_registry.approve_device(device_id, approved_by=args.by)
    print(f"Approved {device_id} (by {args.by}).")
    return 0


def cmd_revoke(args):
    device_id = args.revoke
    if not device_registry.get_device(device_id):
        print(f"No such device: {device_id}", file=sys.stderr)
        return 1

    device_registry.revoke_device(device_id, revoked_by=args.by, reason=args.reason)
    print(f"Revoked device {device_id}.")

    # Revoking a device while leaving its live tokens usable is a trap: the
    # device is blocked from authenticating again, but anything already
    # issued keeps working until it expires. Close both here so an operator
    # under pressure cannot forget the second half.
    try:
        from common import token_store, revocation
        killed = 0
        for record in token_store.load_all() if hasattr(token_store, "load_all") else []:
            if record.get("device_id") == device_id:
                revocation.revoke(record["jti"], record.get("exp"),
                                  reason=f"device_revoked:{device_id}")
                killed += 1
        if killed:
            print(f"Also revoked {killed} live token(s) issued to this device.")
        else:
            print("No live tokens found for this device "
                  "(they may simply have expired already).")
    except Exception as e:  # noqa: BLE001
        print(f"WARNING: could not sweep live tokens for this device ({e}). "
              f"Run: python -m tools.revoke_token --user <username>", file=sys.stderr)
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Administer the PyZTNA device registry (enrollment approval).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="list all enrolled devices")
    group.add_argument("--show", metavar="DEVICE_ID", help="show one device in full")
    group.add_argument("--approve", metavar="DEVICE_ID", help="approve a pending device")
    group.add_argument("--revoke", metavar="DEVICE_ID", help="revoke a device")
    parser.add_argument("--pending-only", action="store_true",
                        help="with --list, show only devices awaiting approval")
    parser.add_argument("--by", default="admin", help="who is performing this action")
    parser.add_argument("--reason", default="", help="reason, for --revoke")
    parser.add_argument("--yes", action="store_true",
                        help="skip the interactive thumbprint confirmation")
    args = parser.parse_args()

    if args.list:
        return cmd_list(args)
    if args.show:
        return cmd_show(args)
    if args.approve:
        return cmd_approve(args)
    if args.revoke:
        return cmd_revoke(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
