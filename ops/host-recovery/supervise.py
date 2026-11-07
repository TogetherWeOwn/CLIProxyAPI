"""Explicit manager-launched unresolved owner, not an installer/recovery grant.

Run trusted installed code with Python -I. This runner always denies recovery and
start authority. It owns the existing installation lock until TERM/INT and uses
an independently pinned local alert inbox, not an external notification service.
"""
import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_recovery.installation import DirectoryApproval
from host_recovery.launch import load_launch
from host_recovery.unresolved_service import ServiceAlerts, run_unresolved


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "host-recovery-supervisor: invalid-arguments\n")


def main(argv=None):
    parser = Parser(description="Retain unresolved supervisor ownership; recovery/start authority always denied.")
    parser.add_argument("--approval", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    for root in ("endpoint", "alert-endpoint", "alert-receipts"):
        parser.add_argument("--" + root, required=True)
        parser.add_argument("--" + root + "-device", type=int, required=True)
        parser.add_argument("--" + root + "-inode", type=int, required=True)
    parser.add_argument("--deadline", type=float, required=True, help="Absolute original local monotonic deadline")
    parser.add_argument("--alert-deadline", type=float, required=True,
                        help="Absolute nonrenewing local escalation limit; not a recovery allowance")
    parser.add_argument("--alert-route", required=True)
    parser.add_argument("--listener-uid", type=int, required=True)
    parser.add_argument("--listener-instance", required=True)
    args = parser.parse_args(argv)
    try:
        approval = load_launch(args.approval, sha256=args.sha256, uid=args.uid, gid=args.gid)
        def directory(name):
            return DirectoryApproval(getattr(args, name), getattr(args, name + "_device"),
                getattr(args, name + "_inode"), os.geteuid(), os.getegid(), 0o700)
        alerts = ServiceAlerts(endpoint=directory("alert_endpoint"), receipts=directory("alert_receipts"),
            route_id=args.alert_route, listener_uid=args.listener_uid, instance_id=args.listener_instance,
            deadline=args.alert_deadline)
        run_unresolved(approval, endpoint=directory("endpoint"), alerts=alerts, deadline=args.deadline)
        # There is no healthy/completed exit. Do not block service shutdown on a
        # stdout/status consumer or print restricted paths and exception details.
        return 3
    except Exception:
        return 1


if __name__ == "__main__":
    sys.exit(main())
