"""Read-only manager-launched status; no live defaults or service operations.

Run with Python -I from trusted repository/package code. This process must itself
be the approved supervisor MainPID. It is not a client that attaches to or takes
ownership from a running supervisor, and is not a persistent recovery service.
"""
import argparse
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_recovery.commands import Deadline
from host_recovery.durable import canonical
from host_recovery.launch import inspect_status, load_launch


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default includes arbitrary supplied values and paths.
        self.exit(2, "host-recovery-status: invalid-arguments\n")


def main(argv=None):
    parser = Parser(description="Read-only pinned calling-supervisor status; no execution or start permission.")
    parser.add_argument("--approval", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--deadline", type=float, required=True, help="Explicit absolute local monotonic deadline")
    args = parser.parse_args(argv)
    try:
        timer = Deadline(time.monotonic, args.deadline)
        timer.remaining()
        approval = load_launch(args.approval, sha256=args.sha256, uid=args.uid, gid=args.gid)
        timer.remaining()
        result = inspect_status(approval, deadline=args.deadline)
        timer.remaining()
        sys.stdout.buffer.write(canonical({**result, "launch_sha256": args.sha256}))
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        # Restricted path/manager/parser exception text never becomes a receipt.
        # A broken output pipe is also a failure, not an alternate stdout receipt.
        sys.stderr.write("host-recovery-status: unavailable\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
