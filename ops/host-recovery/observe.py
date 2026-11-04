"""Bounded manager-launched observation, not a recovery service or installer.

Run with Python -I from trusted package code as the pinned calling MainPID. Every
input is explicit. SIGTERM/INT interrupt the local wait, but never clear intent,
start/restart a worker or claim a completed recovery. No unit is installed here.
"""
import argparse
import os
from pathlib import Path
import signal
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_recovery.commands import Deadline
from host_recovery.durable import canonical
from host_recovery.launch import load_launch
from host_recovery.observation import observe_request


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "host-recovery-observe: invalid-arguments\n")


def main(argv=None):
    parser = Parser(description="Read-only locked observation; cannot execute recovery or grant starts.")
    parser.add_argument("--approval", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--deadline", type=float, required=True, help="Explicit absolute local monotonic deadline")
    parser.add_argument("--interval", type=float, required=True)
    parser.add_argument("--max-observations", type=int, required=True)
    args = parser.parse_args(argv)
    previous = {}
    try:
        timer = Deadline(time.monotonic, args.deadline)
        timer.remaining()
        stop = threading.Event()
        def shutdown(signum, frame):
            stop.set()
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, shutdown)
        approval = load_launch(args.approval, sha256=args.sha256, uid=args.uid, gid=args.gid)
        timer.remaining()
        result = observe_request(approval, deadline=args.deadline, interval=args.interval,
            max_observations=args.max_observations, stop=stop.is_set, wait=stop.wait)
        timer.remaining()
        # Only after the lock/ancestry context has closed. This is an unresolved
        # read-only receipt, not a recovery terminal or alert-delivery receipt.
        raw = canonical({**result, "launch_sha256": args.sha256})
        # No buffered tail to flush/retry at interpreter shutdown after EPIPE or
        # a partial write. Output errors never manufacture a complete receipt.
        if os.write(sys.stdout.fileno(), raw) != len(raw):
            raise OSError("observation-output-incomplete")
        return 3
    except Exception:
        sys.stderr.write("host-recovery-observe: unavailable\n")
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    sys.exit(main())
