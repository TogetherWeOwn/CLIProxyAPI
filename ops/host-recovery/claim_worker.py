"""Manager-launched identity worker; never grants or runs restoration/start.

Run trusted installed code with Python -I and explicit independently provisioned
launch/directory pins. This is not a recovery service installer or execution CLI.
The program deliberately exits unresolved even after a successful identity claim.
"""
import argparse
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_recovery.commands import Deadline, LocalCommands
from host_recovery.durable import canonical
from host_recovery.installation import DirectoryApproval
from host_recovery.launch import load_launch
from host_recovery.worker_runtime import run_worker


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "host-recovery-worker: invalid-arguments\n")


def main(argv=None):
    parser = Parser(description="Claim identity as the pinned worker; no recovery/start permission.")
    parser.add_argument("--approval", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--endpoint-device", type=int, required=True)
    parser.add_argument("--endpoint-inode", type=int, required=True)
    parser.add_argument("--deadline", type=float, required=True, help="Absolute original local monotonic deadline")
    args = parser.parse_args(argv)
    commands = LocalCommands(time.monotonic)
    try:
        timer = Deadline(time.monotonic, args.deadline)
        timer.remaining()
        approval = load_launch(args.approval, sha256=args.sha256, uid=args.uid, gid=args.gid)
        endpoint = DirectoryApproval(args.endpoint, args.endpoint_device, args.endpoint_inode,
                                     approval.supervisor.uid, approval.supervisor.gid, 0o700)
        timer.remaining()
        result = run_worker(approval, endpoint=endpoint, deadline=args.deadline, commands=commands)
        timer.remaining()
        raw = canonical({**result, "launch_sha256": args.sha256})
        if os.write(sys.stdout.fileno(), raw) != len(raw):
            raise OSError("worker-output-incomplete")
        return 3
    except Exception:
        sys.stderr.write("host-recovery-worker: unavailable\n")
        return 1
    finally:
        # Never add an unmetered wait. This single-process CLI then exits; the
        # embedding API instead requires a caller-owned transport/reaping loop.
        commands.reap()


if __name__ == "__main__":
    sys.exit(main())
