"""Root-provisioned manager entrypoint; conservative runners only, no installer."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_recovery.jobs import recovery_unit
from host_recovery.launch import load_launch
from host_recovery.service_anchor import anchor_argv, read_service_anchor


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "host-recovery-service: invalid-arguments\n")


def main(argv=None):
    parser = Parser(description="Launch only the fixed unresolved supervisor or identity worker.")
    parser.add_argument("--role", required=True, choices=("supervisor", "worker"))
    parser.add_argument("--anchor", required=True)
    args = parser.parse_args(argv)
    try:
        anchor = read_service_anchor(args.anchor, role=args.role)
        options = anchor["arguments"]
        approval = load_launch(options["approval"], sha256=options["sha256"], uid=options["uid"], gid=options["gid"])
        unit = approval.supervisor.unit if args.role == "supervisor" else recovery_unit(approval.job.request_id)
        if anchor["unit"] != unit:
            return 1
        # Fixed repository modules only. Neither an anchor nor an environment
        # value can name a callback/module, grant execution or load recovery code.
        if args.role == "supervisor":
            from supervise import main as run
        else:
            from claim_worker import main as run
        return run(anchor_argv(anchor))
    except Exception:
        # Never disclose restricted anchor/configuration paths or exception text.
        return 1


if __name__ == "__main__":
    sys.exit(main())
