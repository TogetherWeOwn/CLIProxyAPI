#!/usr/bin/env python3
"""Record the source-only HOLD report for the source-packet job.

Standard-library-only, offline. This replaces the last multi-line workflow
shell block, which ran two module invocations in sequence: the packet
verifier captured into ``source-binding.json``, then the actions identity
written to ``actions-identity.json``. The composition is now regression
tested — both commands run with fixed argv, a nonzero packet exit code
stops the report before the identity is written, and child exit codes
propagate exactly as the old fail-fast shell did. Children inherit the
runner environment (``HEAD_SHA`` and the ``GITHUB_*`` values); the identity
module validates them and fails closed. The report binds one exact PR head
and run to both evidence files while retaining **qualification=HOLD** and
**service_recovery=NOT_TESTED**: it is source-binding evidence, never
service, journal, watchdog, quiescence, restart, or recovery proof.
"""

import subprocess
import sys


EVIDENCE_DIR = "qualification-evidence"

# These argv lists are token-identical to the former workflow shell lines.
PACKET_COMMAND = [
    "python3", "-I", "ops/stock-recovery/stdout_evidence.py",
    "--dir", EVIDENCE_DIR, "--output", "source-binding.json",
    "--", "python3", "-I", "ops/stock-recovery/packet.py",
    "ops/stock-recovery/manifest.json",
]
IDENTITY_COMMAND = [
    "python3", "-I", "ops/stock-recovery/actions_identity.py",
    "--mode", "source", "--output", EVIDENCE_DIR + "/actions-identity.json",
]


class SourceReportError(ValueError):
    """The HOLD report cannot be recorded."""


def record():
    """Run the packet capture, then the identity, returning a child code.

    The packet runs first and its evidence is retained before the identity
    is attempted, exactly as the workflow shell ordered them. A nonzero
    packet exit code returns immediately without writing the identity. A
    command that fails to start at all raises ``SourceReportError``
    instead of returning a code.
    """
    for command in (PACKET_COMMAND, IDENTITY_COMMAND):
        try:
            completed = subprocess.run(command, check=False)
        except OSError as exc:
            # Do not echo argv or environment values into CI logs on failure.
            raise SourceReportError("report command failed to start") from exc
        if completed.returncode != 0:
            return completed.returncode
    return 0


def main():
    try:
        return record()
    except SourceReportError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
