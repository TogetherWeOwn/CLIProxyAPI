#!/usr/bin/env python3
"""Verify that frozen-runtime help output identifies the candidate binary.

Standard-library-only, offline, no execution. This checks the retained
``--help`` output of the frozen runtime for bounded size and the candidate's
version/commit self-report plus usage and core flag markers. It is a
lineage smoke input, not service, journal, watchdog, quiescence, restart,
or recovery proof.
"""

import argparse
import hashlib
import sys

MAX_HELP_BYTES = 65536

# (label, required substring). The binary self-reports version/commit;
# usage and flags show the executable that ran is the expected stock binary.
MARKERS = (
    ("version", "CLIProxyAPI Version: v8.0.60"),
    ("commit", "Commit: 91e0dee"),
    ("usage", "\nUsage of /CLIProxyAPI\n"),
    ("config flag", "\n  -config"),
    ("tui flag", "\n  -tui"),
)


class HelpIdentityError(ValueError):
    """Help output does not identify the frozen candidate."""


def verify_help_output(data):
    if not isinstance(data, (bytes, bytearray)):
        raise HelpIdentityError("help output must be bytes")
    if not 0 < len(data) <= MAX_HELP_BYTES:
        raise HelpIdentityError("help output size out of bounds")
    try:
        text = bytes(data).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HelpIdentityError("help output is not valid UTF-8") from exc
    for label, marker in MARKERS:
        if marker not in text:
            raise HelpIdentityError("help output missing " + label + " marker")
    return {
        "help_sha256": hashlib.sha256(bytes(data)).hexdigest(),
        "markers": sorted(label for label, _ in MARKERS),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="retained help output file")
    args = parser.parse_args(argv)
    with open(args.path, "rb") as handle:
        data = handle.read()
    try:
        result = verify_help_output(data)
    except HelpIdentityError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("help sha256:", result["help_sha256"])
    print("markers:", ", ".join(result["markers"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
