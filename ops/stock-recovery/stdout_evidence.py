#!/usr/bin/env python3
"""Capture one evidence command's stdout into a retained workflow evidence file.

Standard-library-only, offline. This replaces the inline workflow shell that
created an evidence directory with ``mkdir -p`` and redirected one module's
stdout into a retained file with ``>``, so directory handling, byte capture
and child exit-code propagation are regression tested. The captured evidence
is a lineage checkpoint, not service, journal, watchdog, quiescence,
restart, or recovery proof.
"""

import argparse
import subprocess
import sys
from pathlib import Path


class StdoutEvidenceError(ValueError):
    """The evidence capture cannot be constructed or executed safely."""


def _checked_dir(raw):
    """Return the validated evidence directory path, or fail closed."""
    if not isinstance(raw, str) or not raw:
        raise StdoutEvidenceError("evidence directory is empty")
    if raw.strip() != raw or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise StdoutEvidenceError("evidence directory is malformed")
    directory = Path(raw)
    if directory.is_symlink():
        raise StdoutEvidenceError("evidence directory is a symlink")
    if directory.exists() and not directory.is_dir():
        raise StdoutEvidenceError("evidence directory is not a directory")
    return directory


def _checked_output(directory, raw):
    """Return the validated bare-filename evidence output path, or fail closed."""
    if not isinstance(raw, str) or not raw:
        raise StdoutEvidenceError("output name is empty")
    if raw.strip() != raw or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise StdoutEvidenceError("output name is malformed")
    if "/" in raw or "\\" in raw or raw in (".", ".."):
        raise StdoutEvidenceError("output name must be a bare filename")
    output = directory / raw
    if output.is_symlink():
        raise StdoutEvidenceError("output path is a symlink")
    if output.exists() and output.is_dir():
        raise StdoutEvidenceError("output path is a directory")
    return output


def capture(directory, output, command):
    """Run ``command`` and return its exit code, capturing stdout to output.

    The evidence directory is created with parents when missing, exactly as
    ``mkdir -p`` did, but an existing symlinked or non-directory path fails
    closed — stricter than the shell, which would have followed the link.
    Only the child's stdout is captured; stderr stays on the workflow log
    exactly as the old ``>`` redirect behaved. An existing regular output
    file is truncated on a fresh run, like the old shell redirect. A command
    that fails to start at all (missing binary) raises ``StdoutEvidenceError``
    instead of returning its exit code.
    """
    directory_path = _checked_dir(directory)
    if not isinstance(command, (list, tuple)) or not command:
        raise StdoutEvidenceError("evidence command is empty")
    if not all(isinstance(part, str) and part for part in command):
        raise StdoutEvidenceError("evidence command is malformed")
    output_path = _checked_output(directory_path, output)
    try:
        directory_path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StdoutEvidenceError("evidence directory cannot be created") from exc
    if directory_path.is_symlink() or not directory_path.is_dir():
        raise StdoutEvidenceError("evidence directory is not a directory")
    try:
        with output_path.open("wb") as stream:
            completed = subprocess.run(
                list(command), stdout=stream, check=False)
    except OSError as exc:
        # Do not echo untrusted argv into CI logs on failure.
        raise StdoutEvidenceError("evidence command failed to start") from exc
    return completed.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, help="evidence directory to create if missing")
    parser.add_argument("--output", required=True, help="bare evidence filename inside the directory")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command after -- whose stdout is retained")
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    try:
        return capture(args.dir, args.output, command)
    except (StdoutEvidenceError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
