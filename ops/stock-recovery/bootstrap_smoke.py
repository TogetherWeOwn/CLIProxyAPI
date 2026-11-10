#!/usr/bin/env python3
"""Run the frozen-runtime ``--help`` smoke in an unprivileged empty root.

Standard-library-only. This replaces the inline workflow shell that ran
``sudo unshare ... chroot ... --help`` so the exact fixed argument vector,
root/output validation, and child exit-code propagation are regression
tested. The only command executed is the fixed help smoke: no host state,
store, provider, network interface, daemon or environment is passed — the
environment is emptied apart from a minimal fixed ``PATH``. It is a lineage
smoke input, not service, journal, watchdog, quiescence, restart, or
recovery proof.
"""

import argparse
import subprocess
import sys
from pathlib import Path


# Fixed smoke environment: empty apart from a minimal PATH, so no host
# credentials, store or provider configuration can leak into the chroot.
SMOKE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
# Unprivileged nobody user/group inside the disposable root.
USER_SPEC = "65534:65534"
BINARY_PATH = "/CLIProxyAPI"


class BootstrapSmokeError(ValueError):
    """The smoke command cannot be constructed or executed safely."""


def build_smoke_command(root):
    """Build the exact fixed help-smoke argument vector for ``root``.

    ``sudo unshare --net --pid --fork --kill-child`` isolates the smoke in
    fresh network/PID namespaces; ``env -i`` drops every host variable
    apart from the fixed ``PATH``; ``chroot --userspec`` runs the frozen
    binary as the unprivileged nobody user inside the disposable root.
    """
    return [
        "sudo", "unshare", "--net", "--pid", "--fork", "--kill-child",
        "env", "-i", "PATH=" + SMOKE_PATH,
        "chroot", "--userspec=" + USER_SPEC, str(root), BINARY_PATH, "--help",
    ]


def _checked_root(raw):
    """Return the validated disposable test-root path, or fail closed."""
    if not isinstance(raw, str) or not raw:
        raise BootstrapSmokeError("test root is empty")
    if raw.strip() != raw or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise BootstrapSmokeError("test root is malformed")
    root = Path(raw)
    if not root.is_absolute():
        raise BootstrapSmokeError("test root must be absolute")
    # Never chroot into the filesystem root or a single-level system
    # directory such as /tmp. Workflow roots sit one level below the
    # runner temp directory, e.g. <temp>/stock-root-<run>-<attempt>.
    if len(root.parts) < 3:
        raise BootstrapSmokeError("test root is too shallow")
    if root.is_symlink():
        raise BootstrapSmokeError("test root is a symlink")
    if not root.is_dir():
        raise BootstrapSmokeError("test root is not a directory")
    return root


def _checked_output(raw):
    """Return the validated retained help-output path, or fail closed."""
    if not isinstance(raw, str) or not raw:
        raise BootstrapSmokeError("output path is empty")
    if raw.strip() != raw or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise BootstrapSmokeError("output path is malformed")
    output = Path(raw)
    if output.is_symlink():
        raise BootstrapSmokeError("output path is a symlink")
    if output.exists() and output.is_dir():
        raise BootstrapSmokeError("output path is a directory")
    parent = output.parent
    if parent.is_symlink() or not parent.is_dir():
        raise BootstrapSmokeError("output directory is not a directory")
    return output


def run_smoke(root, output):
    """Run the help smoke and return the child exit code.

    The child's stdout and stderr are both captured into the retained
    output file, exactly as the workflow shell redirect did. A child that
    fails to start at all (missing sudo/unshare/chroot) raises
    ``BootstrapSmokeError`` instead of returning its exit code.
    """
    root_path = _checked_root(root)
    output_path = _checked_output(output)
    command = build_smoke_command(root_path)
    try:
        with output_path.open("wb") as stream:
            completed = subprocess.run(
                command, stdout=stream, stderr=subprocess.STDOUT, check=False)
    except OSError as exc:
        # Do not echo untrusted path values into CI logs on failure.
        raise BootstrapSmokeError("smoke command failed to start") from exc
    return completed.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", help="disposable test root holding the frozen runtime")
    parser.add_argument("output", help="retained help output file")
    args = parser.parse_args(argv)
    try:
        return run_smoke(args.root, args.output)
    except (BootstrapSmokeError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
