#!/usr/bin/env python3
"""Remove disposable download and test-root directories, failing closed.

Standard-library-only, offline, no execution. This replaces the inline
workflow shell loop that ran ``rm -r`` on runner-temp paths with a checked
removal: each target must be an absolute path of sufficient depth, must not
itself be a symlink or a regular file, and absence is an idempotent no-op.
Removing a symlinked or wrongly typed path fails closed and preserves its
target. The removal of each existing directory is verified afterwards. This
is cleanup evidence only, not service, journal, watchdog, quiescence,
restart, or recovery proof.
"""

import argparse
import os
from pathlib import Path
import shutil
import stat
import sys


class DisposableCleanupError(ValueError):
    """A disposable path cannot be removed safely."""


def _checked_path(raw):
    """Return one absolute disposable directory path, or fail closed."""
    if not isinstance(raw, str) or not raw:
        raise DisposableCleanupError("disposable path is empty")
    if raw.strip() != raw or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise DisposableCleanupError("disposable path is malformed")
    path = Path(raw)
    if not path.is_absolute():
        raise DisposableCleanupError("disposable path must be absolute")
    # Never remove the filesystem root or a single-level system directory
    # such as /tmp. Workflow targets sit one level below the runner temp
    # directory, e.g. <temp>/stock-root-<run>-<attempt>.
    if len(path.parts) < 3:
        raise DisposableCleanupError("disposable path is too shallow")
    return path


def remove_disposable(raw):
    """Remove one disposable directory.

    Returns ``"removed"`` when an existing directory is deleted and
    verified gone, or ``"absent"`` when the path does not exist. Symlinks
    and regular files fail closed and are preserved.
    """
    path = _checked_path(raw)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "absent"
    except OSError as exc:
        raise DisposableCleanupError("disposable path cannot be inspected") from exc
    if stat.S_ISLNK(info.st_mode):
        raise DisposableCleanupError("disposable path is a symlink")
    if not stat.S_ISDIR(info.st_mode):
        raise DisposableCleanupError("disposable path is not a directory")
    try:
        shutil.rmtree(path)
    except OSError as exc:
        raise DisposableCleanupError("disposable path cannot be removed") from exc
    if os.path.lexists(path):
        raise DisposableCleanupError("disposable path still exists after removal")
    return "removed"


def remove_disposables(raw_paths):
    """Remove every disposable path and return the cleanup evidence."""
    if not isinstance(raw_paths, (list, tuple)) or not raw_paths:
        raise DisposableCleanupError("no disposable paths given")
    removed = []
    absent = []
    for raw in raw_paths:
        outcome = remove_disposable(raw)
        if outcome == "removed":
            removed.append(str(raw))
        else:
            absent.append(str(raw))
    return {
        "removed": removed,
        "absent": absent,
        "qualification": "HOLD",
        "service_recovery": "NOT_TESTED",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="disposable directories to remove")
    args = parser.parse_args(argv)
    import json

    try:
        result = remove_disposables(args.paths)
    except DisposableCleanupError as exc:
        # Do not echo untrusted path values into CI logs on failure.
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
