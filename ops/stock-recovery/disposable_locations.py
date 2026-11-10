#!/usr/bin/env python3
"""Allocate disposable download and test-root locations, failing closed.

Standard-library-only, offline, no execution. This replaces the inline
workflow shell that printed ``DOWNLOAD``/``ROOT`` lines pointing under
``$RUNNER_TEMP`` into ``$GITHUB_ENV``. That shell silently produced a
filesystem-root child path when ``RUNNER_TEMP`` was missing or relative.
Here the base must be an existing non-symlink directory of sufficient
depth so each allocated child satisfies the disposable-cleanup depth rule,
the Actions run/attempt values must be bounded numeric identifiers, and
the two appended lines never carry a newline or control character. The
allocation is location evidence only, not service, journal, watchdog,
quiescence, restart, or recovery proof.
"""

import os
from pathlib import Path
import re
import sys


class DisposableLocationsError(ValueError):
    """A disposable location cannot be allocated safely."""


_NUMERIC = re.compile(r"[0-9]+\Z")


def _checked_numeric(env, name):
    """Return one bounded numeric Actions identifier, failing closed."""
    value = env.get(name)
    if not isinstance(value, str) or not value:
        raise DisposableLocationsError("missing disposable location value: " + name)
    if value != value.strip() or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise DisposableLocationsError("malformed disposable location value: " + name)
    if len(value) > 32:
        raise DisposableLocationsError("oversized disposable location value: " + name)
    if _NUMERIC.fullmatch(value) is None:
        raise DisposableLocationsError("malformed disposable location value: " + name)
    return value


def _checked_base(env):
    """Return the runner-temp base directory, failing closed."""
    value = env.get("RUNNER_TEMP")
    if not isinstance(value, str) or not value:
        raise DisposableLocationsError("missing disposable location value: RUNNER_TEMP")
    if value != value.strip() or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise DisposableLocationsError("malformed disposable location value: RUNNER_TEMP")
    if len(value) > 1024:
        raise DisposableLocationsError("oversized disposable location value: RUNNER_TEMP")
    base = Path(value)
    if not base.is_absolute():
        raise DisposableLocationsError("runner temp must be absolute")
    # Each child must clear the disposable-cleanup depth rule (3+ parts),
    # so the base itself needs at least 2 parts (e.g. /home/runner/work/_temp
    # or <temp under /tmp>). / and /tmp alone fail here.
    if len(base.parts) < 2:
        raise DisposableLocationsError("runner temp is too shallow")
    if base.is_symlink():
        raise DisposableLocationsError("runner temp is a symlink")
    if not base.is_dir():
        raise DisposableLocationsError("runner temp is not a directory")
    return base


def build_locations(env):
    """Return the disposable ``(download, root)`` paths for one Actions run."""
    if not hasattr(env, "get"):
        raise DisposableLocationsError("disposable location environment must be a mapping")
    base = _checked_base(env)
    run_id = _checked_numeric(env, "GITHUB_RUN_ID")
    run_attempt = _checked_numeric(env, "GITHUB_RUN_ATTEMPT")
    download = base / ("stock-runtime-%s-%s" % (run_id, run_attempt))
    root = base / ("stock-root-%s-%s" % (run_id, run_attempt))
    return download, root


def write_env_file(env, download, root):
    """Append the ``DOWNLOAD``/``ROOT`` lines to the ``GITHUB_ENV`` file."""
    raw = env.get("GITHUB_ENV")
    if not isinstance(raw, str) or not raw:
        raise DisposableLocationsError("missing disposable location value: GITHUB_ENV")
    if raw.strip() != raw or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise DisposableLocationsError("malformed disposable location value: GITHUB_ENV")
    if len(raw) > 4096:
        raise DisposableLocationsError("oversized disposable location value: GITHUB_ENV")
    target = Path(raw)
    if not target.is_absolute():
        raise DisposableLocationsError("github env must be absolute")
    if target.is_symlink():
        raise DisposableLocationsError("github env is a symlink")
    lines = "DOWNLOAD=%s\nROOT=%s\n" % (download, root)
    try:
        with target.open("a", encoding="utf-8") as handle:
            handle.write(lines)
    except OSError as exc:
        raise DisposableLocationsError("github env cannot be written") from exc
    return lines


def main(argv=None):
    # Allocation takes no arguments; argv exists only for symmetry with the
    # other offline helpers.
    del argv
    try:
        env = os.environ
        download, root = build_locations(env)
        write_env_file(env, download, root)
    except DisposableLocationsError as exc:
        # Do not print untrusted environment values into CI logs.
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
