#!/usr/bin/env python3
"""Prepare the disposable chroot root for the frozen-runtime help smoke.

Standard-library-only, offline, no execution. This installs the already
materialized frozen binary and loader set into a new empty root and
recreates the stock image's merged-usr topology so the binary's PT_INTERP
loader resolves without host libraries. It is a lineage smoke input, not
service, journal, watchdog, quiescence, restart, or recovery proof.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


MAX_BINARY = 128 * 1024 * 1024
MAX_LIB = 8 * 1024 * 1024
BINARY_NAME = "CLIProxyAPI"
# Frozen loader set, relative to the materialized ``libs`` root. The binary
# itself lives beside that root as ``runtime/CLIProxyAPI``.
FROZEN_LIBS = (
    "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "usr/lib/x86_64-linux-gnu/libc.so.6",
    "usr/lib/x86_64-linux-gnu/libm.so.6",
    "usr/lib/x86_64-linux-gnu/libdl.so.2",
    "usr/lib/x86_64-linux-gnu/libpthread.so.0",
    "usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
    "etc/ld.so.cache",
)
LOADER_NAME = "ld-linux-x86-64.so.2"
# Absolute (inside the chroot) loader path the binary's PT_INTERP expects.
LOADER_INTERP = "/lib64/" + LOADER_NAME


class BootstrapRootError(ValueError):
    """The disposable root cannot be established."""


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _checked_source(runtime_root, relative, limit):
    """Read one bounded regular source file, rejecting symlinks."""
    if not isinstance(relative, str) or not relative or relative.startswith("/"):
        raise BootstrapRootError("invalid source path")
    if any(part in ("", ".", "..") for part in relative.split("/")):
        raise BootstrapRootError("invalid source path")
    current = runtime_root
    for part in relative.split("/"):
        current = current / part
        if current.is_symlink():
            raise BootstrapRootError("source path is a symlink: " + relative)
    try:
        info = current.stat()
    except OSError as exc:
        raise BootstrapRootError("source file missing: " + relative) from exc
    if not stat.S_ISREG(info.st_mode):
        raise BootstrapRootError("source file is not regular: " + relative)
    if not 0 < info.st_size <= limit:
        raise BootstrapRootError("source file size out of bounds: " + relative)
    return current.read_bytes()


def _publish(root, relative, data, mode):
    """Write one file without overwriting, with an exact mode."""
    target = root
    for part in relative.split("/")[:-1]:
        target = target / part
        if target.is_symlink():
            raise BootstrapRootError("root path is a symlink: " + relative)
        target.mkdir(mode=0o755, exist_ok=True)
        if target.is_symlink() or not target.is_dir():
            raise BootstrapRootError("root path is not a directory: " + relative)
    leaf = root / relative
    if leaf.is_symlink():
        raise BootstrapRootError("root path is a symlink: " + relative)
    with leaf.open("xb") as stream:
        stream.write(data)
    os.chmod(leaf, mode)
    return leaf


def prepare_root(runtime_dir, root):
    """Create ``root`` and install the frozen runtime into it.

    ``runtime_dir`` is the directory holding ``CLIProxyAPI`` and ``libs/``
    as published by ``runtime_artifact``. ``root`` must not already exist.
    """
    runtime_dir = Path(runtime_dir)
    root = Path(root)
    if runtime_dir.is_symlink() or not runtime_dir.is_dir():
        raise BootstrapRootError("runtime directory is not a directory")
    if root.is_symlink() or root.exists():
        raise BootstrapRootError("test root already exists")
    # Read and bound every source byte before creating anything, so a
    # partial source set never leaves a half-populated root behind.
    binary = _checked_source(runtime_dir, BINARY_NAME, MAX_BINARY)
    libs = {name: _checked_source(runtime_dir, "libs/" + name, MAX_LIB)
            for name in FROZEN_LIBS}
    root.mkdir(mode=0o755, parents=False, exist_ok=False)
    if root.is_symlink() or not root.is_dir():
        raise BootstrapRootError("test root is not a directory")
    os.chmod(root, 0o755)
    _publish(root, BINARY_NAME, binary, 0o755)
    for name in FROZEN_LIBS:
        mode = 0o644 if name == "etc/ld.so.cache" else 0o755
        _publish(root, name, libs[name], mode)
    # Recreate the image's merged-usr topology for PT_INTERP resolution:
    # /lib64 -> usr/lib64 with the loader symlink, /lib -> usr/lib.
    (root / "usr/lib64").mkdir(mode=0o755, exist_ok=True)
    if (root / "usr/lib64").is_symlink():
        raise BootstrapRootError("root path is a symlink: usr/lib64")
    loader_link = root / "usr/lib64" / LOADER_NAME
    loader_link.symlink_to("/lib/x86_64-linux-gnu/" + LOADER_NAME)
    (root / "lib").symlink_to("usr/lib")
    (root / "lib64").symlink_to("usr/lib64")
    # The interpreter path must resolve inside the new root. Its loader
    # symlink is absolute, so it only resolves under chroot; emulate the
    # chroot lookup by stripping the leading slash and following the
    # merged-usr links relative to the root instead of the host root.
    if os.readlink(loader_link) != "/lib/x86_64-linux-gnu/" + LOADER_NAME:
        raise BootstrapRootError("loader link does not match the frozen interpreter path")
    frozen_loader = root / "usr/lib/x86_64-linux-gnu" / LOADER_NAME
    if frozen_loader.is_symlink() or not frozen_loader.is_file():
        raise BootstrapRootError("loader does not resolve inside the test root")
    if frozen_loader.read_bytes() != libs["usr/lib/x86_64-linux-gnu/" + LOADER_NAME]:
        raise BootstrapRootError("resolved loader is not the frozen loader")
    return {
        "binary_digest": digest(binary),
        "binary_size": len(binary),
        "libs": {name: digest(libs[name]) for name in FROZEN_LIBS},
        "loader_interp": LOADER_INTERP,
        "qualification": "HOLD",
        "service_recovery": "NOT_TESTED",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime_dir", help="materialized runtime directory")
    parser.add_argument("root", help="new disposable test root to create")
    args = parser.parse_args(argv)
    try:
        result = prepare_root(args.runtime_dir, args.root)
    except (BootstrapRootError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
