"""Restricted, idempotent whole-tree restoration after external quiescence.

This module does not stop writers or authorize a start. The caller must hold the
installation lock and prove manager AND daemon quiescence before entering. Roots
are explicit open directory handles; an accepted plan lists every permitted new
entry. Never remove an unknown entry or follow a link to make restoration pass.
"""
from contextlib import contextmanager
import os
import stat

from .durable import Rejected, atomic_write, canonical, component, digest
from .inventory import relative_path, snapshot, validate_tree


def stages(tree):
    """Names must be reserved in the accepted write set before admission."""
    result = {}
    for path, row in tree["entries"].items():
        if row["kind"] == "file":
            parent, _, _ = path.rpartition("/")
            name = ".recovery-restore-" + digest(path.encode("utf-8"))
            result[path] = parent + "/" + name if parent else name
    return result


@contextmanager
def parent_of(root, path):
    relative_path(path)
    parts = path.split("/")
    fd = os.dup(root)
    try:
        for name in parts[:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd, parts[-1]
    finally:
        os.close(fd)


def validate_plan(tree, blobs, additions):
    validate_tree(tree, blobs)
    if type(additions) is not dict or len(additions) + len(tree["entries"]) > 4096:
        raise Rejected("restore-additions-schema")
    reserved = stages(tree)
    entries = tree["entries"]
    if (set(reserved.values()) & (set(entries) | set(additions))
            or len(set(reserved.values())) != len(reserved)
            or len(entries) + len(additions) + len(reserved) > 4096):
        raise Rejected("restore-stage-collision-or-capacity")
    if any(row["kind"] == "directory" and row["mode"] & 0o700 != 0o700 for row in entries.values()):
        raise Rejected("restore-directory-access-unsupported")
    for path, kind in additions.items():
        relative_path(path)
        if path in entries or kind not in ("file", "directory"):
            raise Rejected("restore-addition-conflict")
        parent = path.rpartition("/")[0] or "."
        if entries.get(parent, {}).get("kind", additions.get(parent)) != "directory":
            raise Rejected("restore-addition-parent")
    # This implementation supports a single accepted ownership domain per root.
    owner = (entries["."]["uid"], entries["."]["gid"])
    if any((row["uid"], row["gid"]) != owner for row in entries.values()):
        raise Rejected("restore-mixed-ownership-unsupported")
    return reserved, owner


def restore_tree(root, tree, blobs, additions, *, fault=None, check=lambda: None):
    """Restore the full accepted root, then independently rescan bytes/metadata.

    A failure returns no oracle receipt. Known staging files are reconciled on a
    retry, including files left by failed writes before rename. New candidate
    entries are removed only if explicitly in additions. No in-memory partial
    progress is needed to retry. A manager-enforced deadline remains external;
    check() supplies accounting at every operation, not a hard I/O timeout.
    """
    reserved, (uid, gid) = validate_plan(tree, blobs, additions)
    check()
    current, _ = snapshot(root, uid=uid, gid=gid)
    expected = tree["entries"]
    allowed = {path: row["kind"] for path, row in expected.items()}
    allowed.update(additions)
    allowed.update(dict.fromkeys(reserved.values(), "file"))
    for path, row in current["entries"].items():
        if allowed.get(path) != row["kind"]:
            raise Rejected("restore-unexpected-entry-or-kind")
    # Verify the complete current inventory before the first mutation. A changed
    # type, unsafe metadata or unknown entry must not cause partial cleanup.
    for path in sorted(set(current["entries"]) - set(expected), key=lambda p: (-p.count("/"), p)):
        check()
        with parent_of(root, path) as (fd, name):
            if current["entries"][path]["kind"] == "directory":
                os.rmdir(name, dir_fd=fd)
            else:
                os.unlink(name, dir_fd=fd)
            os.fsync(fd)
    for path in sorted(expected, key=lambda p: (p.count("/"), p)):
        if path == "." or expected[path]["kind"] != "directory":
            continue
        check()
        with parent_of(root, path) as (fd, name):
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                os.fchown(child, uid, gid)
                os.fchmod(child, expected[path]["mode"])
                os.fsync(child)
                os.fsync(fd)
            finally:
                os.close(child)
    for path, row in sorted(expected.items()):
        if row["kind"] != "file":
            continue
        check()
        with parent_of(root, path) as (fd, name):
            atomic_write(fd, name, blobs[row["sha256"]], uid=row["uid"], gid=row["gid"],
                         mode=row["mode"], fault=fault, stage_name=component(reserved[path].split("/")[-1]))
    check()
    os.fchown(root, uid, gid)
    os.fchmod(root, expected["."]["mode"])
    os.fsync(root)
    actual, actual_blobs = snapshot(root, uid=uid, gid=gid)
    if actual != tree or actual_blobs != blobs:
        raise Rejected("restore-oracle-mismatch")
    check()
    return {"schema": "host-recovery-tree-restored-v1", "entries": len(expected),
            "baseline_sha256": digest(canonical(tree)),
            "production_acceptance": False}
