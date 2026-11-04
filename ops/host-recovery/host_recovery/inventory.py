"""Whole-directory inventory and restricted immutable baseline storage.

This is a component, not a mutator or start authorization. A scan is valid only
while cooperating writers are excluded. Restricted manifests include paths and
hashes; public receipts expose only aggregate counts and the manifest digest.
"""
import os
import re
import stat

from .durable import Rejected, atomic_write, canonical, component, decode, digest, read_file, signature

MAX_ENTRIES = 4096
MAX_TREE_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 16
HASH = re.compile(r"[a-f0-9]{64}\Z")


def relative_path(name):
    if type(name) is not str:
        raise Rejected("relative-path-required")
    for part in name.split("/"):
        component(part)
    return name


def metadata(st, uid, gid):
    if (st.st_uid, st.st_gid) != (uid, gid) or stat.S_IMODE(st.st_mode) & 0o7022:
        raise Rejected("unsupported-tree-ownership-or-mode")
    return {"uid": st.st_uid, "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode)}


def snapshot(root_fd, *, uid, gid):
    entries, blobs, signatures = {}, {}, {}
    size = 0

    def walk(fd, prefix, depth):
        nonlocal size
        if depth > MAX_DEPTH:
            raise Rejected("tree-depth-limit")
        before = os.fstat(fd)
        row = metadata(before, uid, gid)
        if not stat.S_ISDIR(before.st_mode) or os.listxattr(fd):
            raise Rejected("unsupported-directory-metadata")
        entries[prefix or "."] = {"kind": "directory", **row}
        signatures[prefix or "."] = signature(before)
        names = sorted(os.listdir(fd))
        for name in names:
            component(name)
            if len(entries) >= MAX_ENTRIES:
                raise Rejected("tree-entry-limit")
            path = prefix + "/" + name if prefix else name
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if st.st_dev != before.st_dev:
                raise Rejected("cross-device-tree")
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    if signature(st) != signature(os.fstat(child)):
                        raise Rejected("directory-changed-before-read")
                    walk(child, path, depth + 1)
                    if signature(st) != signature(os.stat(name, dir_fd=fd, follow_symlinks=False)):
                        raise Rejected("directory-changed-during-read")
                finally:
                    os.close(child)
            else:
                raw, got = read_file(fd, name)
                if signature(st) != signature(got):
                    raise Rejected("file-changed-before-read")
                row = metadata(got, uid, gid)
                size += len(raw)
                if size > MAX_TREE_BYTES:
                    raise Rejected("tree-byte-limit")
                pin = digest(raw)
                entries[path] = {"kind": "file", "sha256": pin, "size": len(raw), **row}
                signatures[path] = signature(got)
                blobs[pin] = raw
        if names != sorted(os.listdir(fd)) or signature(before) != signature(os.fstat(fd)):
            raise Rejected("inventory-changed-during-read")

    walk(root_fd, "", 0)
    # A second scan of identities catches changes in earlier siblings while a
    # later subtree was read. This is not a substitute for writer quiescence.
    def recheck(fd, prefix):
        if signature(os.fstat(fd)) != signatures[prefix or "."]:
            raise Rejected("inventory-changed-after-read")
        for name in sorted(os.listdir(fd)):
            path = prefix + "/" + name if prefix else name
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if path not in signatures or signature(st) != signatures[path]:
                raise Rejected("inventory-changed-after-read")
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    recheck(child, path)
                finally:
                    os.close(child)
        if signature(os.fstat(fd)) != signatures[prefix or "."]:
            raise Rejected("inventory-changed-after-read")

    recheck(root_fd, "")
    return {"schema": "host-recovery-tree-v1", "entries": entries}, blobs


def selected_auths(tree, blobs, selected, expected_type="meta"):
    if expected_type not in ("meta", "meta-muse") or type(selected) is not dict or len(selected) != 9:
        raise Rejected("exact-nine-auth-mapping-required")
    if any(type(flag) is not bool for flag in selected.values()) or sum(selected.values()) != 7:
        raise Rejected("seven-disabled-two-enabled-required")
    for name, disabled in selected.items():
        relative_path(name)
        row = tree["entries"].get(name)
        if not row or row["kind"] != "file":
            raise Rejected("selected-auth-not-in-inventory")
        raw = blobs[row["sha256"]]
        value = decode(raw)
        if value.get("type") != expected_type or type(value.get("disabled")) is not bool or value["disabled"] is not disabled:
            raise Rejected("selected-auth-state-mismatch")
    return {"selected": 9, "disabled": 7, "enabled": 2}


def validate_tree(tree, blobs):
    if type(tree) is not dict or set(tree) != {"schema", "entries"} or tree["schema"] != "host-recovery-tree-v1":
        raise Rejected("baseline-tree-schema")
    entries = tree["entries"]
    if type(entries) is not dict or not 1 <= len(entries) <= MAX_ENTRIES or "." not in entries:
        raise Rejected("baseline-tree-entries")
    pins, total = set(), 0
    for name, row in entries.items():
        if name != ".":
            relative_path(name)
            if len(name.split("/")) > MAX_DEPTH + 1:
                raise Rejected("baseline-depth-limit")
            parent = name.rpartition("/")[0] or "."
            if type(entries.get(parent)) is not dict or entries[parent].get("kind") != "directory":
                raise Rejected("baseline-parent-missing")
        if type(row) is not dict:
            raise Rejected("baseline-row")
        fields = {"kind", "uid", "gid", "mode"}
        kind = row.get("kind")
        if kind == "file":
            fields |= {"sha256", "size"}
        elif kind != "directory":
            raise Rejected("baseline-kind")
        if name == "." and kind != "directory":
            raise Rejected("baseline-root-kind")
        if set(row) != fields or any(type(row.get(k)) is not int or row[k] < 0 for k in ("uid", "gid", "mode")):
            raise Rejected("baseline-metadata")
        if row["mode"] > 0o777 or row["mode"] & 0o022:
            raise Rejected("baseline-mode")
        if kind == "file":
            pin = row["sha256"]
            if type(pin) is not str or not HASH.fullmatch(pin) or pin not in blobs:
                raise Rejected("baseline-blob-missing")
            raw = blobs[pin]
            if type(raw) is not bytes or type(row["size"]) is not int or len(raw) != row["size"] or digest(raw) != pin:
                raise Rejected("baseline-blob-mismatch")
            if len(raw) > 4 * 1024 * 1024:
                raise Rejected("baseline-file-size-limit")
            total += len(raw)
            pins.add(pin)
    if set(blobs) != pins or total > MAX_TREE_BYTES:
        raise Rejected("baseline-blob-inventory")


def save_baseline(parent, name, tree, blobs, *, fault=None):
    """Create once in a private state directory; never overwrite a baseline."""
    component(name)
    st = os.fstat(parent)
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise Rejected("private-baseline-parent-required")
    validate_tree(tree, blobs)
    os.mkdir(name, 0o700, dir_fd=parent)
    os.fsync(parent)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        for pin, raw in sorted(blobs.items()):
            atomic_write(fd, pin, raw, fault=fault)
        raw = canonical(tree)
        pin = atomic_write(fd, "manifest.json", raw, fault=fault)
        load_baseline(fd, pin)
        os.fsync(parent)
        return pin
    finally:
        os.close(fd)


def load_baseline(fd, pin):
    if type(pin) is not str or not HASH.fullmatch(pin):
        raise Rejected("baseline-pin-required")
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise Rejected("private-baseline-required")
    raw, st = read_file(fd, "manifest.json")
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600:
        raise Rejected("private-baseline-file-required")
    if digest(raw) != pin:
        raise Rejected("baseline-manifest-mismatch")
    tree, blobs = decode(raw), {}
    for name in os.listdir(fd):
        if name == "manifest.json":
            continue
        if not HASH.fullmatch(name):
            raise Rejected("unexpected-baseline-entry")
        value, st = read_file(fd, name)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600:
            raise Rejected("private-baseline-file-required")
        blobs[name] = value
    validate_tree(tree, blobs)
    return tree, blobs


def receipt(tree):
    return {"schema": "host-recovery-inventory-receipt-v1",
            "manifest_sha256": digest(canonical(tree)),
            "entries": len(tree["entries"]), "production_acceptance": False}
