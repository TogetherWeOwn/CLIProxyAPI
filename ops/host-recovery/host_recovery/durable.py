"""Restricted persistence primitives for host-recovery-v1; no service operations.

Callers must hold the installation lock and fence all cooperating writers. These
primitives do not defend against a hostile root or provide a host start fence.
All paths are explicit; error messages must not contain restricted source data.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
import secrets
import stat

MAX_FILE_BYTES = 4 * 1024 * 1024


class Rejected(ValueError):
    """A fixed, secret-free rejection code."""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Rejected("duplicate-json-key")
            value[key] = item
        return value

    def nonfinite(_):
        raise Rejected("nonfinite-json")

    def finite_float(text):
        value = float(text)
        if not math.isfinite(value):
            raise Rejected("nonfinite-json")
        return value

    if type(raw) is not bytes or len(raw) > MAX_FILE_BYTES:
        raise Rejected("json-size-or-type")
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite, parse_float=finite_float)
    except (UnicodeError, ValueError, RecursionError):
        raise Rejected("invalid-json") from None
    if type(value) is not dict:
        raise Rejected("json-object-required")
    return value


def component(name):
    if type(name) is not str or not name or name in (".", "..") or "/" in name or "\0" in name:
        raise Rejected("unsafe-path-component")
    return name


def signature(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


@contextmanager
def directory(path, private=False):
    """Open every absolute path component without following symlinks."""
    path = os.fspath(path)
    if not os.path.isabs(path) or path == "/" or path.endswith("/"):
        raise Rejected("explicit-directory-required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in path.split("/")[1:]:
            component(name)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        st = os.fstat(fd)
        if private and (st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700):
            raise Rejected("private-owned-directory-required")
        yield fd
    finally:
        os.close(fd)


def read_file(parent, name, limit=MAX_FILE_BYTES):
    component(name)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise Rejected("regular-single-link-file-required")
        if os.listxattr(fd):
            raise Rejected("unsupported-file-metadata")
        blocks, count = [], 0
        while True:
            block = os.read(fd, min(65536, limit + 1 - count))
            if not block:
                break
            count += len(block)
            if count > limit:
                raise Rejected("file-size-limit")
            blocks.append(block)
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if signature(before) != signature(after) or signature(before) != signature(current):
            raise Rejected("file-changed-during-read")
        return b"".join(blocks), before
    finally:
        os.close(fd)


def atomic_write(parent, name, raw, *, uid=None, gid=None, mode=0o600, fault=None):
    """Acknowledge only after content, rename, directory fsync and readback.

    Any exception, including one after rename, means uncertain persistence. Never
    turn the presence of the destination into a successful terminal transition.
    Staging files survive failure for reconciliation; this function cannot delete
    evidence or a previous nonterminal intent on a best-effort cleanup path.
    """
    component(name)
    if type(raw) is not bytes or len(raw) > MAX_FILE_BYTES:
        raise Rejected("write-size-or-type")
    if type(mode) is not int or mode < 0 or mode > 0o777 or mode & 0o022:
        raise Rejected("unsafe-file-mode")
    uid = os.geteuid() if uid is None else uid
    gid = os.getegid() if gid is None else gid
    stage = ".recovery-stage-" + secrets.token_hex(16)
    hook = fault or (lambda _: None)
    hook("create")
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            hook("write")
            count = os.write(fd, view)
            if count <= 0:
                raise Rejected("short-write")
            view = view[count:]
        hook("file-fsync")
        os.fsync(fd)
    finally:
        os.close(fd)
    hook("rename")
    os.replace(stage, name, src_dir_fd=parent, dst_dir_fd=parent)
    hook("directory-fsync")
    os.fsync(parent)
    hook("readback")
    actual, st = read_file(parent, name)
    if actual != raw or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (uid, gid, mode):
        raise Rejected("durable-readback-mismatch")
    return digest(raw)


@contextmanager
def installation_lock(path, owner):
    """Lock the installation directory, not a replaceable PID/lock file.

    The persistent supervisor must retain this fd for the complete attempt and
    recovery. A contender raises; it cannot return a success-looking result.
    """
    if type(owner) is not dict or set(owner) != {"installation_id", "attempt_id", "unit", "invocation_id", "boot_id"}:
        raise Rejected("manager-owner-required")
    if any(type(value) is not str or not value or len(value) > 256 for value in owner.values()):
        raise Rejected("manager-owner-identity")
    with directory(path, private=True) as fd:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd, dict(owner)


def notify(notice, persist, transport):
    """Disk and independent transport are separate attempts, neither implies ACK.

    The transport is injected, must be bounded/nonblocking, and returns a strict
    boolean delivery receipt. No exception text or restricted notice is logged.
    """
    result = {"receipt_persisted": False, "transport_delivered": False,
              "human_acknowledged": False, "receipt_error": None, "transport_error": None}
    try:
        persist(notice)
        result["receipt_persisted"] = True
    except Exception:
        result["receipt_error"] = "alert-persistence-failed"
    try:
        if transport(notice) is True:
            result["transport_delivered"] = True
        else:
            result["transport_error"] = "alert-delivery-unconfirmed"
    except Exception:
        result["transport_error"] = "alert-transport-failed"
    return result
