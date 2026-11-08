"""Local ownership/record primitives for the retained detached wrapper adaptation.

No runtime entrypoint, success receipt, process containment or daemon interface.
The caller must provide a stable private resource directory shared by ALL forward,
watchdog and manual-recovery entrants, not a different directory per attempt.
"""

from contextlib import contextmanager
import fcntl
import json
import os
import re
import stat
import uuid


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
RECORDS = frozenset(("armed", "stop-intent", "failure"))


class AttemptError(ValueError):
    """Ownership or record identity cannot be established."""


def _directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise AttemptError("resource directory must be private and owned by the caller")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _sync_directory(fd):
    os.fsync(fd)


def _publish(directory, name, value):
    """Publish once, syncing both the contents and directory; never replace records."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    if len(raw) > 16384:
        raise AttemptError("record exceeds size limit")
    temporary = ".pending-" + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # link, unlike replace, fails if a previous participant already published.
        os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        _sync_directory(directory)
    finally:
        os.unlink(temporary, dir_fd=directory)
        _sync_directory(directory)


def _read(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise AttemptError("record is not a private regular file")
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise AttemptError("record exceeds size limit")
    return json.loads(raw)


class Ownership:
    """One nonblocking flock inode, never unlinked/truncated by this helper.

    This is cooperative same-user exclusion, not a hostile-user security boundary.
    It DOES NOT prove old descendants or queued daemon operations are quiescent.
    """

    def __init__(self, resource_directory):
        self.path = resource_directory
        self.directory = None
        self.lock = None

    def __enter__(self):
        if self.directory is not None:
            raise AttemptError("ownership object is already open")
        self.directory = _directory(self.path)
        try:
            self.lock = os.open("ownership.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                                0o600, dir_fd=self.directory)
            info = os.fstat(self.lock)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise AttemptError("invalid ownership lock")
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _sync_directory(self.directory)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *_):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None

    def _check(self):
        if self.lock is None:
            raise AttemptError("common ownership is not held")
        current = os.stat("ownership.lock", dir_fd=self.directory, follow_symlinks=False)
        held = os.fstat(self.lock)
        if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino) or held.st_nlink != 1:
            raise AttemptError("common ownership inode changed")

    @contextmanager
    def attempt(self, package_digest, attempt_id, *, create=False):
        self._check()
        if not isinstance(package_digest, str) or not DIGEST.fullmatch(package_digest):
            raise AttemptError("invalid package digest")
        if not isinstance(attempt_id, str) or not NONCE.fullmatch(attempt_id):
            raise AttemptError("attempt ID must be a fresh 128-bit nonce")
        name = "attempt-" + attempt_id
        if create:
            os.mkdir(name, 0o700, dir_fd=self.directory)
            _sync_directory(self.directory)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=self.directory)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise AttemptError("attempt directory must be private")
            identity = {"schema": "stock-wrapper-attempt/v1", "package_digest": package_digest,
                        "attempt_id": attempt_id}
            if create:
                _publish(fd, "identity.json", identity)
            if _read(fd, "identity.json") != identity:
                raise AttemptError("attempt/package identity mismatch")
            current = Attempt(self, fd, identity)
            try:
                yield current
            finally:
                current.directory = None
        finally:
            os.close(fd)


class Attempt:
    def __init__(self, ownership, directory, identity):
        self.ownership = ownership
        self.directory = directory
        self.identity = identity

    def publish(self, kind, observation_digest):
        self.ownership._check()
        if self.directory is None:
            raise AttemptError("attempt handle is closed")
        if kind not in RECORDS:
            raise AttemptError("unsupported record; success acceptance is not implemented")
        if not isinstance(observation_digest, str) or not DIGEST.fullmatch(observation_digest):
            raise AttemptError("record must reference a digest-bound observation")
        value = {**self.identity, "kind": kind, "observation_digest": observation_digest}
        _publish(self.directory, kind + ".json", value)
        return self.read(kind)

    def read(self, kind):
        self.ownership._check()
        if self.directory is None:
            raise AttemptError("attempt handle is closed")
        if kind not in RECORDS:
            raise AttemptError("unsupported record")
        value = _read(self.directory, kind + ".json")
        if not isinstance(value, dict) or value.keys() != self.identity.keys() | {"kind", "observation_digest"}:
            raise AttemptError("invalid record shape")
        if any(value[key] != expected for key, expected in self.identity.items()) or value["kind"] != kind:
            raise AttemptError("record belongs to another attempt/package")
        if not isinstance(value["observation_digest"], str) or not DIGEST.fullmatch(value["observation_digest"]):
            raise AttemptError("invalid observation digest")
        return value
