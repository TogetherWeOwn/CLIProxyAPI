"""Restricted file-handle prefix capture, NOT asynchronous producer completion.

There is no Docker/stdout opener or container provenance oracle here. A file may
be an externally declared mirror, but a filename/EOF/stable stat is not proof of
that binding or that a producer's queue drained. Every snapshot is prefix-only.
Callers must retain the explicit private spool directory and all raw artifacts.
"""
import os
import stat
import uuid

from .durable import (MAX_FILE_BYTES, Rejected, atomic_write, digest, directory,
                      signature)
from .journal import identity


class FileCapture:
    """Keep a no-follow regular-file handle; refuse rotation, gaps and rewrites.

    This component supports full prefixes from offset zero only. Concurrent
    modification during a read is rejected rather than guessed complete. Reopen,
    rotation following and daemon stream cursors need separate reviewed adapters.
    No path, ownership, permission or source-kind default is supplied.
    """
    def __init__(self, *, source_id, path, uid, gid, mode):
        if not identity(source_id):
            raise Rejected("collection-source-identity")
        if (type(path) is not str or not os.path.isabs(path) or path.endswith("/")
                or any(type(v) is not int or v < 0 for v in (uid, gid, mode))
                or mode > 0o777 or mode & 0o022):
            raise Rejected("collection-source-contract")
        self.source_id, self.path = source_id, path
        self.owner_mode = (uid, gid, mode)
        self.parent = None
        self.fd = None
        self.previous = b""
        self.failed = False

    def __enter__(self):
        if self.parent is not None or self.failed:
            raise Rejected("collection-handle-reuse")
        parent, self.name = os.path.split(self.path)
        self.parent = directory(parent)
        try:
            self.parent_fd = self.parent.__enter__()
            self.fd = os.open(self.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                              dir_fd=self.parent_fd)
            self.opened = self._stat()
            self._check_path(self.opened)
        except Exception:
            self.failed = True
            self.__exit__(None, None, None)
            raise Rejected("collection-source-open-failed") from None
        return self

    def __exit__(self, *args):
        self.failed = True  # Closed handles cannot be silently reopened.
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.parent is not None:
            self.parent.__exit__(*args)
            self.parent = None

    def _stat(self):
        st = os.fstat(self.fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or os.listxattr(self.fd)
                or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != self.owner_mode):
            raise Rejected("collection-source-metadata")
        return st

    def _check_path(self, st):
        current = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
        if signature(st) != signature(current):
            raise Rejected("collection-source-rotation-or-change")

    def snapshot(self, spool_fd, *, fault=None):
        """Persist exact raw bytes before acknowledging a bounded prefix receipt.

        A read/persistence failure permanently poisons this capture. A subsequent
        healthy read must not turn an ambiguous/missing interval into coverage.
        """
        if self.fd is None or self.failed:
            raise Rejected("collection-handle-unavailable")
        try:
            private = os.fstat(spool_fd)
            if (not stat.S_ISDIR(private.st_mode) or private.st_uid != os.geteuid()
                    or stat.S_IMODE(private.st_mode) != 0o700):
                raise Rejected("private-collection-spool-required")
            before = self._stat()
            if (before.st_dev, before.st_ino) != (self.opened.st_dev, self.opened.st_ino):
                raise Rejected("collection-opened-identity-changed")
            self._check_path(before)
            if before.st_size > MAX_FILE_BYTES:
                raise Rejected("collection-source-overflow")
            os.lseek(self.fd, 0, os.SEEK_SET)
            blocks, count = [], 0
            while True:
                block = os.read(self.fd, min(65536, MAX_FILE_BYTES + 1 - count))
                if not block:
                    break
                count += len(block)
                if count > MAX_FILE_BYTES:
                    raise Rejected("collection-source-overflow")
                blocks.append(block)
            raw = b"".join(blocks)
            after = self._stat()
            self._check_path(after)
            if signature(before) != signature(after) or len(raw) != before.st_size:
                raise Rejected("collection-source-changed-during-read")
            if not raw.startswith(self.previous):
                raise Rejected("collection-source-truncated-or-rewritten")
            # Unique names preserve earlier raw snapshots, including an empty one.
            name = "prefix-" + uuid.uuid4().hex + ".raw"
            pin = atomic_write(spool_fd, name, raw, fault=fault)
            receipt = {"schema": "replay-source-prefix-v1", "source_id": self.source_id,
                       "device": before.st_dev, "inode": before.st_ino,
                       "start_offset": 0, "end_offset": len(raw), "previous_end_offset": len(self.previous),
                       "raw_sha256": pin, "raw_handle": name, "empty": not raw,
                       "coverage": "prefix_only", "producer_drained": False}
            if pin != digest(raw):
                raise Rejected("collection-raw-pin-mismatch")
            self.previous = raw
            return receipt
        except Exception:
            self.failed = True
            raise Rejected("collection-snapshot-failed") from None
