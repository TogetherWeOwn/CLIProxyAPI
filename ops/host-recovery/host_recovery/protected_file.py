"""Borrowed protected files with bounded reads and retained descriptor identity.

Callers supply approved directory handles, owner identity, writer exclusion and
inclusive deadline checks. Reading/hashing a file does not authenticate approval
or authorize later execution, restoration or a service start.
"""
import hashlib
import os

from .durable import Rejected, signature
from .loading import NAME, metadata, owner

CHUNK = 65536


class ProtectedFile:
    """Never reopen the file between its first read and final byte/identity check."""
    def __init__(self, root, name, *, uid, gid, limit, current):
        owner(uid, gid)
        if (type(name) is not str or NAME.fullmatch(name) is None or name in (".", "..")
                or type(limit) is not int or limit <= 0 or not callable(current)):
            raise Rejected("protected-file-explicit-boundary-required")
        self.root, self.name, self.uid, self.gid = root, name, uid, gid
        self.current, self.limit, self.fd = current, limit, None
        try:
            current()
            self.fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                              dir_fd=root.fd)
            self.info = self._metadata()
            self.validate()
        except BaseException:
            self.close()
            raise

    def _metadata(self):
        st = metadata(self.fd, uid=self.uid, gid=self.gid)
        if (st.st_nlink != 1 or st.st_dev != self.root.approval.device
                or not 0 < st.st_size <= self.limit):
            raise Rejected("protected-file-regular-bounded-single-link-required")
        return st

    def validate(self):
        self.current()
        self.root.validate()
        if (signature(self._metadata()) != signature(self.info)
                or signature(os.stat(self.name, dir_fd=self.root.fd, follow_symlinks=False)) != signature(self.info)):
            raise Rejected("protected-file-changed")
        self.current()

    def read_at(self, offset, count):
        self.current()
        if not 0 <= offset <= self.info.st_size or not 0 <= count <= self.info.st_size - offset:
            raise Rejected("protected-file-read-range")
        block = os.pread(self.fd, count, offset)
        if len(block) != count:
            raise Rejected("protected-file-short-read")
        self.current()
        return block

    def blocks(self):
        for offset in range(0, self.info.st_size, CHUNK):
            yield self.read_at(offset, min(CHUNK, self.info.st_size - offset))
        self.validate()

    def checksum(self):
        result = hashlib.sha256()
        for block in self.blocks():
            result.update(block)
        return result.hexdigest()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
