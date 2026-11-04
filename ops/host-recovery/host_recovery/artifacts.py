"""Read-only, descriptor-bound plugin archive/library correspondence checks.

Approval and protected directory identities come from the trusted installation
boundary. The caller retains the installation lock and excludes cooperating
writers. No archive extraction, plugin loading, approval discovery, installation
or service-start authority. Hostile root/same-uid writers and wedged kernel I/O
are not made safe by hashing or Python deadline checks.
"""
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import os
import stat
import struct
import zipfile

from .commands import Deadline
from .durable import Rejected, canonical, digest, signature
from .installation import DirectoryApproval, open_approved_directory
from .loading import NAME, metadata, owner, pin, relative

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_LIBRARY = 128 * 1024 * 1024
MAX_MEMBERS = 64
MAX_DIRECTORY = 64 * 1024
CHUNK = 65536


@dataclass(frozen=True)
class PluginArtifactApproval:
    intent_sha256: str
    archive_sha256: str
    library_sha256: str
    archive_root: DirectoryApproval
    library_root: DirectoryApproval
    archive_name: str
    library_name: str
    library_member: str
    uid: int
    gid: int

    def __post_init__(self):
        for value in (self.intent_sha256, self.archive_sha256, self.library_sha256):
            pin(value)
        owner(self.uid, self.gid)
        for root in (self.archive_root, self.library_root):
            if (not isinstance(root, DirectoryApproval)
                    or (root.uid, root.gid) != (self.uid, self.gid)):
                raise Rejected("artifact-protected-roots-required")
        for name in (self.archive_name, self.library_name):
            if type(name) is not str or NAME.fullmatch(name) is None or name in (".", ".."):
                raise Rejected("artifact-file-name-required")
        relative(self.library_member)


class _File:
    """Borrow a protected root; never reopen the artifact after its hash check."""
    def __init__(self, root, name, approval, limit, current):
        self.root, self.name, self.approval = root, name, approval
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
        st = metadata(self.fd, uid=self.approval.uid, gid=self.approval.gid)
        if (st.st_nlink != 1 or st.st_dev != self.root.approval.device
                or not 0 < st.st_size <= self.limit):
            raise Rejected("artifact-regular-bounded-single-link-file-required")
        return st

    def validate(self):
        self.current()
        self.root.validate()
        if (signature(self._metadata()) != signature(self.info)
                or signature(os.stat(self.name, dir_fd=self.root.fd, follow_symlinks=False)) != signature(self.info)):
            raise Rejected("artifact-file-changed")
        self.current()

    def read_at(self, offset, count):
        self.current()
        if not 0 <= offset <= self.info.st_size or not 0 <= count <= self.info.st_size - offset:
            raise Rejected("artifact-read-range")
        block = os.pread(self.fd, count, offset)
        if len(block) != count:
            raise Rejected("artifact-short-read")
        self.current()
        return block

    def checksum(self):
        result = hashlib.sha256()
        for offset in range(0, self.info.st_size, CHUNK):
            result.update(self.read_at(offset, min(CHUNK, self.info.st_size - offset)))
        self.validate()
        return result.hexdigest()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class _Reader:
    """Small seekable facade with metered, bounded pread for the ZIP parser."""
    def __init__(self, source):
        self.source, self.offset = source, 0

    def seekable(self):
        return True

    def tell(self):
        return self.offset

    def seek(self, offset, whence=os.SEEK_SET):
        self.source.current()
        origins = {os.SEEK_SET: 0, os.SEEK_CUR: self.offset, os.SEEK_END: self.source.info.st_size}
        if whence not in origins:
            raise Rejected("artifact-seek-origin")
        target = offset + origins[whence]
        if not 0 <= target <= self.source.info.st_size:
            raise Rejected("artifact-seek-range")
        self.offset = target
        return target

    def read(self, count=-1):
        available = self.source.info.st_size - self.offset
        count = available if count < 0 else min(count, available)
        if count > CHUNK:
            raise Rejected("artifact-parser-read-limit")
        raw = self.source.read_at(self.offset, count)
        self.offset += len(raw)
        return raw


class PluginArtifactGate:
    """Fresh dual hashes and archive-member correspondence, not a start oracle.

    check() revalidates owner/lock/writer exclusion before, throughout and after
    verification. Approval pins must be independently authenticated, including the
    intent binding. The ZIP subset is deliberately bounded: classic single-disk,
    no comments/ZIP64/encryption/special entries; stored or deflated regular files.
    Other formats fail closed rather than invoke an external extraction tool.
    """
    def __init__(self, *, approval, check, clock):
        if (not isinstance(approval, PluginArtifactApproval)
                or not callable(check) or not callable(clock)):
            raise Rejected("artifact-explicit-boundary-required")
        self.approval, self.check, self.clock = approval, check, clock

    def verify(self, intent, *, deadline):
        try:
            remaining = Deadline(self.clock, deadline).remaining
            def current():
                remaining()
                if self.check() is not True:
                    raise Rejected("artifact-boundary-unconfirmed")
                remaining()

            approval = self.approval
            if digest(canonical(intent)) != approval.intent_sha256:
                raise Rejected("artifact-intent-pin-mismatch")
            current()
            with ExitStack() as stack:
                archive_root = stack.enter_context(open_approved_directory(approval.archive_root))
                library_root = stack.enter_context(open_approved_directory(approval.library_root))
                archive = _File(archive_root, approval.archive_name, approval, MAX_ARCHIVE, current)
                stack.callback(archive.close)
                library = _File(library_root, approval.library_name, approval, MAX_LIBRARY, current)
                stack.callback(library.close)
                if (archive.info.st_dev, archive.info.st_ino) == (library.info.st_dev, library.info.st_ino):
                    raise Rejected("artifact-distinct-files-required")
                if archive.checksum() != approval.archive_sha256 or library.checksum() != approval.library_sha256:
                    raise Rejected("artifact-dual-pin-mismatch")
                self._member(archive, library.info.st_size, current)
                # Rehash both retained descriptors: filesystem timestamp granularity
                # cannot make metadata equality stand in for unchanged bytes.
                if archive.checksum() != approval.archive_sha256 or library.checksum() != approval.library_sha256:
                    raise Rejected("artifact-bytes-changed")
                # A parsed archive never licenses a later path reopen/load/start.
                archive.validate()
                library.validate()
                current()
            current()
        except Exception:
            # Parser, filesystem and caller errors must never expose restricted
            # names, archive contents, pins or underlying exception text.
            raise Rejected("artifact-check-unconfirmed") from None
        return True

    def _member(self, archive, library_size, current):
        size = archive.info.st_size
        if size < 22:
            raise Rejected("artifact-zip-required")
        end = struct.unpack("<4s4H2LH", archive.read_at(size - 22, 22))
        magic, disk, directory_disk, disk_count, count, length, offset, comment = end
        if (magic != b"PK\x05\x06" or disk or directory_disk or disk_count != count
                or not 1 <= count <= MAX_MEMBERS or not 0 < length <= MAX_DIRECTORY
                or offset + length != size - 22 or comment):
            raise Rejected("artifact-supported-zip-required")
        if size >= 42 and archive.read_at(size - 42, 4) == b"PK\x06\x07":
            raise Rejected("artifact-zip64-not-supported")
        with zipfile.ZipFile(_Reader(archive)) as package:
            entries = package.infolist()
            if len(entries) != count or package.start_dir != offset:
                raise Rejected("artifact-zip-directory-mismatch")
            seen, total, selected = set(), 0, None
            for entry in entries:
                current()
                name = relative(entry.filename)
                mode = entry.external_attr >> 16
                if (entry.orig_filename != name or name in seen or entry.is_dir() or entry.external_attr & 0x10
                        or (mode and (stat.S_IFMT(mode) not in (0, stat.S_IFREG) or mode & 0o7022))
                        or entry.flag_bits & ~0x808
                        or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or entry.extra or entry.comment
                        or not 0 <= entry.header_offset < offset
                        or not 0 <= entry.file_size <= MAX_LIBRARY):
                    raise Rejected("artifact-supported-zip-entry-required")
                seen.add(name)
                total += entry.file_size
                if total > MAX_LIBRARY:
                    raise Rejected("artifact-zip-expanded-limit")
                if name == self.approval.library_member:
                    selected = entry
            if (min(entry.header_offset for entry in entries) != 0 or selected is None
                    or selected.file_size != library_size):
                raise Rejected("artifact-library-member-required")
            result, actual = hashlib.sha256(), 0
            with package.open(selected) as member:
                while True:
                    current()
                    block = member.read(CHUNK)
                    if not block:
                        break
                    actual += len(block)
                    if actual > library_size:
                        raise Rejected("artifact-member-size-limit")
                    result.update(block)
            if actual != library_size or result.hexdigest() != self.approval.library_sha256:
                raise Rejected("artifact-member-pin-mismatch")
            current()
