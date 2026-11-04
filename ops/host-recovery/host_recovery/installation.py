"""Protected installation-root acquisition and locked read-only loading.

Approvals are supplied by the trusted installer/manager, never discovered beside
mutable content or from a request. This cannot authenticate that caller, its code,
mount namespace or approval channel. No install, execution or service grant.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import os
import stat

from .durable import Rejected
from .journal import identity

FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class DirectoryApproval:
    path: str
    device: int
    inode: int
    uid: int
    gid: int
    mode: int

    def __post_init__(self):
        if (type(self.path) is not str or not self.path.startswith("/")
                or len(self.path) > 4096 or len(self.path.split("/")) > 65
                or any(part in ("", ".", "..") or "\0" in part for part in self.path.split("/")[1:])):
            raise Rejected("installation-absolute-path-required")
        if (any(type(value) is not int or value < 0 for value in (self.device, self.inode, self.uid, self.gid))
                or self.inode == 0 or max(self.uid, self.gid) > 2147483647
                or type(self.mode) is not int or self.mode not in (0o500, 0o555, 0o700, 0o755)):
            raise Rejected("installation-directory-approval-required")


@dataclass(frozen=True)
class InstallationApproval:
    installation_id: str
    content: DirectoryApproval
    journal: DirectoryApproval

    def __post_init__(self):
        if (not identity(self.installation_id) or not isinstance(self.content, DirectoryApproval)
                or not isinstance(self.journal, DirectoryApproval) or self.journal.mode != 0o700):
            raise Rejected("installation-approval-required")
        a, b = self.content, self.journal
        if (a.path == b.path or a.path.startswith(b.path + "/") or b.path.startswith(a.path + "/")
                or (a.device, a.inode) == (b.device, b.inode)):
            raise Rejected("installation-separate-roots-required")


def directory_identity(st):
    # Directory contents change during journal writes. Bind the opened object and
    # protection metadata, not mtime/size, which would create a new lock namespace.
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid)


def protected(fd, uid):
    st = os.fstat(fd)
    mode = stat.S_IMODE(st.st_mode)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, uid)
            or mode & 0o7022 or os.listxattr(fd)):
        raise Rejected("installation-protected-ancestry-required")
    return directory_identity(st)


class _Directory:
    def __init__(self, approval):
        self.approval, self.chain = approval, []
        try:
            fd = os.open("/", FLAGS)
            self.chain.append((None, fd, None))
            self.chain[-1] = (None, fd, protected(fd, approval.uid))
            for name in approval.path.split("/")[1:]:
                parent = self.chain[-1][1]
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                fd = os.open(name, FLAGS, dir_fd=parent)
                # Track immediately so all validation failures close this fd.
                self.chain.append((name, fd, None))
                actual = protected(fd, approval.uid)
                if directory_identity(before) != actual:
                    raise Rejected("installation-directory-changed")
                self.chain[-1] = (name, fd, actual)
            st = os.fstat(self.fd)
            if (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (
                    approval.device, approval.inode, approval.uid, approval.gid, approval.mode):
                raise Rejected("installation-root-pin-mismatch")
            self.validate()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.chain[-1][1]

    def validate(self):
        if not self.chain:
            raise Rejected("installation-directory-closed")
        for index, (name, fd, expected) in enumerate(self.chain):
            if protected(fd, self.approval.uid) != expected:
                raise Rejected("installation-directory-changed")
            if index:
                st = os.stat(name, dir_fd=self.chain[index - 1][1], follow_symlinks=False)
                if directory_identity(st) != expected:
                    raise Rejected("installation-directory-changed")

    def close(self):
        while self.chain:
            _, fd, _ = self.chain.pop()
            os.close(fd)


@contextmanager
def open_approved_directory(approval):
    """Retain a protected path identity without acquiring a second lock.

    The approval and writer exclusion come from the caller's trusted boundary.
    Opening a directory is not permission to mutate it or start a service.
    """
    if not isinstance(approval, DirectoryApproval):
        raise Rejected("installation-directory-approval-required")
    handle = _Directory(approval)
    try:
        yield handle
        handle.validate()
    finally:
        handle.close()


class InstallationHandles:
    """Borrowed handles, valid only inside open_installation's lock lifetime.

    The journal inode is the existing installation-directory flock target, not a
    new lock file or attempt-specific namespace. Workers must not acquire this
    owner context while the supervisor holds it. Loading is read-only; handing
    snapshots/descriptors to an executor would require a separate reviewed path.
    """
    def __init__(self, approval, content, journal):
        self.approval, self._content, self._journal = approval, content, journal
        self.closed, self.failed = False, False

    def validate(self):
        if self.closed or self.failed:
            raise Rejected("installation-handles-unavailable")
        try:
            self._content.validate()
            self._journal.validate()
        except BaseException:
            self.failed = True
            raise

    def snapshot(self, *, content_approval, recovery_approval, binding, supervisor_owner, boot_id, now):
        """Capture both approved sources under the same validated journal lock."""
        from .loading import ContentApproval, RecoveryApproval, load_content, load_recovery

        self.validate()
        try:
            if (not isinstance(content_approval, ContentApproval) or not isinstance(recovery_approval, RecoveryApproval)
                    or recovery_approval.installation_id != self.approval.installation_id
                    or (content_approval.uid, content_approval.gid) != (self.approval.content.uid, self.approval.content.gid)
                    or (recovery_approval.uid, recovery_approval.gid) != (self.approval.journal.uid, self.approval.journal.gid)):
                raise Rejected("installation-loading-approval-mismatch")
            content = load_content(self._content.fd, content_approval)
            inputs = load_recovery(self._journal.fd, approval=recovery_approval, binding=binding,
                                   supervisor_owner=supervisor_owner, boot_id=boot_id, now=now)
            self.validate()
            return content, inputs
        except BaseException:
            self.failed = True
            raise


@contextmanager
def open_installation(approval):
    """Open protected ancestry, verify independent inode pins, retain one lock.

    No directories/lock files are created and no permission is relaxed. A changed
    path, failed observation or contender raises. An open directory alone is not
    proof that its pathname still designates the approved installation.
    """
    if not isinstance(approval, InstallationApproval):
        raise Rejected("installation-approval-required")
    content, journal, handles = None, None, None
    try:
        content = _Directory(approval.content)
        journal = _Directory(approval.journal)
        fcntl.flock(journal.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        handles = InstallationHandles(approval, content, journal)
        handles.validate()
        yield handles
        handles.validate()
    finally:
        if handles is not None:
            handles.closed = True
        if journal is not None:
            journal.close()
        if content is not None:
            content.close()
