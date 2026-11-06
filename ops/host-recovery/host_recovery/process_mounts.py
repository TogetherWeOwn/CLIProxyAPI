"""Linux point observation of one authenticated process's path-resolution view.

The caller supplies a pidfd from its independently authenticated daemon boundary,
not pidfd_open of a guessed PID. The check callback must retain that transport,
manager identity and complete fence. Equal views are not continuous exclusion,
container-mounted byte verification, approval provisioning or start authority.
"""
from contextlib import ExitStack, contextmanager
import fcntl
import os
import stat

from .commands import Deadline
from .durable import Rejected, canonical, digest
from .worker import wait_for_cancellation

NS_GET_NSTYPE = 0xb703
CLONE_NEWNS = 0x00020000
MAX_FDINFO = 4096


def fdinfo_number(fd, field):
    with open(f"/proc/self/fdinfo/{fd}", "rb") as stream:
        raw = stream.read(MAX_FDINFO + 1)
    rows = [line.split(b":", 1)[1].strip() for line in raw.splitlines() if line.startswith(field + b":")]
    if (len(raw) > MAX_FDINFO or len(rows) != 1 or not rows[0].isdigit()
            or len(rows[0]) > 20 or int(rows[0]) < 1):
        raise Rejected("process-mount-kernel-identity-unconfirmed")
    return int(rows[0])


def object_identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


def root_identity(fd):
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        raise Rejected("process-mount-root-required")
    return (*object_identity(fd), fdinfo_number(fd, b"mnt_id"))


def mount_identity(fd):
    if fcntl.ioctl(fd, NS_GET_NSTYPE) != CLONE_NEWNS:
        raise Rejected("process-mount-namespace-required")
    return object_identity(fd)


@contextmanager
def open_process_mount_view(*, pid, pidfd, check, clock):
    """Retain duplicated pidfd, proc directory and first matching namespace/root.

    No socket is opened, process is launched, setns is performed, or new lock is
    acquired. The supplied process identity must already be authorized. Missing
    procfs/nsfs/pidfd support or access refuses without a numeric-PID fallback.
    """
    if (type(pid) is not int or not 1 <= pid <= 2147483647
            or type(pidfd) is not int or pidfd < 0 or not callable(check) or not callable(clock)):
        raise Rejected("process-mount-explicit-boundaries-required")
    with ExitStack() as stack:
        owned = os.dup(pidfd)
        stack.callback(os.close, owned)
        os.set_inheritable(owned, False)
        if (os.readlink(f"/proc/self/fd/{owned}") != "anon_inode:[pidfd]"
                or fdinfo_number(owned, b"Pid") != pid or wait_for_cancellation(owned, 0)):
            raise Rejected("process-mount-pidfd-unconfirmed")
        proc = os.open(f"/proc/{pid}", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, proc)
        view = ProcessMountView(pid, owned, proc, check, clock, stack)
        try:
            yield view
        finally:
            view.closed = True


class ProcessMountView:
    """Same mount namespace AND same root mount; explicitly not container proof."""
    def __init__(self, pid, pidfd, proc, check, clock, stack):
        self.pid, self.pidfd, self.proc = pid, pidfd, proc
        self.check, self.clock = check, clock
        self._binding = pid, pidfd, proc, check, clock
        self._stack, self._retained, self._signature = stack, None, None
        self.closed = self.failed = self._active = False
        self._last_clock = None

    def _bound(self):
        pid, pidfd, proc, check, clock = self._binding
        if (self.closed or self.failed or (self.pid, self.pidfd, self.proc) != (pid, pidfd, proc)
                or self.check is not check or self.clock is not clock
                or os.readlink(f"/proc/self/fd/{pidfd}") != "anon_inode:[pidfd]"
                or fdinfo_number(pidfd, b"Pid") != pid or wait_for_cancellation(pidfd, 0)):
            raise Rejected("process-mount-view-unavailable")

    def _now(self):
        now = self._binding[4]()
        if (type(now) not in (int, float) or self._last_clock is not None and now < self._last_clock):
            raise Rejected("process-mount-clock-discontinuity")
        self._last_clock = now
        return now

    def _current(self, deadline):
        remaining = Deadline(self._now, deadline).remaining
        remaining()
        self._bound()
        if self._binding[3](deadline=deadline) is not True:
            raise Rejected("process-mount-authority-unconfirmed")
        remaining()
        self._bound()

    def _capture(self, stack):
        def opened(path, flags, **kwargs):
            fd = os.open(path, flags | os.O_CLOEXEC, **kwargs)
            stack.callback(os.close, fd)
            return fd
        # These are deliberate kernel procfs magic links, anchored to the pinned
        # process directory. Generic filesystem symlink traversal is not used.
        caller_ns = opened("/proc/self/ns/mnt", os.O_RDONLY)
        peer_ns = opened("ns/mnt", os.O_RDONLY, dir_fd=self.proc)
        caller_root = opened("/", os.O_PATH | os.O_DIRECTORY)
        peer_root = opened("root", os.O_PATH | os.O_DIRECTORY, dir_fd=self.proc)
        handles = caller_ns, peer_ns, caller_root, peer_root
        signature = self._identities(handles)
        if signature[0] != signature[1] or signature[2] != signature[3]:
            raise Rejected("process-mount-view-mismatch")
        return handles, signature

    @staticmethod
    def _identities(handles):
        return (mount_identity(handles[0]), mount_identity(handles[1]),
                root_identity(handles[2]), root_identity(handles[3]))

    def observe(self, *, deadline):
        try:
            if self._active:
                raise Rejected("process-mount-reentrant-observation")
            self._active = True
            self._current(deadline)
            with ExitStack() as sample:
                handles, before = self._capture(sample)
                if self._signature is not None and before != self._signature:
                    raise Rejected("process-mount-view-changed")
                self._current(deadline)
                Deadline(self._now, deadline).remaining()
                with ExitStack() as trailing:
                    _, after = self._capture(trailing)
                    if (before != after or self._identities(handles) != before
                            or self._retained is not None and self._identities(self._retained) != before):
                        raise Rejected("process-mount-view-changed")
                Deadline(self._now, deadline).remaining()
                self._bound()
                if self._retained is None:
                    self._retained, self._signature = handles, before
                    self._stack.enter_context(sample.pop_all())
                return {"schema": "host-recovery-process-mount-view-v1",
                        "view_sha256": digest(canonical(before)), "source_namespace_matches": True,
                        "container_namespace_verified": False, "start_authorized": False}
        except BaseException:
            self.failed = True
            raise Rejected("process-mount-observation-unconfirmed") from None
        finally:
            self._active = False
