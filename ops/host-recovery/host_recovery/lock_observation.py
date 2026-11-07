"""Read-only Linux observation of the supervisor's ORIGINAL directory flock.

Never acquire, duplicate or receive the lock's open file description. The opened
journal handle is independently pinned and unlocked. A descriptor number is only
a lookup hint; the live kernel peer, inode and exclusive FLOCK must all agree.
This point observation is not a lasting lease, manager identity or start grant.
"""
import os
import re
import stat
import time

from .commands import Deadline
from .durable import Rejected
from .installation import DirectoryApproval, directory_identity, open_approved_directory
from .worker import PeerSession

MAX_FDINFO = 16384
LOCK = re.compile(rb"[0-9]+: FLOCK  ADVISORY  WRITE ([1-9][0-9]*) ([a-f0-9]+):([a-f0-9]+):([0-9]+) 0 EOF\Z")


def exclusive_flock(raw, *, pid, device, inode):
    """Parse fdinfo, not /proc/locks' namespace-filtered global inventory.

    Whole-file exclusive advisory flock is the only supported lock type. POSIX,
    OFD, waiting locks, shared locks and partial byte ranges cannot stand in for
    the installation-directory flock used by open_installation.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FDINFO:
        raise Rejected("original-lock-fdinfo-unconfirmed")
    rows = raw.splitlines()
    locks = [row.split(b"\t", 1)[1] for row in rows if row.startswith(b"lock:\t")]
    # Do not hide malformed/duplicate lock rows behind a matching one.
    if len(locks) != 1 or sum(row.startswith(b"lock:") for row in rows) != 1:
        raise Rejected("original-lock-exclusive-flock-required")
    match = LOCK.fullmatch(locks[0])
    if match is None:
        raise Rejected("original-lock-exclusive-flock-required")
    actual = tuple(int(item, base) for item, base in zip(match.groups(), (10, 16, 16, 10)))
    if actual != (pid, os.major(device), os.minor(device), inode):
        raise Rejected("original-lock-owner-or-inode-mismatch")
    inodes = [row for row in rows if row.startswith(b"ino:")]
    if len(inodes) != 1 or inodes[0] != b"ino:\t" + str(inode).encode("ascii"):
        raise Rejected("original-lock-fdinfo-inode-mismatch")


def _fdinfo(proc, descriptor):
    fd = os.open("fdinfo/" + str(descriptor), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=proc)
    try:
        raw = bytearray()
        while len(raw) <= MAX_FDINFO:
            block = os.read(fd, min(4096, MAX_FDINFO + 1 - len(raw)))
            if not block:
                return bytes(raw)
            raw.extend(block)
        raise Rejected("original-lock-fdinfo-limit")
    finally:
        os.close(fd)


class OriginalLockObservation:
    """Revoking observation for one peer, original journal and descriptor hint.

    The caller must separately bind this peer to the original manager MainPID,
    UID/GID, unit/invocation, cgroup, request, approval and nonrenewing phase.
    Unsupported procfs/namespace/permission behavior refuses without a PID or
    lock-acquisition fallback. Recheck inside every future privileged barrier.
    No operational runner consumes this component yet.
    """
    def __init__(self, *, peer, journal, descriptor, deadline, clock=time.monotonic):
        if (not isinstance(peer, PeerSession) or not isinstance(journal, DirectoryApproval)
                or journal.mode != 0o700
                or (journal.uid, journal.gid) != (peer.peer["uid"], peer.peer["gid"])
                or type(descriptor) is not int or not 0 <= descriptor <= 1048575):
            raise Rejected("original-lock-explicit-peer-and-journal-required")
        self.peer, self.journal, self.descriptor = peer, journal, descriptor
        self.clock, self.deadline = clock, deadline
        self.failed, self.last_clock = False, None
        Deadline(self._now, deadline).remaining()

    def _now(self):
        value = self.clock()
        if type(value) in (int, float) and self.last_clock is not None and value < self.last_clock:
            raise Rejected("original-lock-clock-changed")
        self.last_clock = value
        return value

    def _live(self, timer):
        timer.remaining()
        if not self.peer.alive():
            raise Rejected("original-lock-peer-lost")

    def observe(self, *, deadline):
        try:
            if self.failed or deadline > self.deadline:
                raise Rejected("original-lock-observation-revoked")
            timer = Deadline(self._now, deadline)
            self._live(timer)
            pid = self.peer.peer["pid"]
            proc = os.open("/proc/" + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                # PID reporting and credentials must use the same namespaces as
                # SO_PEERCRED. Mount namespaces may differ: the opened inode, not
                # the peer's pathname or mount ID, is the flock target.
                for namespace in ("pid", "user"):
                    actual = os.stat("ns/" + namespace, dir_fd=proc)
                    expected = os.stat("/proc/self/ns/" + namespace)
                    if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                        raise Rejected("original-lock-namespace-unconfirmed")
                with open_approved_directory(self.journal) as handle:
                    expected = directory_identity(os.fstat(handle.fd))
                    for _ in range(2):
                        self._live(timer)
                        before = os.stat("fd/" + str(self.descriptor), dir_fd=proc)
                        if not stat.S_ISDIR(before.st_mode) or directory_identity(before) != expected:
                            raise Rejected("original-lock-descriptor-mismatch")
                        exclusive_flock(_fdinfo(proc, self.descriptor), pid=pid,
                                        device=before.st_dev, inode=before.st_ino)
                        after = os.stat("fd/" + str(self.descriptor), dir_fd=proc)
                        if directory_identity(after) != expected:
                            raise Rejected("original-lock-descriptor-changed")
                        handle.validate()
                        self._live(timer)
                # Context-exit path validation can outlive the last kernel read.
                self._live(timer)
            finally:
                os.close(proc)
            self._live(timer)
            return {"schema": "host-recovery-lock-observation-v1", "exclusive_flock_observed": True,
                    "complete_fence_proven": False, "start_allowed": False, "production_acceptance": False}
        except Exception:
            self.failed = True
            raise Rejected("original-lock-observation-unconfirmed") from None
