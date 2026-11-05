"""Bounded pre-stop kernel process witnesses, not runtime containment authority.

Two matching descriptor-relative cgroup inventories bracket live pidfd acquisition.
Death checks apply only to the observed process set. They cannot prove that no
process escaped before capture, exclude a later launch, or establish complete
runtime/shim/writer ownership. No signal, numeric-PID fallback or replay exists.
"""
import os
import re
import select
import stat

from .broker_runtime import RuntimeDomain
from .durable import Rejected

MAX_GROUPS = 128
MAX_PROCESSES = 256
MAX_ENTRIES = 4096
MAX_DEPTH = 16
MAX_BYTES = 8192


def _procs(fd, device):
    source = os.open("cgroup.procs", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    try:
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode) or before.st_dev != device or before.st_nlink != 1:
            raise Rejected("runtime-processes-kernel-file-required")
        blocks, size = [], 0
        while True:
            block = os.read(source, MAX_BYTES + 1 - size)
            if not block:
                break
            size += len(block)
            if size > MAX_BYTES:
                raise Rejected("runtime-processes-file-overflow")
            blocks.append(block)
        after = os.fstat(source)
        path = os.stat("cgroup.procs", dir_fd=fd, follow_symlinks=False)
        def identity(info):
            return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink
        if identity(before) != identity(after) or identity(before) != identity(path):
            raise Rejected("runtime-processes-kernel-file-replaced")
        raw = b"".join(blocks)
        if raw and (not raw.endswith(b"\n") or re.fullmatch(rb"(?:[1-9][0-9]{0,9}\n)+", raw) is None):
            raise Rejected("runtime-processes-pid-schema")
        values = [int(line) for line in raw.splitlines()]
        if (len(values) > MAX_PROCESSES or len(set(values)) != len(values)
                or any(not 1 < pid <= 4294967295 for pid in values)):
            raise Rejected("runtime-processes-pid-limit-or-duplicate")
        return tuple(sorted(values))
    finally:
        os.close(source)


def _scan(domain, check):
    groups, processes = {}, {}
    def visit(fd, path, depth):
        check()
        domain.current()
        info = os.fstat(fd)
        if (depth > MAX_DEPTH or len(groups) >= MAX_GROUPS or not stat.S_ISDIR(info.st_mode)
                or info.st_dev != domain.device):
            raise Rejected("runtime-processes-group-limit-or-identity")
        groups[path] = (info.st_dev, info.st_ino)
        for pid in _procs(fd, domain.device):
            check()
            if pid in processes or len(processes) >= MAX_PROCESSES:
                raise Rejected("runtime-processes-inventory-limit-or-migration")
            processes[pid] = path
        children = []
        with os.scandir(fd) as entries:
            for index, entry in enumerate(entries):
                check()
                if index >= MAX_ENTRIES or entry.is_symlink():
                    raise Rejected("runtime-processes-entry-limit-or-link")
                if entry.is_dir(follow_symlinks=False):
                    children.append(entry.name)
        for name in sorted(children):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                visit(child, path + "/" + name, depth + 1)
                observed = os.fstat(child)
                current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if (observed.st_dev, observed.st_ino) != (current.st_dev, current.st_ino):
                    raise Rejected("runtime-processes-group-replaced")
            finally:
                os.close(child)
        check()
        domain.current()
    visit(domain.fd, domain.cgroup, 0)
    return groups, processes


class RuntimeProcessWitness:
    """Owned pidfds for one sampled set; always close, including failed capture."""
    def __init__(self, domain):
        if not isinstance(domain, RuntimeDomain) or not hasattr(os, "pidfd_open"):
            raise Rejected("runtime-processes-pidfd-domain-required")
        self.domain = self._original_domain = domain
        self._configuration = domain.configuration()
        self._fds = []
        self.closed = False

    def _current(self, check):
        check()
        if (self.closed or self.domain is not self._original_domain
                or self.domain.configuration() != self._configuration):
            raise Rejected("runtime-processes-original-domain-required")
        self.domain.current()
        check()

    @staticmethod
    def _exited(fd, identity):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) != identity:
            raise Rejected("runtime-processes-pidfd-replaced")
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        events = poller.poll(0)
        if any(mask & ~(select.POLLIN | select.POLLHUP) for _, mask in events):
            raise Rejected("runtime-processes-pidfd-unconfirmed")
        return bool(events)

    @classmethod
    def capture(cls, *, domain, check):
        witness = cls(domain)
        try:
            witness._current(check)
            first = _scan(domain, check)
            for pid, path in sorted(first[1].items()):
                witness._current(check)
                fd = os.pidfd_open(pid, 0)
                # Retain ownership before any further syscall can fail.
                witness._fds.append((fd, None))
                info = os.fstat(fd)
                identity = info.st_dev, info.st_ino
                witness._fds[-1] = (fd, identity)
                os.set_inheritable(fd, False)
                if witness._exited(fd, identity):
                    raise Rejected("runtime-processes-capture-exited")
                # A live pidfd brackets the numeric /proc read. A recycled PID
                # cannot supply this process's membership after it has exited.
                with open("/proc/%d/cgroup" % pid, "rb") as source:
                    membership = source.read(MAX_BYTES + 1)
                if membership != ("0::" + path + "\n").encode("utf-8") or witness._exited(fd, identity):
                    raise Rejected("runtime-processes-membership-unconfirmed")
                witness._current(check)
            if first != _scan(domain, check):
                raise Rejected("runtime-processes-inventory-changed")
            if any(witness._exited(fd, identity) for fd, identity in witness._fds):
                raise Rejected("runtime-processes-trailing-capture-exited")
            witness._current(check)
            return witness
        except BaseException:
            witness.close()
            raise

    @property
    def count(self):
        if self.closed:
            raise Rejected("runtime-processes-witness-closed")
        return len(self._fds)

    def require_dead(self, *, check):
        self._current(check)
        for fd, identity in self._fds:
            if not self._exited(fd, identity):
                raise Rejected("runtime-processes-observed-process-still-live")
            self._current(check)
        self._current(check)

    def close(self):
        if not self.closed:
            self.closed = True
            failed = False
            for fd, _ in self._fds:
                try:
                    os.close(fd)
                except OSError:
                    failed = True
            self._fds.clear()
            if failed:
                raise Rejected("runtime-processes-descriptor-release-unconfirmed")
