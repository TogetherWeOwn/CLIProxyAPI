"""Bounded local command transport; not a privilege or cgroup boundary.

Only fixed adapter-generated argv may reach this transport. Helpers inherit their
manager-owned cgroup; no shell, new session, environment credentials or caller cwd
is inherited. Killing a helper on deadline does NOT cancel a daemon/manager job
or prove descendants stopped. Every uncertain result requires reconciliation.
"""
import math
import os
import selectors
import subprocess
import time

from .durable import Rejected

MAX_OUTPUT = 64 * 1024


class CommandUncertain(Rejected):
    """No successful operation acknowledgment, including a lost reply."""


class Deadline:
    """Same-clock accounting only; cannot interrupt a wedged kernel operation."""
    def __init__(self, clock, deadline):
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise Rejected("command-deadline-required")
        self.clock, self.deadline = clock, deadline
        self.last = clock()
        if type(self.last) not in (int, float) or not math.isfinite(self.last):
            raise CommandUncertain("command-clock-discontinuity")

    def remaining(self):
        now = self.clock()
        if type(now) not in (int, float) or not math.isfinite(now) or now < self.last:
            raise CommandUncertain("command-clock-discontinuity")
        self.last = now
        if now >= self.deadline:
            raise CommandUncertain("command-deadline-missed")
        return self.deadline - now


def check_cancellation(fd):
    if fd is not None:
        if type(fd) is not int or fd < 0:
            raise Rejected("command-cancellation-descriptor-required")
        with selectors.DefaultSelector() as ready:
            ready.register(fd, selectors.EVENT_READ)
            if ready.select(0):
                raise CommandUncertain("command-cancelled")


class LocalCommands:
    def __init__(self, clock=time.monotonic, *, cancel_fd=None):
        self.clock, self.cancel_fd = clock, cancel_fd
        # Keep references to killed helpers until they can be reaped without a
        # wait outside the inclusive deadline. A supervisor must call reap().
        self.pending = []

    def reap(self):
        # Preserve the list object across a main-thread SIGCHLD handler. An
        # interrupted append must not target an obsolete list and lose ownership.
        self.pending[:] = [proc for proc in self.pending if proc.poll() is None]

    def run(self, argv, *, deadline):
        if (type(argv) is not tuple or not argv or not os.path.isabs(argv[0])
                or any(type(arg) is not str or not arg or "\0" in arg for arg in argv)):
            raise Rejected("fixed-command-argv-required")
        timer = Deadline(self.clock, deadline)
        def remaining():
            check_cancellation(self.cancel_fd)
            return timer.remaining()
        remaining()
        self.reap()
        proc = None
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, close_fds=True, cwd="/",
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                                         "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0"})
            raw = bytearray()
            os.set_blocking(proc.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                if self.cancel_fd is not None:
                    selector.register(self.cancel_fd, selectors.EVENT_READ, "cancel")
                while proc.stdout.fileno() in selector.get_map():
                    events = selector.select(remaining())
                    check_cancellation(self.cancel_fd)
                    for key, _ in events:
                        block = os.read(key.fd, min(8192, MAX_OUTPUT + 1 - len(raw)))
                        if not block:
                            selector.unregister(key.fileobj)
                        else:
                            raw.extend(block)
                            if len(raw) > MAX_OUTPUT:
                                raise CommandUncertain("command-output-overflow")
                if self.cancel_fd is None:
                    try:
                        code = proc.wait(timeout=remaining())
                    except subprocess.TimeoutExpired:
                        raise CommandUncertain("command-deadline-missed") from None
                else:
                    # stdout EOF is not process exit. A pidfd keeps cancellation
                    # live even for a helper that closes stdout then hangs.
                    code = proc.poll()
                    if code is None:
                        pidfd = os.pidfd_open(proc.pid, 0)
                        registered = False
                        try:
                            selector.register(pidfd, selectors.EVENT_READ)
                            registered = True
                            selector.select(remaining())
                            check_cancellation(self.cancel_fd)
                            code = proc.poll()
                            if code is None:
                                raise CommandUncertain("command-result-unconfirmed")
                        finally:
                            try:
                                if registered:
                                    selector.unregister(pidfd)
                            finally:
                                os.close(pidfd)
            remaining()
            if code != 0:
                raise CommandUncertain("command-result-unconfirmed")
            return bytes(raw)
        except (OSError, subprocess.SubprocessError):
            raise CommandUncertain("command-transport-unavailable") from None
        finally:
            if proc is not None:
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except OSError:
                        pass
                    self.pending.append(proc)
                    # Close the exit-before-registration SIGCHLD race without
                    # waiting; later exits are reaped by the persistent owner.
                    self.reap()
                proc.stdout.close()
