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


class LocalCommands:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        # Keep references to killed helpers until they can be reaped without a
        # wait outside the inclusive deadline. A supervisor must call reap().
        self.pending = []

    def reap(self):
        self.pending = [proc for proc in self.pending if proc.poll() is None]

    def run(self, argv, *, deadline):
        if (type(argv) is not tuple or not argv or not os.path.isabs(argv[0])
                or any(type(arg) is not str or not arg or "\0" in arg for arg in argv)):
            raise Rejected("fixed-command-argv-required")
        remaining = Deadline(self.clock, deadline).remaining
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
                while selector.get_map():
                    for key, _ in selector.select(remaining()):
                        block = os.read(key.fd, min(8192, MAX_OUTPUT + 1 - len(raw)))
                        if not block:
                            selector.unregister(key.fileobj)
                        else:
                            raw.extend(block)
                            if len(raw) > MAX_OUTPUT:
                                raise CommandUncertain("command-output-overflow")
                try:
                    code = proc.wait(timeout=remaining())
                except subprocess.TimeoutExpired:
                    raise CommandUncertain("command-deadline-missed") from None
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
                proc.stdout.close()
