"""Exact-input comparison at admission and stopped forward revalidation.

The caller retains the installation lock, acquires the executable descriptor and
fresh source snapshots through protected handles, and independently authenticates
all approval pins. The check callback revalidates those handles and writer fence.
This composition supplies neither that authority nor rendering/schema validation,
complete host fencing, recovery execution or an independent old-start oracle.
"""
import copy
from dataclasses import dataclass
import hashlib
import os
import selectors
import stat
import subprocess

from .artifacts import PluginArtifactGate
from .commands import Deadline
from .durable import Rejected, canonical, digest, signature
from .loading import owner, pin

MAX_REQUEST = 36 * 1024 * 1024
MAX_HELPER = 64 * 1024 * 1024
RECEIPT = b'{"schema":"host-recovery-input-result-v1","matched":true,"start_authorized":false}\n'


@dataclass(frozen=True)
class InputApproval:
    intent_sha256: str
    request_sha256: str
    helper_sha256: str
    uid: int
    gid: int

    def __post_init__(self):
        for value in (self.intent_sha256, self.request_sha256, self.helper_sha256):
            pin(value)
        owner(self.uid, self.gid)


class ExactInputGate:
    """One pinned helper and request, rechecked separately at every barrier.

    snapshot(intent, deadline=...) must freshly capture the actual source and
    frozen-render inputs plus independently approved policy, not cached proposed
    bytes. A request digest authenticates nothing by itself. check() must confirm
    the calling owner/lock/protected handles/writer fence before and after capture.
    No secret bytes, parser diagnostics or helper output escape through errors.
    """
    receipt = RECEIPT

    def __init__(self, *, helper_fd, approval, snapshot, check, clock):
        if (type(helper_fd) is not int or helper_fd < 0 or not isinstance(approval, InputApproval)
                or not all(callable(value) for value in (snapshot, check, clock))):
            raise Rejected("input-gate-explicit-boundary-required")
        self.helper_fd, self.approval = helper_fd, approval
        self.snapshot, self.check, self.clock = snapshot, check, clock
        self.pending = []

    def reap(self):
        self.pending = [proc for proc in self.pending if proc.poll() is None]

    def _current(self, remaining):
        remaining()
        if self.check() is not True:
            raise Rejected("input-gate-boundary-unconfirmed")
        remaining()

    def _helper(self, remaining):
        remaining()
        fd, approval = self.helper_fd, self.approval
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_uid, before.st_gid) != (approval.uid, approval.gid)
                or stat.S_IMODE(before.st_mode) not in (0o500, 0o555, 0o700, 0o755)
                or not 0 < before.st_size <= MAX_HELPER or os.listxattr(fd)):
            raise Rejected("input-gate-protected-helper-required")
        checksum, offset = hashlib.sha256(), 0
        while offset < before.st_size:
            remaining()
            block = os.pread(fd, min(65536, before.st_size - offset), offset)
            if not block:
                raise Rejected("input-gate-helper-changed")
            checksum.update(block)
            offset += len(block)
        if (checksum.hexdigest() != approval.helper_sha256
                or signature(before) != signature(os.fstat(fd))):
            raise Rejected("input-gate-helper-pin-mismatch")
        remaining()
        return signature(before)

    def _capture(self, intent, deadline, remaining):
        self._current(remaining)
        raw = self.snapshot(copy.deepcopy(intent), deadline=deadline)
        self._current(remaining)
        if (type(raw) is not bytes or not 0 < len(raw) <= MAX_REQUEST
                or digest(raw) != self.approval.request_sha256):
            raise Rejected("input-gate-request-pin-mismatch")
        remaining()
        return raw

    def verify(self, intent, *, deadline):
        remaining = Deadline(self.clock, deadline).remaining
        try:
            if digest(canonical(intent)) != self.approval.intent_sha256:
                raise Rejected("input-gate-intent-pin-mismatch")
            self._current(remaining)
            helper = self._helper(remaining)
            raw = self._capture(intent, deadline, remaining)
            self._run(raw, remaining)
            # A success receipt is not reusable after source/helper/fence drift.
            self._capture(intent, deadline, remaining)
            if self._helper(remaining) != helper:
                raise Rejected("input-gate-helper-changed")
            self._current(remaining)
        except Exception:
            raise Rejected("input-gate-unconfirmed") from None
        return True

    def _run(self, raw, remaining):
        remaining()
        self.reap()
        proc = None
        try:
            # Execute the inspected inode, never reopen an executable pathname.
            # The helper stays in the caller's cgroup. Its death is not a fence.
            proc = subprocess.Popen(("/proc/self/fd/" + str(self.helper_fd),),
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, close_fds=True,
                                    pass_fds=(self.helper_fd,), cwd="/",
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
            sent, output = 0, bytearray()
            os.set_blocking(proc.stdin.fileno(), False)
            os.set_blocking(proc.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdin, selectors.EVENT_WRITE)
                selector.register(proc.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    for key, _ in selector.select(remaining()):
                        if key.fileobj is proc.stdin:
                            sent += os.write(key.fd, memoryview(raw)[sent:sent + 65536])
                            if sent == len(raw):
                                selector.unregister(proc.stdin)
                                proc.stdin.close()
                        else:
                            block = os.read(key.fd, 4097 - len(output))
                            if not block:
                                selector.unregister(proc.stdout)
                            else:
                                output.extend(block)
                                if len(output) > 4096:
                                    raise Rejected("input-gate-output-limit")
                code = proc.wait(timeout=remaining())
            remaining()
            if sent != len(raw) or code != 0 or bytes(output) != self.receipt:
                raise Rejected("input-gate-helper-refused")
        finally:
            if proc is not None:
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except OSError:
                        pass
                    # Do not add unmetered wait time; a manager must reap pending
                    # children and prove the complete group stopped independently.
                    self.pending.append(proc)
                proc.stdin.close()
                proc.stdout.close()


class ApplicationInputGate(ExactInputGate):
    """Require the application-aware helper, not a comparison-only success receipt.

    All descriptor, capture, deadline and same-lock boundary checks are inherited.
    Only host-owned config types/intrinsic validators are covered; plugin options,
    Compose schemas/rendering and operational/recovery readiness are not.
    """
    receipt = (b'{"schema":"host-recovery-application-input-result-v1","matched":true,'
               b'"application_validated":true,"start_authorized":false}\n')


class GuardedBoundary:
    """Compose the comparison with existing preflight/stopped checks, not replace them.

    Recovery methods are deliberately delegated unchanged: invalid candidate input
    cannot block restoration. Baseline semantic validation remains the independent
    recovery/start oracle's responsibility. This is opt-in source composition, not
    a runnable production supervisor or an installed admission/start fence.
    """
    def __init__(self, boundary, gate, *, preflight_deadline, artifact_gate=None):
        if not isinstance(gate, ExactInputGate):
            raise Rejected("input-gate-required")
        if artifact_gate is not None and not isinstance(artifact_gate, PluginArtifactGate):
            raise Rejected("artifact-gate-required")
        self.boundary, self.gate, self.artifact_gate = boundary, gate, artifact_gate
        self.preflight_deadline = preflight_deadline

    def _verify(self, intent, deadline):
        if self.artifact_gate is not None and self.artifact_gate.verify(intent, deadline=deadline) is not True:
            return False
        return self.gate.verify(intent, deadline=deadline)

    def preflight(self, intent):
        if self.boundary.preflight(copy.deepcopy(intent)) is not True:
            return False
        return self._verify(intent, self.preflight_deadline)

    def revalidate_stopped(self, intent, *, deadline):
        if self.boundary.revalidate_stopped(copy.deepcopy(intent), deadline=deadline) is not True:
            return False
        return self._verify(intent, deadline)

    def __getattr__(self, name):
        return getattr(self.boundary, name)
