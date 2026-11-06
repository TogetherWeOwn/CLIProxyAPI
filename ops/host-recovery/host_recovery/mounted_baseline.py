"""Complete baseline reads through an externally authenticated process root.

The caller must bind the supplied live pidfd to the old full container identity,
retain the installation lock and exclude mount/file/process writers. No daemon
PID discovery, setns, mount, exec, restoration or start is performed here. A
process-root observation does not prove plugin loading, readiness or a fence.
"""
from contextlib import ExitStack, contextmanager
import copy
from dataclasses import dataclass
import os

from .durable import Rejected, canonical, digest
from .journal import validate_intent
from .loading import pin
from .process_mounts import mount_identity, open_process_mount_view, root_identity
from .write_set import WriteSetVerifier


@dataclass(frozen=True)
class MountedBaselineApproval:
    intent_sha256: str
    object_id: str
    mounts_sha256: str

    def __post_init__(self):
        for value in (self.intent_sha256, self.object_id, self.mounts_sha256):
            pin(value)


@contextmanager
def open_mounted_baseline(*, pid, pidfd, approval, mounts, verifier, check, clock):
    """Borrow authenticated authority, duplicate the pidfd and retain kernel views.

    approval and the entire mount mapping are provisioned independently, not
    inferred from a worker report or the current process. Unsupported procfs/nsfs
    access fails closed without a numeric-PID or caller-namespace fallback.
    """
    if not isinstance(approval, MountedBaselineApproval) or not isinstance(verifier, WriteSetVerifier):
        raise Rejected("mounted-baseline-explicit-boundaries-required")
    with ExitStack() as stack:
        process = stack.enter_context(open_process_mount_view(pid=pid, pidfd=pidfd, check=check, clock=clock))
        view = MountedBaseline(process, approval, mounts, verifier, stack)
        try:
            yield view
        finally:
            view.closed = True


class MountedBaseline:
    """Read every approved root from the target's kernel root, never a start oracle."""
    def __init__(self, process, approval, mounts, verifier, stack):
        self.process, self.approval, self.mounts, self.verifier = process, approval, mounts, verifier
        self._binding = process, approval, canonical(mounts), verifier, process._binding
        self._stack, self._retained, self._signature = stack, None, None
        self.closed = self.failed = self.attempted = False

    def _bound(self, intent):
        process, approval, mounts, verifier, binding = self._binding
        if (self.closed or self.failed or self.process is not process or self.approval != approval
                or self.verifier is not verifier or canonical(self.mounts) != mounts
                or process._binding != binding
                or digest(canonical(intent)) != approval.intent_sha256
                or intent["old_object_id"] != approval.object_id
                or digest(mounts) != approval.mounts_sha256):
            raise Rejected("mounted-baseline-binding-changed")
        process._bound()
        verifier._bound_reader()

    def _mapping(self):
        reader = self.verifier._bound_reader()
        sources = {handle.approval.path: name for name, handle in reader.roots.items()}
        result = {}
        for mount in self.mounts:
            # verify_bind_sources validates the full strict mount schema first.
            name = sources[mount["Source"]]
            if name in result:
                raise Rejected("mounted-baseline-duplicate-root")
            result[name] = mount["Destination"]
        if set(result) != set(reader.roots):
            raise Rejected("mounted-baseline-all-roots-required")
        return result

    def _view(self, stack):
        ns = os.open("ns/mnt", os.O_RDONLY | os.O_CLOEXEC, dir_fd=self.process.proc)
        stack.callback(os.close, ns)
        root = os.open("root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=self.process.proc)
        stack.callback(os.close, root)
        return (ns, root), (mount_identity(ns), root_identity(root))

    @staticmethod
    def _destination(root, path, stack):
        parts = path[1:].split("/")
        if len(parts) > 128:
            raise Rejected("mounted-baseline-destination-depth")
        with ExitStack() as walk:
            fd = root
            for part in parts:
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                walk.callback(os.close, fd)
            retained = os.dup(fd)
            stack.callback(os.close, retained)
            os.set_inheritable(retained, False)
            return retained

    def _verify(self, intent, deadline):
        self._bound(intent)
        process, _, _, verifier, _ = self._binding
        process._current(deadline)
        verifier.verify_bind_sources(intent, self.mounts, deadline=deadline)
        self._bound(intent)
        process._current(deadline)
        self._bound(intent)
        mapping = self._mapping()
        with ExitStack() as sample:
            handles, before = self._view(sample)
            if self._signature is not None and before != self._signature:
                raise Rejected("mounted-baseline-process-view-changed")
            roots = {name: self._destination(handles[1], path, sample) for name, path in mapping.items()}
            identities = {name: root_identity(fd) for name, fd in roots.items()}
            receipt = verifier.verify_mounted_files(intent, roots, deadline=deadline)
            self._bound(intent)
            # No authority/clock callback follows these final kernel path reads.
            # Reopen destinations: a still-open detached fd cannot prove what the
            # process now resolves after a mount or root replacement.
            with ExitStack() as trailing:
                current_handles, after = self._view(trailing)
                if (before != after or (mount_identity(handles[0]), root_identity(handles[1])) != before
                        or self._retained is not None and
                        (mount_identity(self._retained[0]), root_identity(self._retained[1])) != before):
                    raise Rejected("mounted-baseline-process-view-changed")
                current_root = current_handles[1]
                for name, path in mapping.items():
                    current = self._destination(current_root, path, trailing)
                    if root_identity(current) != identities[name] or root_identity(roots[name]) != identities[name]:
                        raise Rejected("mounted-baseline-destination-changed")
            process._bound()
            if self._retained is None:
                # Retain only the namespace/root; destination fds remain scoped
                # to this scan and are freshly reopened at every later barrier.
                retained = []
                for original in handles:
                    fd = os.dup(original)
                    self._stack.callback(os.close, fd)
                    os.set_inheritable(fd, False)
                    retained.append(fd)
                self._retained, self._signature = tuple(retained), before
            return {**receipt, "schema": "host-recovery-process-baseline-v1",
                    "object_id": self.approval.object_id, "mounts_sha256": self.approval.mounts_sha256,
                    "process_view_sha256": digest(canonical(before)), "process_root_observed": True,
                    "plugin_readiness_verified": False}

    @contextmanager
    def observe(self, intent, *, deadline):
        if self.attempted:
            self.failed = True
            raise Rejected("mounted-baseline-once-only")
        self.attempted = True
        value = copy.deepcopy(intent)
        original = canonical(value)
        try:
            validate_intent(value)
            receipt = self._verify(value, deadline)
            if canonical(intent) != original:
                raise Rejected("mounted-baseline-intent-changed")
            yield copy.deepcopy(receipt)
            if canonical(intent) != original:
                raise Rejected("mounted-baseline-intent-changed")
            if self._verify(value, deadline) != receipt:
                raise Rejected("mounted-baseline-observation-changed")
        except BaseException:
            self.failed = True
            raise Rejected("mounted-baseline-observation-unconfirmed") from None
