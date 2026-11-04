"""Pinned launch configuration and read-only calling-supervisor status.

The digest and numeric configuration owner come from the trusted launch boundary,
never from this file, its adjacent index, environment identity or a worker request.
A matching digest proves correspondence to that anchor, not who approved it. This
reader neither provisions that anchor nor installs a service/complete host fence.
"""
import copy
from contextlib import contextmanager
from dataclasses import dataclass, fields
import os
import stat
import time

from .bootstrap import SupervisorBinding, SystemdSupervisorIdentity, kernel_boot_id
from .commands import Deadline, LocalCommands
from .durable import Rejected, decode, digest, read_file, signature
from .installation import DirectoryApproval, InstallationApproval, _Directory, open_installation, protected
from .jobs import RecoveryJobBinding
from .loading import ContentApproval, RecoveryApproval, owner, pin


@dataclass(frozen=True)
class LaunchApproval:
    installation: InstallationApproval
    content: ContentApproval
    recovery: RecoveryApproval
    supervisor: SupervisorBinding
    job: RecoveryJobBinding
    systemctl: str

    def __post_init__(self):
        expected = ((self.installation, InstallationApproval), (self.content, ContentApproval),
                    (self.recovery, RecoveryApproval), (self.supervisor, SupervisorBinding),
                    (self.job, RecoveryJobBinding))
        if any(not isinstance(value, kind) for value, kind in expected):
            raise Rejected("launch-typed-approval-required")
        if (self.installation.installation_id != self.recovery.installation_id
                or (self.content.uid, self.content.gid) != (self.installation.content.uid, self.installation.content.gid)
                or (self.recovery.uid, self.recovery.gid) != (self.installation.journal.uid, self.installation.journal.gid)
                or (self.supervisor.uid, self.supervisor.gid) != (self.recovery.uid, self.recovery.gid)):
            raise Rejected("launch-approval-identity-mismatch")
        if (type(self.systemctl) is not str or not self.systemctl.startswith("/") or len(self.systemctl) > 4096
                or any(part in ("", ".", "..") or "\0" in part for part in self.systemctl.split("/")[1:])):
            raise Rejected("launch-explicit-systemctl-required")


def typed(kind, value):
    if type(value) is not dict or set(value) != {field.name for field in fields(kind)}:
        raise Rejected("launch-approval-schema")
    return kind(**value)


def parse_launch(raw):
    value = decode(raw)
    if set(value) != {"schema", "installation", "content", "recovery", "supervisor", "job", "systemctl"}:
        raise Rejected("launch-approval-schema")
    if value["schema"] != "host-recovery-launch-v1":
        raise Rejected("launch-approval-schema")
    layout = value["installation"]
    if type(layout) is not dict or set(layout) != {"installation_id", "content", "journal"}:
        raise Rejected("launch-approval-schema")
    installation = InstallationApproval(layout["installation_id"], typed(DirectoryApproval, layout["content"]),
                                        typed(DirectoryApproval, layout["journal"]))
    return LaunchApproval(installation, typed(ContentApproval, value["content"]),
                          typed(RecoveryApproval, value["recovery"]), typed(SupervisorBinding, value["supervisor"]),
                          typed(RecoveryJobBinding, value["job"]), value["systemctl"])


def load_launch(path, *, sha256, uid, gid):
    """Read exact bytes through protected ancestry with an external digest anchor.

    The parent inode is observed here for edge continuity, NOT used as approval.
    The external digest authenticates neither the installer nor its authority;
    provisioning/review of that digest and the executable launch remains required.
    All descriptors close on refusal. No directory, file or permission is changed.
    """
    pin(sha256)
    owner(uid, gid)
    if (type(path) is not str or not path.startswith("/") or len(path) > 4096
            or len(path.split("/")) > 65
            or any(part in ("", ".", "..") or "\0" in part for part in path.split("/")[1:])):
        raise Rejected("launch-absolute-path-required")
    parent, name = os.path.split(path)
    # A root-level approval file is deliberately unsupported by DirectoryApproval.
    st = os.stat(parent, follow_symlinks=False)
    directory = _Directory(DirectoryApproval(parent, st.st_dev, st.st_ino, st.st_uid, st.st_gid,
                                               stat.S_IMODE(st.st_mode)))
    try:
        # Only root or the explicitly trusted configuration owner may own ancestors.
        # _Directory also checks against the parent owner; this additional pass
        # prevents a foreign parent owner from becoming its own trust anchor.
        for _, fd, _ in directory.chain:
            protected(fd, uid)
        raw, before = read_file(directory.fd, name, limit=65536)
        if ((before.st_uid, before.st_gid) != (uid, gid)
                or stat.S_IMODE(before.st_mode) not in (0o400, 0o444, 0o600, 0o644)
                or before.st_dev != os.fstat(directory.fd).st_dev):
            raise Rejected("launch-protected-configuration-required")
        if digest(raw) != sha256:
            raise Rejected("launch-configuration-pin-mismatch")
        result = parse_launch(raw)
        again, after = read_file(directory.fd, name, limit=65536)
        if raw != again or signature(before) != signature(after):
            raise Rejected("launch-configuration-changed")
        directory.validate()
        return result
    finally:
        directory.close()


class _CallingSession:
    """Borrowed read-only inputs/lock; never an execution or fence lease."""
    def __init__(self, approval, observer, observed, handles, content, inputs, clock, timer):
        self.approval, self.observer, self.handles = approval, observer, handles
        self.observed = copy.deepcopy(observed)
        self.content, self.inputs, self.clock = content, inputs, clock
        self.deadline = min(timer.deadline, inputs.request["deadline"])
        self.timer = timer
        self.timer.deadline = self.deadline
        self.closed, self.failed = False, False

    def validate(self):
        if self.closed or self.failed:
            raise Rejected("launch-session-unavailable")
        try:
            self.timer.remaining()
            expected = self.observed["owner"]
            actual = self.observer.observe_owner(copy.deepcopy(expected), deadline=self.deadline)
            if type(actual) is not dict or actual != expected:
                raise Rejected("launch-supervisor-owner-changed")
            self.handles.validate()
            # Readback after the manager query prevents that query from concealing
            # a cooperating journal/content change. Never adopt a newer request.
            content, inputs = self.handles.snapshot(content_approval=self.approval.content,
                recovery_approval=self.approval.recovery, binding=self.approval.job,
                supervisor_owner=expected, boot_id=expected["boot_id"], now=self.clock())
            if content.files != self.content.files or inputs != self.inputs:
                raise Rejected("launch-snapshot-changed")
            self.timer.remaining()
        except BaseException:
            self.failed = True
            raise

    def status(self):
        if self.closed or self.failed:
            raise Rejected("launch-session-unavailable")
        return {"schema": "host-recovery-status-v1", "operation": "status", "state": "inputs_verified_only",
                "installation_id": self.approval.recovery.installation_id,
                "attempt_id": self.approval.recovery.attempt_id, "request_id": self.approval.job.request_id,
                "source_revision": self.approval.content.source_revision,
                "intent_sha256": self.approval.recovery.intent_sha256,
                "content_index_sha256": self.approval.content.index_sha256,
                "complete_fence_proven": False, "recovery_execution_allowed": False, "start_allowed": False,
                "terminal_outcome_verified": False, "production_acceptance": False}


@contextmanager
def _calling_session(approval, *, deadline, clock, boot_id, commands):
    """Retain the existing installation lock until final ancestry validation.

    Private input/identity composition for status, observation and identity-only
    broker exchange. The caller must not publish a result until context exit
    succeeds. This session never acquires a second lock or grants execution/fence
    authority. The broker separately requires its explicit complete-fence boundary.
    """
    if not isinstance(approval, LaunchApproval):
        raise Rejected("launch-typed-approval-required")
    timer = Deadline(clock, deadline)
    timer.remaining()
    observer = SystemdSupervisorIdentity(systemctl=approval.systemctl, commands=commands,
                                         binding=approval.supervisor, clock=clock, boot_id=boot_id)
    observed = observer.bootstrap(installation_id=approval.recovery.installation_id,
                                  attempt_id=approval.recovery.attempt_id, deadline=deadline)
    timer.remaining()
    with open_installation(approval.installation) as handles:
        content, inputs = handles.snapshot(content_approval=approval.content, recovery_approval=approval.recovery,
            binding=approval.job, supervisor_owner=observed["owner"], boot_id=observed["owner"]["boot_id"], now=clock())
        # Keep clock continuity from bootstrap through the initial filesystem read.
        timer.remaining()
        session = _CallingSession(approval, observer, observed, handles, content, inputs, clock, timer)
        try:
            session.validate()
            yield session
        finally:
            session.closed = True
    session.timer.remaining()


def inspect_status(approval, *, deadline, clock=time.monotonic, boot_id=kernel_boot_id, commands=None):
    """Read status as the pinned calling MainPID; no dispatch/restore/start route.

    One caller deadline bounds all local manager queries and is checked around
    filesystem reads; original journal deadlines can shorten it, never renew it.
    An expired/cross-boot journal refuses rather than issuing a new allowance.
    commands is injectable only as a trusted component-test boundary.
    """
    transport = LocalCommands(clock) if commands is None else commands
    with _calling_session(approval, deadline=deadline, clock=clock, boot_id=boot_id, commands=transport) as session:
        result = session.status()
    return result
