"""Pinned launch configuration and read-only calling-supervisor status.

The digest and numeric configuration owner come from the trusted launch boundary,
never from this file, its adjacent index, environment identity or a worker request.
A matching digest proves correspondence to that anchor, not who approved it. This
reader neither provisions that anchor nor installs a service/complete host fence.
"""
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


def inspect_status(approval, *, deadline, clock=time.monotonic, boot_id=kernel_boot_id, commands=None):
    """Read status as the pinned calling MainPID; no dispatch/restore/start route.

    One caller deadline bounds all local manager queries and is checked around
    filesystem reads; original journal deadlines can shorten it, never renew it.
    An expired/cross-boot journal refuses rather than issuing a new allowance.
    commands is injectable only as a trusted component-test boundary.
    """
    if not isinstance(approval, LaunchApproval):
        raise Rejected("launch-typed-approval-required")
    timer = Deadline(clock, deadline)
    timer.remaining()
    transport = LocalCommands(clock) if commands is None else commands
    observer = SystemdSupervisorIdentity(systemctl=approval.systemctl, commands=transport,
                                         binding=approval.supervisor, clock=clock, boot_id=boot_id)
    observed = observer.bootstrap(installation_id=approval.recovery.installation_id,
                                  attempt_id=approval.recovery.attempt_id, deadline=deadline)
    timer.remaining()
    with open_installation(approval.installation) as handles:
        content, inputs = handles.snapshot(content_approval=approval.content, recovery_approval=approval.recovery,
            binding=approval.job, supervisor_owner=observed["owner"], boot_id=observed["owner"]["boot_id"], now=clock())
        end = min(deadline, inputs.request["deadline"])
        remaining = Deadline(clock, end)
        remaining.remaining()
        observer.observe_owner(observed["owner"], deadline=end)
        handles.validate()
        # Readback after the final manager observation prevents that observation
        # from concealing a cooperating journal/content change during the query.
        latest_content, latest_inputs = handles.snapshot(content_approval=approval.content,
            recovery_approval=approval.recovery, binding=approval.job, supervisor_owner=observed["owner"],
            boot_id=observed["owner"]["boot_id"], now=clock())
        if latest_content.files != content.files or latest_inputs != inputs:
            raise Rejected("launch-snapshot-changed")
        remaining.remaining()
        result = {"schema": "host-recovery-status-v1", "operation": "status", "state": "inputs_verified_only",
                  "installation_id": approval.recovery.installation_id, "attempt_id": approval.recovery.attempt_id,
                  "request_id": approval.job.request_id, "source_revision": approval.content.source_revision,
                  "intent_sha256": approval.recovery.intent_sha256, "content_index_sha256": approval.content.index_sha256,
                  "complete_fence_proven": False, "recovery_execution_allowed": False, "start_allowed": False,
                  "terminal_outcome_verified": False, "production_acceptance": False}
    # Context-exit ancestry validation must also succeed before publishing status.
    remaining.remaining()
    return result
