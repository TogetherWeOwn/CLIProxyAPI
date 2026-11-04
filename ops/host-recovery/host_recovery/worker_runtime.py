"""Protected worker launch composition; the supervisor retains the only lock.

The installed service/interpreter and approvals must be independently provisioned.
No code is imported from the captured content. Identity-only invocation is runnable
without granting recovery; execution additionally requires the existing independent
operational boundary, not an on-disk flag or a successful claim.
"""
from contextlib import ExitStack
import copy
import os
import time

from .bootstrap import kernel_boot_id
from .commands import Deadline, LocalCommands
from .durable import Rejected, canonical, decode, digest, notify, read_file
from .installation import DirectoryApproval, open_approved_directory
from .launch import LaunchApproval
from .loading import load_content, load_recovery
from .worker_bootstrap import SystemdWorkerBootstrap
from .worker_recovery import WorkerEvidence, WorkerRecovery


def _separate(approvals):
    for index, first in enumerate(approvals):
        for second in approvals[index + 1:]:
            if ((first.device, first.inode) == (second.device, second.inode)
                    or os.path.commonpath((first.path, second.path)) in (first.path, second.path)):
                raise Rejected("worker-runtime-separate-roots-required")


def run_worker(approval, *, endpoint, deadline, boundary=None, evidence=None,
               persist_alert=None, transport_alert=None, clock=time.monotonic,
               boot_id=kernel_boot_id, commands=None):
    """Load pinned original inputs, claim once and optionally run/report recovery.

    The journal descriptor is read-only and never flocked by the worker. Writer
    exclusion comes from the authenticated connected supervisor's retained lock,
    not from opening a path. Repeated snapshots detect observed drift but cannot
    defend against hostile same-UID/root writers or attest the installed code.

    With no execution arguments this exchanges identity only. With all four,
    WorkerRecovery requires its independent operational authorization and complete
    fence/oracle contracts. Scripted boundaries remain component evidence. No
    service install, forward operation, journal terminal or settlement is provided.
    """
    if (not isinstance(approval, LaunchApproval) or not isinstance(endpoint, DirectoryApproval)
            or endpoint.mode != 0o700
            or (endpoint.uid, endpoint.gid) != (os.geteuid(), os.getegid())
            or (approval.recovery.uid, approval.recovery.gid) != (os.geteuid(), os.getegid())):
        raise Rejected("worker-runtime-explicit-approval-required")
    execution = any(value is not None for value in (boundary, evidence, persist_alert, transport_alert))
    if execution and (boundary is None or not isinstance(evidence, DirectoryApproval)
                      or evidence.mode != 0o700
                      or (evidence.uid, evidence.gid) != (os.geteuid(), os.getegid())
                      or not callable(persist_alert) or not callable(transport_alert)):
        raise Rejected("worker-runtime-execution-boundaries-required")
    alerted = False

    def alert_transport(notice):
        nonlocal alerted
        alerted = True
        return transport_alert(notice)

    try:
        return _run_worker(approval, endpoint=endpoint, deadline=deadline, boundary=boundary, evidence=evidence,
            persist_alert=persist_alert, transport_alert=alert_transport if execution else None,
            clock=clock, boot_id=boot_id, commands=commands)
    except Exception:
        # Protected-input/connection/context-exit failures can happen before or
        # after WorkerRecovery exists. Storage must never gate independent alert.
        if execution and not alerted:
            notify({"schema": "host-recovery-notice-v1", "attempt_id": approval.recovery.attempt_id,
                    "original_cause": "supervisor-restart-recovery-required",
                    "recovery_error": "recovery-resume-inputs-failed", "outcome": "recovery_unresolved",
                    "start_fenced": True}, persist_alert, alert_transport)
        raise


def _run_worker(approval, *, endpoint, deadline, boundary, evidence, persist_alert, transport_alert,
                clock, boot_id, commands):
    execution = boundary is not None
    roots = [approval.installation.content, approval.installation.journal, endpoint]
    if execution:
        roots.append(evidence)
    _separate(roots)
    timer = Deadline(clock, deadline)
    timer.remaining()
    transport = LocalCommands(clock) if commands is None else commands
    active, failed = True, False
    with ExitStack() as stack:
        directories = [stack.enter_context(open_approved_directory(root)) for root in roots]
        content_root, journal_root, endpoint_root = directories[:3]
        # Discovery only. load_recovery authenticates the complete request against
        # the independently approved request digest before using this owner.
        raw, _ = read_file(journal_root.fd, "reconcile-request.json")
        owner = decode(raw).get("owner")
        content = load_content(content_root.fd, approval.content)
        inputs = load_recovery(journal_root.fd, approval=approval.recovery, binding=approval.job,
            supervisor_owner=owner, boot_id=boot_id(), now=clock())
        end = min(deadline, inputs.request["deadline"])
        timer.deadline = end

        def current(*, deadline):
            nonlocal failed
            try:
                if not active or failed or deadline > end:
                    raise Rejected("worker-runtime-session-unavailable")
                timer.remaining()
                Deadline(clock, deadline).remaining()
                for directory in directories:
                    directory.validate()
                captured = load_content(content_root.fd, approval.content)
                original = load_recovery(journal_root.fd, approval=approval.recovery, binding=approval.job,
                    supervisor_owner=owner, boot_id=boot_id(), now=clock())
                if captured.files != content.files or original != inputs:
                    raise Rejected("worker-runtime-inputs-changed")
                for directory in directories:
                    directory.validate()
                timer.remaining()
                Deadline(clock, deadline).remaining()
                return True
            except BaseException:
                failed = True
                raise

        class PinnedBootstrap(SystemdWorkerBootstrap):
            def _verify_peer(self, *, peer, peer_alive, deadline):
                current(deadline=deadline)
                result = super()._verify_peer(peer=peer, peer_alive=peer_alive, deadline=deadline)
                current(deadline=deadline)
                return result

        try:
            current(deadline=end)
            worker = PinnedBootstrap(systemctl=approval.systemctl, commands=transport,
                supervisor_binding=approval.supervisor, worker_binding=approval.job,
                request=inputs.request, intent_sha256=approval.recovery.intent_sha256,
                installation_id=approval.recovery.installation_id, attempt_id=approval.recovery.attempt_id,
                clock=clock, boot_id=boot_id)
            provider = None
            if execution:
                engine = WorkerRecovery(approval=approval.recovery, binding=approval.job,
                    intent=inputs.intent, request=inputs.request, boundary=boundary,
                    evidence=WorkerEvidence(evidence, approval.job.request_id, clock=clock),
                    persist_alert=persist_alert, transport_alert=transport_alert, clock=clock, boot_id=boot_id)

                def provider(claim, *, deadline, check):
                    def lease(*, deadline):
                        current(deadline=deadline)
                        if check(deadline=deadline) is not True:
                            raise Rejected("worker-runtime-peer-unconfirmed")
                        return current(deadline=deadline)
                    return engine(claim, deadline=deadline, check=lease)

            path = os.path.join(endpoint_root.approval.path, "claim-" + approval.job.request_id + ".sock")
            kwargs = {} if provider is None else {"recovery_provider": provider}
            claim = worker.claim(path, deadline=end, **kwargs)
            current(deadline=end)
            result = {"schema": "host-recovery-worker-runtime-v1", "request_id": approval.job.request_id,
                      "intent_sha256": approval.recovery.intent_sha256, "claim_sha256": digest(canonical(claim)),
                      "operation": "claim_and_report" if execution else "claim",
                      "state": "report_acknowledged_unsettled" if execution else "identity_received_only",
                      "result_receipt": copy.deepcopy(worker.result_receipt),
                      "start_permission": False, "recovery_completed": False,
                      "installation_settled": False, "production_acceptance": False}
        finally:
            # A retained provider/check cannot touch borrowed descriptors after
            # close, including when an fd number is reused for another directory.
            active = False
    timer.remaining()
    return result
