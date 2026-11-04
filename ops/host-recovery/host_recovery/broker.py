"""Pinned calling-manager to one worker identity exchange, not recovery execution.

The original request must already exist and belong to this supervisor invocation.
The existing installation lock is borrowed, never reacquired or handed to the
worker. The complete fence and independent alert transport are explicit trusted
boundaries; this composition neither implements nor authenticates them. No live
entrypoint/default, service installation, dispatch, restore or start grant exists.
"""
import copy
import os
import time

from .bootstrap import kernel_boot_id
from .commands import LocalCommands
from .durable import Rejected, canonical, notify
from .installation import DirectoryApproval, open_approved_directory
from .jobs import SystemdRecoveryJobs
from .launch import LaunchApproval, _calling_session
from .supervisor import RecoverySupervisor
from .worker import WorkerListener


class _ClaimManager:
    """No enqueue method: this manager can only revalidate an existing request."""
    def __init__(self, session, endpoint, fence):
        self.session, self.endpoint, self.fence_boundary = session, endpoint, fence

    def validate(self, deadline):
        if deadline > self.session.deadline:
            raise Rejected("broker-original-deadline-required")
        self.session.timer.remaining()
        self.endpoint.validate()
        self.session.validate()

    def observe_owner(self, owner, *, deadline):
        self.validate(deadline)
        if canonical(owner) != canonical(self.session.observed["owner"]):
            raise Rejected("broker-original-owner-required")
        return copy.deepcopy(self.session.observed["owner"])

    def fence(self, intent, *, deadline):
        self.validate(deadline)
        if canonical(intent) != canonical(self.session.inputs.intent):
            raise Rejected("broker-original-intent-required")
        result = self.fence_boundary(copy.deepcopy(intent), deadline=deadline)
        self.validate(deadline)
        return result is True


class _ClaimJobs:
    def __init__(self, jobs, uid, gid):
        self.jobs, self.uid, self.gid = jobs, uid, gid

    def observe(self, request_id, *, deadline):
        return self.jobs.observe(request_id, deadline=deadline)

    def observe_worker(self, request_id, *, pid, deadline):
        return self.jobs.observe_worker(request_id, pid=pid, deadline=deadline, uid=self.uid, gid=self.gid)


def serve_claim(approval, *, endpoint, deadline, fence, persist_alert, transport_alert,
                clock=time.monotonic, boot_id=kernel_boot_id, commands=None, fault=None, result_oracle=None):
    """Serve one original-owner identity claim using pinned manager/input readers.

    endpoint is an independently approved private directory, owned by the calling
    supervisor's numeric UID/GID. Only the fixed request-digest socket name is used.
    A preexisting socket is never removed/replaced, even after a lost reply. The
    current transport supports same-UID workers only; there is no permission grant.

    fence must enforce all starts/writers/pending operations, not just return a
    matching value. persist_alert and transport_alert retain their existing local
    receipt semantics. They must be independently provisioned and bounded; caller
    dictionaries and scripted callbacks are not proof of operational enforcement.
    The returned secret-free receipt means a local claim reply was sent, not that
    the peer received/accepted it or recovery ran. Context-exit validation must
    succeed before the receipt is returned. Failure leaves original durable state.
    Optional result_oracle extends the same connection to a durable worker report
    and fresh independent result observation. It must implement the RESULTS-v1
    contract; a scripted callback is not that oracle. No settlement/start grant is
    added, and a failed result exchange cannot return identity-only success.
    """
    if (not isinstance(approval, LaunchApproval) or not isinstance(endpoint, DirectoryApproval)
            or endpoint.mode != 0o700
            or not all(callable(value) for value in (fence, persist_alert, transport_alert))
            or result_oracle is not None and not callable(result_oracle)):
        raise Rejected("broker-explicit-boundaries-required")
    alerted = False

    def alert_transport(notice):
        nonlocal alerted
        alerted = True
        return transport_alert(notice)

    try:
        return _serve_claim(approval, endpoint=endpoint, deadline=deadline, fence=fence,
            persist_alert=persist_alert, transport_alert=alert_transport, clock=clock,
            boot_id=boot_id, commands=commands, fault=fault, result_oracle=result_oracle)
    except Exception:
        # Bootstrap/readback/context-exit failures can precede or outlive the
        # supervisor object. They still need independent transport on disk failure.
        if not alerted:
            notify({"schema": "host-recovery-notice-v1", "attempt_id": approval.recovery.attempt_id,
                    "original_cause": "supervisor-restart-recovery-required",
                    "recovery_error": "supervisor-worker-claim-unconfirmed",
                    "outcome": "recovery_unresolved", "start_fenced": True}, persist_alert, alert_transport)
        raise Rejected("broker-claim-unconfirmed") from None


def _serve_claim(approval, *, endpoint, deadline, fence, persist_alert, transport_alert,
                 clock, boot_id, commands, fault, result_oracle):
    transport = LocalCommands(clock) if commands is None else commands
    with _calling_session(approval, deadline=deadline, clock=clock, boot_id=boot_id, commands=transport) as session:
        if (endpoint.uid, endpoint.gid) != (approval.supervisor.uid, approval.supervisor.gid):
            raise Rejected("broker-same-owner-endpoint-required")
        # Do not contaminate either protected tree with socket state, including
        # a journal whose entry set must stay pinned through each claim phase.
        for root in (approval.installation.content.path, approval.installation.journal.path):
            if os.path.commonpath((root, endpoint.path)) == root:
                raise Rejected("broker-separate-endpoint-required")
        with open_approved_directory(endpoint) as directory:
            manager = _ClaimManager(session, directory, fence)
            process = RecoverySupervisor(session.handles._journal.fd, owner=session.observed["owner"],
                manager=manager, clock=clock, boot_id=boot_id, persist_alert=persist_alert,
                transport_alert=transport_alert, fault=fault, observe_existing=True)
            listener = None
            try:
                if (process.error is not None or process.worker_attempted
                        or canonical(process.pending_request) != canonical(session.inputs.request)):
                    raise Rejected("broker-unclaimed-original-request-required")
                manager.validate(session.deadline)
                path = os.path.join(endpoint.path, "claim-" + approval.job.request_id + ".sock")
                listener = WorkerListener(path, worker_uid=endpoint.uid, clock=clock)
                manager.validate(session.deadline)
                jobs = SystemdRecoveryJobs(systemctl=approval.systemctl, commands=transport,
                    binding=approval.job, clock=clock, boot_id=boot_id)
                claim = listener.accept_once(supervisor=process, observer=_ClaimJobs(jobs, endpoint.uid, endpoint.gid),
                                             deadline=session.deadline, result_oracle=result_oracle)
                process._current(session.deadline)
                if canonical(process._saved_claim(process.pending_request)) != canonical(claim):
                    raise Rejected("broker-saved-claim-changed")
                manager.validate(session.deadline)
                result = {**session.status(), "schema": "host-recovery-broker-status-v1",
                          "operation": "claim", "state": "identity_reply_sent_only",
                          "claim_recorded": True, "claim_reply_sent": True,
                          "peer_acknowledgment_verified": False, "restoration_permission": False,
                          "recovery_completed": False,
                          "worker_result_observed": process.result_observed, "installation_settled": False}
                if result_oracle is not None:
                    result.update(operation="claim_and_result", state="result_observed_unsettled")
            except Exception:
                if process.error is None:
                    process._fail(Rejected("supervisor-worker-claim-unconfirmed"),
                                  "supervisor-worker-claim-unconfirmed")
                raise Rejected("broker-claim-unconfirmed") from None
            finally:
                process.closed = True
                if listener is not None:
                    listener.close()
        session.validate()
        # The last manager/snapshot validation may itself expose a changed saved
        # claim. Check fixed records after all external callbacks, before unlock.
        if (set(os.listdir(process.fd)) != process.initial_entries
                or canonical(process._saved_claim(process.pending_request)) != canonical(claim)):
            raise Rejected("broker-saved-claim-changed")
        process._records_current()
        if canonical(process._pending_request()) != canonical(session.inputs.request):
            raise Rejected("broker-original-request-changed")
        if result_oracle is not None:
            process._saved_result()
        session.timer.remaining()
    return result
