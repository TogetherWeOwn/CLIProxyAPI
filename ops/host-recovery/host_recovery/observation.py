"""Lock-retaining calling-manager observation; no execution/fence authority.

This follows an already-dispatched request, never starts or redispatches a job.
It composes actual read-only manager adapters, without substituting a fake True
for the missing complete host fence. Inputs remain bound to the original request
and same supervisor invocation. A read-only observation cannot reconcile an older
supervisor invocation, continue across boots/expiry, settle an outcome or clear the
latch. Restart/claim/execution and operational alert wiring remain separate work.
"""
import copy
import time

from .bootstrap import kernel_boot_id
from .budget import positive
from .commands import LocalCommands
from .durable import Rejected, canonical
from .jobs import SystemdRecoveryJobs, validate_observation
from .launch import _calling_session


def observe_request(approval, *, deadline, interval, max_observations, stop, wait,
                    clock=time.monotonic, boot_id=kernel_boot_id, commands=None):
    """Hold the existing installation lock across bounded read-only observations.

    stop/wait are interruptible local lifecycle callbacks, not authorization. No
    output is emitted while the lock is held. A returned receipt is unresolved,
    even for an inactive worker. Filesystem/manager/clock uncertainty raises before
    publication, and context-exit ancestry validation must also succeed. No disk
    write, intent clearing or alert-delivery claim is made by this operation.
    """
    if (not positive(interval) or type(max_observations) is not int or not 1 <= max_observations <= 4096
            or not callable(stop) or not callable(wait)):
        raise Rejected("observation-bounds-required")
    transport = LocalCommands(clock) if commands is None else commands
    with _calling_session(approval, deadline=deadline, clock=clock, boot_id=boot_id, commands=transport) as session:
        jobs = SystemdRecoveryJobs(systemctl=approval.systemctl, commands=transport,
            binding=approval.job, clock=clock, boot_id=boot_id)
        owner = session.observed["owner"]
        invocation, job, count = None, None, 0
        session.timer.remaining()
        start = session.timer.last
        while True:
            session.validate()
            stopping = stop()
            if type(stopping) is not bool:
                raise Rejected("observation-stop-schema")
            if stopping:
                reason = "stop_requested"
                break
            before = jobs.observe(approval.job.request_id, deadline=session.deadline)
            validate_observation(before, approval.job.request_id, owner["boot_id"])
            if before["invocation_id"] == owner["invocation_id"]:
                raise Rejected("observation-separate-worker-required")
            session.validate()
            after = jobs.observe(approval.job.request_id, deadline=session.deadline)
            validate_observation(after, approval.job.request_id, owner["boot_id"])
            if canonical(before) != canonical(after):
                raise Rejected("observation-job-changed-during-query")
            session.validate()
            if invocation is not None and before["invocation_id"] != invocation:
                raise Rejected("observation-worker-invocation-lost")
            if before["invocation_id"]:
                invocation = before["invocation_id"]
            job, count = copy.deepcopy(before), count + 1
            if job["state"] == "inactive_unverified":
                reason = "worker_inactive_unverified"
                break
            if count >= max_observations:
                reason = "observation_limit"
                break
            # Same timer through all ticks, manager calls and filesystem reads.
            # A callback cannot renew the original deadline or spin early polls.
            delay = min(interval, session.timer.remaining())
            waited_at = session.timer.last
            interrupted = wait(delay)
            if type(interrupted) is not bool:
                raise Rejected("observation-wait-schema")
            session.timer.remaining()
            if interrupted:
                reason = "stop_requested"
                break
            if session.timer.last <= waited_at or session.timer.last < waited_at + delay:
                raise Rejected("observation-wait-incomplete")
        session.validate()
        result = {**session.status(), "schema": "host-recovery-observation-v1", "operation": "observe",
                  "state": "observation_ended_unresolved", "reason": reason, "job": job,
                  "observations": count, "deadline": session.deadline,
                  "started_monotonic": start, "last_monotonic": session.timer.last,
                  "sampled_elapsed_seconds": session.timer.last - start,
                  "recovery_completed": False, "alert_delivery_verified": False}
    return result
