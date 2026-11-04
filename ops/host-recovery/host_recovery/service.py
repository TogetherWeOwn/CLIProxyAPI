"""Persistent same-lock supervisor lifecycle for an original recovery request.

This is an embedding entrypoint, not an installer or a complete host start fence.
The service owner supplies separately provisioned fence/oracle/alert capabilities
and retains command cleanup ownership. No callback is imported from configuration.
A handled request remains latched, even after a positively observed worker result.
"""
import os
import stat
import time

from .bootstrap import kernel_boot_id
from .broker import _serve_session
from .commands import Deadline
from .durable import Rejected, canonical, digest, notify
from .installation import DirectoryApproval, open_installation
from .launch import LaunchApproval, _calling_session
from .worker import cancellation_pending, wait_for_cancellation


def _cancel_descriptor(fd):
    if type(fd) is not int or fd < 0:
        raise Rejected("service-cancellation-descriptor-required")
    mode = os.fstat(fd).st_mode
    if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
        raise Rejected("service-cancellation-descriptor-required")
    cancellation_pending(fd)


def run_supervisor(approval, *, endpoint, deadline, fence, result_oracle, persist_alert,
                   transport_alert, commands, cancel_fd, clock=time.monotonic,
                   boot_id=kernel_boot_id, fault=None):
    """Serve once, then retain the installation lock until explicit shutdown.

    This accepts only an already durable, original-owner request; no dispatch,
    adoption of an older invocation, forward admission, settlement or start grant
    is added. The same lock spans bootstrap, claim/result and passive unresolved
    hold. A failed bootstrap/exchange does not return to an automatic retry loop.

    cancel_fd is a caller-owned read pipe/socket, readable on shutdown (EOF also
    cancels). It must remain open and unreused throughout this call. Cancellation
    wakes accept and connected-peer waits and revokes the server's peer lease.
    Closing that connection revokes the worker, but does NOT prove its descendants
    or daemon objects quiescent. The manager/complete fence must retain ownership
    after shutdown/SIGKILL. This service never clears the durable intent.

    Passive hold is service lifetime, not extra recovery allowance: no recovery,
    validation, polling or persistence retries occur there. One original-deadline
    alarm attempts independent escalation, never recovery or an on-time claim.
    Alert callbacks must be independently bounded, including after expiration;
    this lifecycle cannot prove delivery or measured caps. Hold cannot renew the
    request. No output consumer can block this service.
    commands has an external lifecycle owner, as with run_worker.
    """
    if (not isinstance(approval, LaunchApproval) or not isinstance(endpoint, DirectoryApproval)
            or endpoint.mode != 0o700
            or (endpoint.uid, endpoint.gid) != (os.geteuid(), os.getegid())
            or (approval.supervisor.uid, approval.supervisor.gid) != (os.geteuid(), os.getegid())
            or not all(callable(value) for value in (fence, result_oracle, persist_alert, transport_alert))
            or not callable(getattr(commands, "run", None))):
        raise Rejected("service-explicit-boundaries-required")
    _cancel_descriptor(cancel_fd)
    timer = Deadline(clock, deadline)
    timer.remaining()
    result = {"schema": "host-recovery-service-status-v1", "operation": "supervise_original_request",
              "request_id": approval.job.request_id, "attempt_id": approval.recovery.attempt_id,
              "state": "shutdown_unresolved", "worker_result_observed": False,
              "exchange_error": None, "hold_deadline_missed": False,
              "installation_settled": False, "start_permission": False,
              "recovery_completed": False, "production_acceptance": False}
    attempted = set()

    def alert_transport(notice):
        attempted.add(digest(canonical(notice)))
        return transport_alert(notice)

    def report(code):
        notice = {"schema": "host-recovery-notice-v1", "attempt_id": approval.recovery.attempt_id,
                  "original_cause": "supervisor-restart-recovery-required", "recovery_error": code,
                  "outcome": "recovery_unresolved", "start_fenced": True}
        if digest(canonical(notice)) not in attempted:
            notify(notice, persist_alert, alert_transport)

    def guarded_fence(intent, *, deadline):
        if cancellation_pending(cancel_fd):
            raise Rejected("service-shutdown-requested")
        value = fence(intent, deadline=deadline)
        if cancellation_pending(cancel_fd):
            raise Rejected("service-shutdown-requested")
        return value

    try:
        # Acquire before manager bootstrap. Once acquired, even bootstrap failure
        # remains owned until shutdown; _calling_session borrows, never reflocks.
        with open_installation(approval.installation) as handles:
            if not cancellation_pending(cancel_fd):
                try:
                    with _calling_session(approval, deadline=deadline, clock=clock, boot_id=boot_id,
                                          commands=commands, handles=handles, timer=timer) as session:
                        receipt = _serve_session(session, endpoint=endpoint, fence=guarded_fence,
                            result_oracle=result_oracle, persist_alert=persist_alert, transport_alert=alert_transport,
                            clock=clock, boot_id=boot_id, commands=commands, fault=fault, cancel_fd=cancel_fd)
                    # The session and every borrowed execution callback are now
                    # revoked; only the outer installation lock remains live.
                    result["worker_result_observed"] = receipt["worker_result_observed"] is True
                except Exception:
                    result["exchange_error"] = "supervisor-worker-result-unconfirmed"
                    report(result["exchange_error"])
            # No recovery action or timer renewal after this point. Even expiry,
            # a failed notice or a worker report cannot release the live lock.
            alarm = True
            while True:
                remaining = None
                if alarm:
                    try:
                        remaining = timer.remaining()
                    except Exception:
                        expired = timer.last >= timer.deadline
                        result["hold_deadline_missed"] = True if expired else None
                        report("supervisor-expired-continuation-required" if expired
                               else "supervisor-clock-continuation-required")
                        alarm = False
                if cancellation_pending(cancel_fd):
                    break
                wait_for_cancellation(cancel_fd, remaining)
        return result
    except Exception:
        # Invalid ancestry/failed lock acquisition cannot be called a retained
        # owner. Do not report a normal service shutdown when that contract fails.
        raise Rejected("service-installation-unconfirmed") from None
