"""Runnable conservative supervisor owner; no recovery or start authority.

This composes real protected loading, local alert IPC and signal cancellation with
service.run_supervisor. Until the complete host fence/oracle is implemented, its
fixed boundary refuses every claim. No flag, adjacent file or imported callback
can turn this runner into execution authority. It does not install a service.
"""
from contextlib import contextmanager
import errno
import os
import signal
import time

from .alert import AlertClient, validate_notice
from .commands import Deadline, LocalCommands
from .durable import Rejected, atomic_write, canonical, digest
from .installation import DirectoryApproval, open_approved_directory
from .journal import identity
from .service import run_supervisor
from .worker_runtime import _separate


@contextmanager
def shutdown_pipe(*, reap=None):
    """Own a nonblocking cancellation pipe; restore handlers before closing it.

    A full pipe already signifies shutdown. Repeated signals never block and do
    not drain cancellation. This context must run on the Python main thread.
    """
    read, write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    previous = {}
    try:
        def stop(signum, frame):
            try:
                os.write(write, b"!")
            except OSError as error:
                if error.errno != errno.EAGAIN:
                    raise
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, stop)
        if reap is not None:
            # Popen.poll is nonblocking (including its waitpid lock). Reap only
            # retained owned helpers, never waitpid(-1) or another owner's child.
            previous[signal.SIGCHLD] = signal.signal(signal.SIGCHLD, lambda *args: reap())
        yield read
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        os.close(read)
        os.close(write)


class ServiceAlerts:
    """Once-only local notices, never a receipt for external/human delivery.

    Both private directories and listener instance are independently provisioned.
    The absolute alert deadline is never renewed, including after the original
    recovery target expired. A later escalation window cannot become an on-time
    recovery claim. Failed persistence must not prevent the transport attempt.
    """
    def __init__(self, *, endpoint, receipts, route_id, listener_uid, instance_id, deadline,
                 clock=time.monotonic, fault=None):
        if (not isinstance(endpoint, DirectoryApproval) or not isinstance(receipts, DirectoryApproval)
                or any(root.mode != 0o700 or (root.uid, root.gid) != (os.geteuid(), os.getegid())
                       for root in (endpoint, receipts))
                or type(listener_uid) is not int or listener_uid < 0 or not identity(instance_id)):
            raise Rejected("service-alert-approvals-required")
        _separate([endpoint, receipts])
        self.endpoint, self.receipts = endpoint, receipts
        self.timer = Deadline(clock, deadline)
        self.timer.remaining()
        self.client = AlertClient(os.path.join(endpoint.path, "alert.sock"), route_id,
                                  listener_uid=listener_uid, clock=clock)
        self.instance_id, self.fault = instance_id, fault
        self.challenge_attempted = False
        self.challenge_verified = False
        self.persisted, self.attempted, self.admitted = set(), set(), set()

    def persist(self, notice):
        validate_notice(notice)
        raw = canonical(notice)
        pin = digest(raw)
        name = "notice-" + pin + ".json"
        with open_approved_directory(self.receipts) as directory:
            self.timer.remaining()
            # Never overwrite retained evidence, including visible bytes after a
            # failed directory fsync. A restart requires explicit reconciliation.
            if name in os.listdir(directory.fd) or ".stage-" + name in os.listdir(directory.fd):
                raise Rejected("service-alert-receipt-retained")
            atomic_write(directory.fd, name, raw, stage_name=".stage-" + name, fault=self.fault)
            directory.validate()
            self.timer.remaining()
        self.timer.remaining()
        self.persisted.add(pin)

    def transport(self, notice):
        validate_notice(notice)
        pin = digest(canonical(notice))
        if pin in self.attempted:
            raise Rejected("service-alert-send-once-only")
        self.attempted.add(pin)
        self.timer.remaining()
        with open_approved_directory(self.endpoint) as directory:
            if not self.challenge_attempted:
                self.challenge_attempted = True
                reply = self.client.preflight(deadline=self.timer.deadline)
                if reply["instance_id"] != self.instance_id:
                    raise Rejected("service-alert-instance-mismatch")
                self.challenge_verified = True
            if not self.challenge_verified:
                raise Rejected("service-alert-challenge-unconfirmed")
            directory.validate()
            self.timer.remaining()
            if self.client.deliver(notice, deadline=self.timer.deadline) is not True:
                raise Rejected("service-alert-admission-unconfirmed")
            directory.validate()
            self.timer.remaining()
        self.timer.remaining()
        self.admitted.add(pin)
        return True

    def status(self):
        return {"receipt_count": len(self.persisted), "transport_attempt_count": len(self.attempted),
                "volatile_admission_count": len(self.admitted),
                "listener_instance_verified": self.challenge_verified,
                "external_delivery_verified": False, "human_acknowledged": False}


def run_unresolved(approval, *, endpoint, alerts, deadline, clock=time.monotonic):
    """Run as the pinned manager MainPID, retaining ownership until TERM/INT.

    Actual local manager commands only observe identity; this runner has no
    dispatch/daemon/restore/start method. Missing fence authority refuses before
    a worker claim. The service still retains the installation lock and attempts
    the separately pinned local alert route. No stdout consumer is used here.
    """
    if not isinstance(alerts, ServiceAlerts):
        raise Rejected("service-explicit-alert-owner-required")
    _separate([approval.installation.content, approval.installation.journal, endpoint,
               alerts.endpoint, alerts.receipts])
    commands = LocalCommands(clock)
    original_cancel = alerts.client.cancel_fd
    try:
        with shutdown_pipe(reap=commands.reap) as cancel_fd:
            commands.cancel_fd = alerts.client.cancel_fd = cancel_fd
            try:
                result = run_supervisor(approval, endpoint=endpoint, deadline=deadline,
                    fence=lambda intent, **kwargs: False, result_oracle=lambda *args, **kwargs: False,
                    persist_alert=alerts.persist, transport_alert=alerts.transport, commands=commands,
                    cancel_fd=cancel_fd, clock=clock)
            finally:
                # Never leave a borrowed descriptor number attached after close.
                commands.cancel_fd = None
                alerts.client.cancel_fd = original_cancel
        return {**result, "operation": "hold_without_execution_authority", "alerts": alerts.status()}
    finally:
        # SIGCHLD also reaps during passive hold. Never add a wait outside the
        # reserve or infer cgroup/daemon quiescence from helper cleanup.
        commands.reap()
