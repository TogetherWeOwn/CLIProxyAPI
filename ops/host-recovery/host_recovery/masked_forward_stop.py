"""Original-operation forward mask/cancel/reload/stop/KILL composition.

Embedding only: no IPC or runner enables it. A stopped masked projection and an
exact stop completion are not actual-exec exclusion, cgroup quiescence, complete
activation ownership, cold-runtime reconciliation, drain or recovery authority.
"""
from .broker_operations import OperationJournal
from .durable import Rejected, canonical, decode, digest
from .job_cancellation import WaitingStartCancellation
from .manager_jobs import ForwardStopJobs
from .mask_reload import ManagerMaskReload
from .unit_masks import PersistentUnitMasks


class MaskedForwardStop:
    """One fixed sequence under the existing journal mutex, never a second lock.

    Trusted provisioning supplies the original session's peer/flock/manager/input
    barrier. It must remain valid across the loaded-to-masked transition; a stale
    loaded-unit check refuses rather than being weakened or replaced here.
    """
    def __init__(self, *, journal, masks, jobs):
        if (not isinstance(journal, OperationJournal) or not isinstance(masks, PersistentUnitMasks)
                or not isinstance(jobs, ForwardStopJobs) or jobs.journal is not journal
                or masks.units != jobs.units or masks.attempted or jobs._attempted):
            raise Rejected("masked-forward-original-unused-boundaries-required")
        self.journal, self.masks, self.jobs = journal, masks, jobs
        self.session = jobs.session
        self.cancellation = WaitingStartCancellation(journal=journal, masks=masks, session=self.session)
        self.reload = ManagerMaskReload(journal=journal, masks=masks, session=self.session)
        self._original = (journal, masks, jobs, self.session, self.cancellation, self.reload)
        self._configuration = self.configuration()
        self._operation = None
        self.attempted, self.completed, self.failed, self._published = False, False, False, False

    def configuration(self):
        return canonical({"schema": "host-recovery-masked-forward-stop-target-v1",
            "binding_sha256": digest(self.journal._binding), "epoch_sha256": digest(self.journal._epoch),
            "masks": decode(self.masks.configuration()), "jobs": decode(self.jobs.configuration()),
            "cancellation": decode(self.cancellation.configuration()), "reload": decode(self.reload.configuration()),
            "kill_whom": "all", "kill_signal": 9})

    @property
    def target_sha256(self):
        return digest(self._configuration)

    def _current(self):
        if (self.failed or self._configuration != self.configuration() or self._operation is None
                or (self.journal, self.masks, self.jobs, self.session, self.cancellation, self.reload) != self._original
                or self.jobs.session is not self.session or self.jobs.failed):
            raise Rejected("masked-forward-configuration-changed")
        operation = decode(self._operation)
        self.journal._current()
        self.journal._time(self.session.deadline)
        if (self._operation != self.journal._pending.get("contain_forward")
                or "contain_forward" in self.journal._returned
                or operation["deadline"] != self.session.deadline or operation["target_sha256"] != self.target_sha256):
            raise Rejected("masked-forward-original-pending-required")
        self.session.identity()
        if self._published:
            self.masks.observe(current=self.session._current)
        self.journal._current()
        self.journal._time(self.session.deadline)
        if (self._configuration != self.configuration()
                or (self.journal, self.masks, self.jobs, self.session, self.cancellation, self.reload) != self._original):
            raise Rejected("masked-forward-trailing-configuration-changed")

    def _completions(self):
        self._current()
        result = self.jobs.observe(deadline=self.session.deadline, check=self._current)
        if set(result) != {"forward"} or result["forward"] not in ("pending_observed", "absent_not_retired",
                                                                 "completion_done_observed"):
            raise Rejected("masked-forward-matching-stop-completion-required")
        self._current()
        return result["forward"] == "completion_done_observed"

    def stop(self, *, operation):
        with self._original[0]._mutex:
            if self.attempted:
                raise Rejected("masked-forward-exhausted")
            self.attempted = True
            try:
                if (type(operation) is not dict or operation.get("method") != "contain_forward"
                        or self.masks.attempted or self.jobs._attempted):
                    raise Rejected("masked-forward-original-operation-required")
                self._operation = canonical(operation)
                operation = decode(self._operation)
                self._current()
                self.masks.publish(current=self._current)
                self._published = True
                self._current()
                canceled = self.cancellation.cancel(operation=operation)
                self._current()
                self.reload.reload(operation=operation)
                self._current()
                # Even an inactive projection requires its own exact stop reply
                # and completion. Cancellation evidence cannot supply either.
                self.jobs.submit("forward", operation=operation, deadline=self.session.deadline, check=self._current)
                done = self._completions()
                killed = False
                if not done:
                    self.session._kill_stopping_unit("forward", check=self._current)
                    killed = True
                while not self._completions():
                    self._current()
                    remaining = self.session.deadline - self.session.clock()
                    if remaining <= 0:
                        raise Rejected("masked-forward-completion-deadline")
                    self.session._connection.wait(max(1, min(50000, int(remaining * 1000000))))
                    self._current()
                receipt = self.reload.observe()
                if receipt["active_unit_count"] != 0:
                    raise Rejected("masked-forward-stopped-projection-required")
                # Reobserve AFTER durable stop completion and after each final
                # external boundary. Do not publish an outer return/settlement.
                self._current()
                if not self._completions() or receipt != self.reload.observe():
                    raise Rejected("masked-forward-final-observation-changed")
                self._current()
                self.completed = True
                return {"schema": "host-recovery-masked-forward-stop-observation-v1",
                    "target_sha256": self.target_sha256, "operation_id": operation["operation_id"],
                    "canceled_waiting_start_count": canceled["canceled_waiting_start_count"],
                    "whole_unit_kill_returned": killed, "fixed_stop_completion_observed": True,
                    "masked_inactive_observed": True, "manager_jobs_retired": False,
                    "activation_exclusion_proven": False, "cgroup_quiescence_proven": False,
                    "pending_drained": False, "complete_fence_proven": False,
                    "recovery_execution_allowed": False, "start_allowed": False,
                    "settlement_allowed": False, "production_acceptance": False}
            except Exception:
                self.failed = self._original[0]._failed = self._original[3].failed = True
                raise Rejected("masked-forward-stop-unconfirmed") from None
