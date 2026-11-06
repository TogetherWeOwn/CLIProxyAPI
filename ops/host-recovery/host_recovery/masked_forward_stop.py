"""Original-operation forward mask/cancel/reload/stop/KILL composition.

Explicit embedding/containment IPC only; no operational runner enables it.
A stopped masked projection and an
exact stop completion are not actual-exec exclusion, cgroup quiescence, complete
activation ownership, cold-runtime reconciliation, drain or recovery authority.
"""
import re

from .broker_authority import SupervisorPeerAuthority
from .broker_operations import OperationJournal
from .durable import Rejected, canonical, decode, digest
from .job_cancellation import WaitingStartCancellation
from .manager_jobs import MANAGER, MANAGER_PATH, ForwardStopJobs
from .mask_reload import ManagerMaskReload
from .unit_masks import PersistentUnitMasks


class _MaskedFixedStop:
    """One fixed sequence under the existing journal mutex, never a second lock.

    Trusted provisioning supplies the original session's peer/flock/manager/input
    barrier. It must remain valid across the loaded-to-masked transition; a stale
    loaded-unit check refuses rather than being weakened or replaced here.
    """
    method = None
    jobs_type = None
    roles = ()
    target_schema = None
    observation_schema = None

    def __init__(self, *, journal, masks, jobs, authority=None):
        if authority is not None and (not isinstance(authority, SupervisorPeerAuthority)
                or not isinstance(journal, OperationJournal) or authority._binding != journal._binding):
            raise Rejected("masked-stop-original-peer-authority-required")
        self.authority = self._original_authority = authority
        self._returned_raw = None
        self._resources_closed = False
        if (not isinstance(journal, OperationJournal) or not isinstance(masks, PersistentUnitMasks)
                or not isinstance(jobs, self.jobs_type) or jobs.journal is not journal
                or masks.units != jobs.units or masks.attempted or jobs._attempted):
            raise Rejected("masked-forward-original-unused-boundaries-required")
        self.journal, self.masks, self.jobs = journal, masks, jobs
        self.session = jobs.session
        if authority is not None and self.session.authority is not authority:
            raise Rejected("masked-stop-manager-original-peer-required")
        self.cancellation = WaitingStartCancellation(journal=journal, masks=masks, session=self.session)
        self.reload = ManagerMaskReload(journal=journal, masks=masks, session=self.session)
        self._original = (journal, masks, jobs, self.session, self.cancellation, self.reload)
        self._mode = (self.method, self.roles, self.jobs_type, self.target_schema, self.observation_schema)
        self._configuration = self.configuration()
        self._operation = None
        self._execution_starts = None
        self.attempted, self.completed, self.failed, self._published = False, False, False, False

    def configuration(self):
        return canonical({"schema": self.target_schema,
            "binding_sha256": digest(self.journal._binding), "epoch_sha256": digest(self.journal._epoch),
            "masks": decode(self.masks.configuration()), "jobs": decode(self.jobs.configuration()),
            "cancellation": decode(self.cancellation.configuration()), "reload": decode(self.reload.configuration()),
            "kill_whom": "all", "kill_signal": 9, "fixed_job_admission_witness": "job-new-v1",
            "fixed_unit_reference": "sender-ref-unit-v1", "post_reload_transition_witness": "reloading-v1"})

    @property
    def target_sha256(self):
        return digest(self._configuration)

    def _current(self):
        if (self._mode != (self.method, self.roles, self.jobs_type, self.target_schema, self.observation_schema)
                or self.failed or self._configuration != self.configuration() or self._operation is None
                or (self.journal, self.masks, self.jobs, self.session, self.cancellation, self.reload) != self._original
                or self.jobs.session is not self.session or self.jobs.failed
                or self.authority is not self._original_authority):
            raise Rejected("masked-forward-configuration-changed")
        if self.authority is not None:
            self.authority.observe(deadline=self.session.deadline)
        operation = decode(self._operation)
        self.journal._current()
        self.journal._time(self.session.deadline)
        returned = self.method in self.journal._returned
        expected_return = canonical({"schema": "host-recovery-broker-return-v1",
            "operation_id": operation["operation_id"], "result": "returned", "pending_drained": False})
        saved_return = self.journal._records.get("operation-%02d-return.json" % operation["sequence"])
        if (self._operation != self.journal._pending.get(self.method)
                or returned and (not self.completed or self._returned_raw != expected_return
                                 or saved_return is None or saved_return[0] != expected_return)
                or not returned and self._returned_raw is not None
                or operation["deadline"] != self.session.deadline or operation["target_sha256"] != self.target_sha256):
            raise Rejected("masked-forward-original-pending-required")
        self.session.identity()
        if self._published:
            self.masks.observe(current=self.session._current)
        self.journal._current()
        self.journal._time(self.session.deadline)
        if self.authority is not None:
            self.authority.observe(deadline=self.session.deadline)
        self.journal._time(self.session.deadline)
        if (self._configuration != self.configuration() or self.authority is not self._original_authority
                or (self.journal, self.masks, self.jobs, self.session, self.cancellation, self.reload) != self._original):
            raise Rejected("masked-forward-trailing-configuration-changed")

    def record_return(self):
        """Persist the completed submission, not drain or installation settlement.

        The connected broker calls this before replying. Recheck the live fixed
        manager/process observations after return durability; a lost peer or disk
        fault leaves the original operation consumed, never replayable.
        """
        with self.journal._mutex:
            try:
                if not self.completed or self._returned_raw is not None:
                    raise Rejected("masked-stop-completed-unreturned-operation-required")
                self.revalidate_completed()
                value = self.journal.returned(decode(self._operation), result="returned")
                self._returned_raw = canonical(value)
                self.revalidate_completed()
                return decode(self._returned_raw)
            except Exception:
                self.failed = self.journal._failed = self.session.failed = True
                raise Rejected("masked-stop-return-unconfirmed") from None

    def revalidate_completed(self):
        """Read-only post-submission checks, including after the outer fsync/ACK."""
        if not self.completed or self._resources_closed:
            raise Rejected("masked-stop-live-completed-sequence-required")
        self._execution_current()
        self.session._fixed_jobs_absent()
        for role in self.roles:
            path = self.session._fixed_unit_paths[role]
            row = {}
            for key, interface, kind in (("Id", "Unit", "s"), ("LoadState", "Unit", "s"),
                    ("ActiveState", "Unit", "s"), ("SubState", "Unit", "s"),
                    ("MainPID", "Service", "u"), ("Job", "Unit", "(uo)")):
                self._current()
                row[key] = self.session._call(self.session.owner, "org.freedesktop.DBus.Properties", "Get", "ss",
                    (MANAGER + "." + interface, key), "v:" + kind, path=path)[0]
                self._current()
            if (row["Id"] != self.jobs.units[role].unit or row["LoadState"] != "masked"
                    or (row["ActiveState"], row["SubState"]) not in (("inactive", "dead"), ("failed", "failed"))
                    or type(row["MainPID"]) is not int or row["MainPID"] != 0
                    or row["Job"] != (0, "/") or type(row["Job"][0]) is not int):
                raise Rejected("masked-stop-trailing-inactive-projection-unconfirmed")
        self._final_check()
        self._execution_current()

    def _execution_snapshot(self):
        starts = {}
        for role in self.roles:
            self._current()
            unit = self.jobs.units[role].unit
            path = self.session._call(self.session.owner, MANAGER + ".Manager", "GetUnit", "s", (unit,), "o")[0]
            if (type(path) is not str
                    or set(self.session._fixed_unit_paths) != set(self.roles)
                    or path != self.session._fixed_unit_paths[role]
                    or re.fullmatch(MANAGER_PATH + r"/unit/[A-Za-z0-9_]{1,1024}", path) is None):
                raise Rejected("masked-fixed-execution-unit-path-unconfirmed")
            self.session._fixed_unit_reference(role, path)
            self._current()
            identity = self.session._call(self.session.owner, "org.freedesktop.DBus.Properties", "Get", "ss",
                (MANAGER + ".Unit", "Id"), "v:s", path=path)[0]
            self._current()
            stamp = self.session._call(self.session.owner, "org.freedesktop.DBus.Properties", "Get", "ss",
                (MANAGER + ".Service", "ExecMainStartTimestampMonotonic"), "v:t", path=path)[0]
            if identity != unit or type(stamp) is not int or not 0 <= stamp < 2**64 - 1:
                raise Rejected("masked-fixed-execution-timestamp-unconfirmed")
            starts[role] = stamp
            self._current()
        return canonical(starts)

    def _execution_current(self):
        # Volatile point samples only. Equal timestamps cannot prove continuous
        # execution exclusion or reconstruct a witness after process/manager loss.
        if self._execution_starts is None or self._execution_snapshot() != self._execution_starts:
            raise Rejected("masked-fixed-execution-timestamp-changed")
        self._current()

    def _completions(self):
        self._execution_current()
        self._current()
        result = self.jobs.observe(deadline=self.session.deadline, check=self._current)
        if (set(result) != set(self.jobs._submitted)
                or any(value not in ("pending_observed", "absent_not_retired", "completion_done_observed")
                       for value in result.values())):
            raise Rejected("masked-forward-matching-stop-completion-required")
        self._current()
        return result

    def _before_stops(self):
        pass

    def _release(self):
        pass

    def _after_stops(self):
        return {}

    def _final_check(self):
        self._current()

    def stop(self, *, operation):
        with self._original[0]._mutex:
            if self.attempted:
                raise Rejected("masked-forward-exhausted")
            self.attempted = True
            try:
                if (type(operation) is not dict or operation.get("method") != self.method
                        or self.masks.attempted or self.jobs._attempted):
                    raise Rejected("masked-forward-original-operation-required")
                self._operation = canonical(operation)
                operation = decode(self._operation)
                self._current()
                self.session._retain_fixed_units()
                self._current()
                self.session._watch_fixed_jobs()
                self._current()
                self._execution_starts = self._execution_snapshot()
                self._execution_current()
                self._before_stops()
                self._execution_current()
                self._current()
                self.masks.publish(current=self._current)
                self._published = True
                self._current()
                canceled = self.cancellation.cancel(operation=operation)
                self._execution_current()
                self.reload.reload(operation=operation)
                self.session._watch_referenced_units()
                self._execution_current()
                # Even an inactive projection requires its own exact stop reply
                # and completion. Cancellation evidence cannot supply either.
                killed = 0
                for role in self.roles:
                    self._execution_current()
                    self.jobs.submit(role, operation=operation, deadline=self.session.deadline, check=self._current)
                    if self._completions()[role] != "completion_done_observed":
                        self.session._kill_stopping_unit(role, check=self._current)
                        killed += 1
                    while self._completions()[role] != "completion_done_observed":
                        self._current()
                        remaining = self.session.deadline - self.session.clock()
                        if remaining <= 0:
                            raise Rejected("masked-forward-completion-deadline")
                        self.session._connection.wait(max(1, min(50000, int(remaining * 1000000))))
                        self._current()
                self._execution_current()
                extra = self._after_stops()
                self._execution_current()
                receipt = self.reload.observe()
                if receipt["active_unit_count"] != 0:
                    raise Rejected("masked-forward-stopped-projection-required")
                # Reobserve AFTER durable stop completion and after each final
                # external boundary. Do not publish an outer return/settlement.
                self._current()
                final = self._completions()
                if (set(final) != set(self.roles) or any(value != "completion_done_observed" for value in final.values())
                        or receipt != self.reload.observe()):
                    raise Rejected("masked-forward-final-observation-changed")
                self._final_check()
                job_observation = self.session._fixed_jobs_absent()
                self._execution_current()
                self.completed = True
                return {"schema": self.observation_schema, **extra, **job_observation,
                    "target_sha256": self.target_sha256, "operation_id": operation["operation_id"],
                    "canceled_waiting_start_count": canceled["canceled_waiting_start_count"],
                    "whole_unit_kill_returned": bool(killed), "fixed_stop_completion_observed": True,
                    "masked_inactive_observed": True, "manager_jobs_retired": False,
                    "fixed_execution_timestamp_count": len(self.roles), "fixed_execution_timestamps_unchanged": True,
                    "fixed_unit_reference_count": len(self.session._fixed_unit_paths),
                    "activation_exclusion_proven": False, "cgroup_quiescence_proven": False,
                    "pending_drained": False, "complete_fence_proven": False,
                    "recovery_execution_allowed": False, "start_allowed": False,
                    "settlement_allowed": False, "production_acceptance": False}
            except Exception:
                self.failed = self._original[0]._failed = self._original[3].failed = True
                raise Rejected("masked-forward-stop-unconfirmed") from None
            finally:
                # A connected containment server retains process witnesses through
                # return fsync and ACK revalidation, then always closes them.
                if self.authority is None or not self.completed:
                    self.close()

    def close(self):
        if self._resources_closed:
            return
        self._resources_closed = True
        try:
            self._release()
        except Exception:
            self.failed = self._original[0]._failed = self._original[3].failed = True
            self.completed = False
            raise Rejected("masked-forward-resource-release-unconfirmed") from None


class MaskedForwardStop(_MaskedFixedStop):
    method = "contain_forward"
    jobs_type = ForwardStopJobs
    roles = ("forward",)
    target_schema = "host-recovery-masked-forward-stop-target-v1"
    observation_schema = "host-recovery-masked-forward-stop-observation-v1"
