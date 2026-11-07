"""Journaled exact waiting-start cancellation before fixed-mask reload.

Embedding only, never enabled by IPC or a service runner. Masks do not stop a
queued job; Cancel return does not prove cancellation. This phase requires the
matching authenticated JobRemoved(canceled) on the original connection. It does
not prove retirement of all jobs, activation exclusion, quiescence or drain.
"""
from .broker_operations import OperationJournal, shape
from .durable import Rejected, canonical, decode, digest
from .loading import pin
from .manager import INVOCATION
from .manager_bus import ManagerJobSession
from .manager_jobs import STOP_ROLES, UNIQUE, jobs_reply, roles_for_method
from .unit_masks import PersistentUnitMasks


def record_names(sequence, role):
    prefix = "operation-%02d-cancel-%02d-" % (sequence, STOP_ROLES.index(role) + 1)
    return tuple(prefix + kind + ".json" for kind in ("pending", "return", "completion"))


def classify_records(pending_raw, returned_raw, completion_raw, *, operation, role):
    """Strict historical correspondence only; never revive a cancellation grant."""
    pending = decode(pending_raw)
    shape(pending, ("schema", "operation_id", "role", "target_sha256", "bus_id", "manager_owner", "job"))
    if (pending_raw != canonical(pending) or pending["schema"] != "host-recovery-job-cancel-pending-v1"
            or role not in roles_for_method(operation["method"]) or pending["role"] != role
            or pending["operation_id"] != operation["operation_id"]
            or type(pending["bus_id"]) is not str or INVOCATION.fullmatch(pending["bus_id"]) is None
            or type(pending["manager_owner"]) is not str or UNIQUE.fullmatch(pending["manager_owner"]) is None):
        raise Rejected("job-cancel-history-pending-unbound")
    pin(pending["target_sha256"])
    rows = jobs_reply(canonical({"type": "a(usssoo)", "data": [[pending["job"]]]}))
    job = next(iter(rows.values()))
    if job[2:4] != ("start", "waiting"):
        raise Rejected("job-cancel-history-waiting-start-required")
    returned = completion = None
    if returned_raw is not None:
        returned = decode(returned_raw)
        shape(returned, ("schema", "pending_sha256", "cancellation_returned", "pending_drained"))
        if (returned_raw != canonical(returned) or returned["schema"] != "host-recovery-job-cancel-return-v1"
                or returned["pending_sha256"] != digest(pending_raw)
                or returned["cancellation_returned"] is not True or returned["pending_drained"] is not False):
            raise Rejected("job-cancel-history-return-unbound")
    if completion_raw is not None:
        completion = decode(completion_raw)
        shape(completion, ("schema", "return_sha256", "job_id", "job_path", "unit", "result", "sender_cookie",
                           "retirement_proven"))
        if (completion_raw != canonical(completion) or returned is None
                or completion["schema"] != "host-recovery-job-cancel-completion-v1"
                or completion["return_sha256"] != digest(returned_raw)
                or type(completion["job_id"]) is not int or completion["job_id"] != job[0]
                or completion["job_path"] != job[4] or completion["unit"] != job[1]
                or completion["result"] != "canceled" or type(completion["sender_cookie"]) is not int
                or not 0 < completion["sender_cookie"] < 2**64 or completion["retirement_proven"] is not False):
            raise Rejected("job-cancel-history-completion-unbound")
    return pending, returned, completion


class WaitingStartCancellation:
    """One bounded snapshot and one Cancel per exact fixed-role waiting start.

    The session's internal barrier retains original peer/lock/manager/input and
    inclusive deadline authority. The caller owns trusted provisioning and the
    original operation; no new lock, numeric-ID API, retry or adoption exists.
    """
    def __init__(self, *, journal, masks, session):
        if (not isinstance(journal, OperationJournal) or not isinstance(masks, PersistentUnitMasks)
                or not isinstance(session, ManagerJobSession) or masks.units != session.units):
            raise Rejected("job-cancel-original-fixed-boundaries-required")
        self.journal, self.masks, self.session = journal, masks, session
        self._original = (journal, masks, session)
        self._configuration = self.configuration()
        self._operation, self._targets = None, None
        self.attempted, self.completed, self.failed = False, False, False

    def configuration(self):
        return canonical({"schema": "host-recovery-job-cancel-target-v1",
            "binding_sha256": digest(self.journal._binding), "epoch_sha256": digest(self.journal._epoch),
            "masks": decode(self.masks.configuration()), "bus_id": self.session.bus_id,
            "manager_owner": self.session.owner, "library_sha256": self.session.library_sha256,
            "deadline": self.session.deadline})

    def _current(self):
        if (self.failed or (self.journal, self.masks, self.session) != self._original
                or self.configuration() != self._configuration or self._operation is None):
            raise Rejected("job-cancel-configuration-changed")
        operation = decode(self._operation)
        self.journal._current()
        self.journal._time(self.session.deadline)
        if (self._operation != self.journal._pending.get(operation["method"])
                or operation["method"] in self.journal._returned or self.session.deadline > operation["deadline"]):
            raise Rejected("job-cancel-original-pending-required")
        self.masks.observe(current=self.session._current)
        self.session.identity()
        self.journal._current()
        self.journal._time(self.session.deadline)
        self.masks.observe(current=self.session._current)
        self.journal._time(self.session.deadline)
        if (self.configuration() != self._configuration or (self.journal, self.masks, self.session) != self._original
                or self._targets is not None and self._targets != canonical(self.session._cancel_targets)):
            raise Rejected("job-cancel-trailing-configuration-changed")

    def _absent(self):
        rows = self.session.jobs()
        names = {unit.unit for unit in self.masks.units.values()}
        if any(row[1] in names for row in rows.values()):
            raise Rejected("job-cancel-fixed-job-remains")
        self._current()

    def cancel(self, *, operation):
        with self._original[0]._mutex:
            if self.attempted:
                raise Rejected("job-cancel-exhausted")
            self.attempted = True
            try:
                if (type(operation) is not dict
                        or set(roles_for_method(operation.get("method"))) != set(self.masks.units)):
                    raise Rejected("job-cancel-original-operation-required")
                self._operation = canonical(operation)
                operation = decode(self._operation)
                self._current()
                targets = self.session._watch_waiting_starts()
                self._targets = canonical(targets)
                self._current()
                for role in sorted(targets):
                    job = targets[role]
                    pending_name, returned_name, completion_name = record_names(operation["sequence"], role)
                    pending = {"schema": "host-recovery-job-cancel-pending-v1", "operation_id": operation["operation_id"],
                        "role": role, "target_sha256": digest(self._configuration), "bus_id": self.session.bus_id,
                        "manager_owner": self.session.owner, "job": list(job)}
                    self.journal._write(pending_name, pending)
                    self._current()
                    self.session._cancel_waiting_start(role, check=self._current)
                    self._current()
                    returned = {"schema": "host-recovery-job-cancel-return-v1",
                        "pending_sha256": digest(canonical(pending)), "cancellation_returned": True, "pending_drained": False}
                    self.journal._write(returned_name, returned)
                    self._current()
                    event = self.session._cancellation(role)
                    while event is None:
                        self._current()
                        remaining = self.session.deadline - self.session.clock()
                        if remaining <= 0:
                            raise Rejected("job-cancel-completion-deadline")
                        self.session._connection.wait(max(1, min(50000, int(remaining * 1000000))))
                        self._current()
                        event = self.session._cancellation(role)
                    if event["result"] != "canceled" or job[0] in self.session.jobs():
                        raise Rejected("job-cancel-matching-canceled-completion-required")
                    value = {"schema": "host-recovery-job-cancel-completion-v1",
                        "return_sha256": digest(canonical(returned)), **event, "retirement_proven": False}
                    classify_records(canonical(pending), canonical(returned), canonical(value), operation=operation, role=role)
                    self.journal._write(completion_name, value)
                    self._current()
                    if self.session._cancellation(role) != event:
                        raise Rejected("job-cancel-trailing-completion-changed")
                self._absent()
                self.completed = True
                return self._receipt(len(targets))
            except Exception:
                self.failed = self._original[0]._failed = self._original[2].failed = True
                raise Rejected("job-cancel-unconfirmed") from None

    def _receipt(self, count):
        return {"schema": "host-recovery-job-cancel-observation-v1", "target_sha256": digest(self._configuration),
            "canceled_waiting_start_count": count, "activation_exclusion_proven": False, "manager_jobs_retired": False,
            "pending_drained": False, "complete_fence_proven": False, "recovery_execution_allowed": False,
            "start_allowed": False, "settlement_allowed": False, "production_acceptance": False}
