"""Journaled fixed-mask reload on an existing authenticated manager connection.

This embedding phase does not cancel jobs, stop units, prove activation ownership
or drain, or authorize recovery/start. The original operation remains pending.
No service/IPC enables this phase; trusted provisioning and original authority
remain prerequisites. Reopened history is never adopted or retried here.
"""
import os
import re

from .broker_operations import OperationJournal
from .durable import Rejected, canonical, decode, digest
from .manager_bus import ManagerJobSession
from .manager_jobs import MANAGER, MANAGER_PATH, roles_for_method
from .unit_masks import PersistentUnitMasks

PROPERTIES = {key: ("Unit", "s") for key in ("Id", "LoadState", "FragmentPath", "ActiveState", "SubState")}
PROPERTIES.update({"DropInPaths": ("Unit", "as"), "Job": ("Unit", "(uo)"), "InvocationID": ("Unit", "ay"),
                   "MainPID": ("Service", "u"), "ControlGroup": ("Service", "s")})


class ManagerMaskReload:
    """One pending subphase, one Reload, one confirmed typed mask projection.

    The session's internal check must revalidate the original live peer, kernel
    lock, manager/input and inclusive deadline, not assume the forward unit stays
    loaded across Reload. Loaded-unit pins elsewhere deliberately stay strict.
    """
    def __init__(self, *, journal, masks, session):
        if (not isinstance(journal, OperationJournal) or not isinstance(masks, PersistentUnitMasks)
                or not isinstance(session, ManagerJobSession) or session.units != masks.units):
            raise Rejected("mask-reload-original-fixed-boundaries-required")
        self.journal, self.masks, self.session = journal, masks, session
        self._original = (journal, masks, session)
        self._configuration = self.configuration()
        self._operation = None
        self.attempted, self.returned, self.failed = False, False, False

    def configuration(self):
        return canonical({"schema": "host-recovery-mask-reload-target-v1",
            "binding_sha256": digest(self.journal._binding), "epoch_sha256": digest(self.journal._epoch),
            "masks": decode(self.masks.configuration()), "bus_id": self.session.bus_id,
            "manager_owner": self.session.owner, "library_sha256": self.session.library_sha256,
            "deadline": self.session.deadline})

    def _current(self):
        if (self.failed or (self.journal, self.masks, self.session) != self._original
                or self.configuration() != self._configuration or self._operation is None):
            raise Rejected("mask-reload-configuration-changed")
        operation = decode(self._operation)
        self.journal._current()
        self.journal._time(self.session.deadline)
        if (self._operation != self.journal._pending.get(operation["method"])
                or operation["method"] in self.journal._returned
                or self.session.deadline > operation["deadline"]):
            raise Rejected("mask-reload-original-pending-required")
        self.masks.observe(current=self.session._current)
        self.session.identity()
        self.journal._current()
        self.journal._time(self.session.deadline)
        self.masks.observe(current=self.session._current)
        self.journal._time(self.session.deadline)
        if (self.configuration() != self._configuration
                or (self.journal, self.masks, self.session) != self._original):
            raise Rejected("mask-reload-trailing-configuration-changed")

    def _read(self, role):
        self._current()
        session = self.session
        unit = self.masks.units[role]
        path = session._call(session.owner, MANAGER + ".Manager", "GetUnit", "s", (unit.unit,), "o")[0]
        if (type(path) is not str
                or re.fullmatch(MANAGER_PATH + r"/unit/[A-Za-z0-9_]{1,1024}", path) is None):
            raise Rejected("mask-reload-unit-path-unconfirmed")
        row = {}
        for key, (interface, kind) in PROPERTIES.items():
            self._current()
            row[key] = session._call(session.owner, "org.freedesktop.DBus.Properties", "Get", "ss",
                (MANAGER + "." + interface, key), "v:" + kind, path=path)[0]
        if type(row["InvocationID"]) is not bytes or len(row["InvocationID"]) != 16:
            raise Rejected("mask-reload-invocation-type-unconfirmed")
        row["InvocationID"] = "" if row["InvocationID"] == bytes(16) else row["InvocationID"].hex()
        active = (row["ActiveState"], row["SubState"]) == ("active", "running")
        inactive = (row["ActiveState"], row["SubState"]) in (("inactive", "dead"), ("failed", "failed"))
        mask_path = os.path.join(self.masks.directory.approval.path, unit.unit)
        if (row["Id"] != unit.unit or row["LoadState"] != "masked"
                or row["FragmentPath"] not in (mask_path, "/dev/null") or row["DropInPaths"] != []
                or not (active or inactive) or type(row["MainPID"]) is not int
                or row["Job"] != (0, "/") or type(row["Job"][0]) is not int
                or active and (row["InvocationID"] != unit.invocation_id or row["ControlGroup"] != unit.cgroup
                               or not 1 < row["MainPID"] <= 4294967295)
                or inactive and (row["MainPID"] != 0 or row["InvocationID"] not in ("", unit.invocation_id)
                                 or row["ControlGroup"] not in ("", unit.cgroup))):
            raise Rejected("mask-reload-effective-projection-unconfirmed")
        self._current()
        return row

    def _observations(self):
        first = {role: self._read(role) for role in sorted(self.masks.units)}
        final = {role: self._read(role) for role in sorted(self.masks.units)}
        if first != final:
            raise Rejected("mask-reload-effective-projection-changed")
        # A name-only masked projection does not establish old-job retirement.
        rows = self.session.jobs()
        if any(row[1] in {unit.unit for unit in self.masks.units.values()} for row in rows.values()):
            raise Rejected("mask-reload-unretired-fixed-job")
        self._current()
        return final

    def reload(self, *, operation):
        with self._original[0]._mutex:
            if self.attempted:
                raise Rejected("mask-reload-exhausted")
            self.attempted = True
            try:
                if (type(operation) is not dict
                        or set(roles_for_method(operation.get("method"))) != set(self.masks.units)):
                    raise Rejected("mask-reload-original-operation-required")
                self._operation = canonical(operation)
                operation = decode(self._operation)
                self._current()
                rows = self.session.jobs()
                if any(row[1] in {unit.unit for unit in self.masks.units.values()} for row in rows.values()):
                    # Reload may discard accepted jobs. Never infer cancellation
                    # from their subsequent absence or issue a blind CancelJob.
                    raise Rejected("mask-reload-prior-job-requires-cancellation")
                prefix = "operation-%02d-mask-reload-" % operation["sequence"]
                pending = {"schema": "host-recovery-mask-reload-pending-v1",
                    "operation_id": operation["operation_id"], "target_sha256": digest(self._configuration)}
                self.journal._write(prefix + "pending.json", pending)
                self._current()
                self.session._call(self.session.owner, MANAGER + ".Manager", "Reload", "", (), "")
                self._current()
                observations = self._observations()
                returned = {"schema": "host-recovery-mask-reload-return-v1", "pending_sha256": digest(canonical(pending)),
                    "manager_reload_returned": True, "effective_masks_observed": True, "pending_drained": False}
                self.journal._write(prefix + "return.json", returned)
                if observations != self._observations():
                    raise Rejected("mask-reload-return-boundary-changed")
                self._current()
                self.returned = True
                return self._receipt(observations)
            except Exception:
                self.failed = self._original[0]._failed = self._original[2].failed = True
                raise Rejected("mask-reload-unconfirmed") from None

    def observe(self):
        with self._original[0]._mutex:
            try:
                if not self.returned:
                    raise Rejected("mask-reload-return-required")
                return self._receipt(self._observations())
            except Exception:
                self.failed = self._original[0]._failed = self._original[2].failed = True
                raise Rejected("mask-reload-observation-unconfirmed") from None

    def _receipt(self, observations):
        return {"schema": "host-recovery-mask-reload-observation-v1", "target_sha256": digest(self._configuration),
                "manager_reload_returned": True, "effective_masks_observed": True, "mask_count": len(observations),
                "active_unit_count": sum(row["ActiveState"] == "active" for row in observations.values()),
                "activation_exclusion_proven": False, "manager_jobs_retired": False, "pending_drained": False,
                "complete_fence_proven": False, "recovery_execution_allowed": False, "start_allowed": False,
                "settlement_allowed": False, "production_acceptance": False}
