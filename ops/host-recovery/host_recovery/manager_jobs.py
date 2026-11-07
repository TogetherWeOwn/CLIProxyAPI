"""Fixed forward/runtime StopUnit submissions with durable manager job identities.

This is an embedding boundary, not an installed broker or complete fence.
Legacy busctl calls are NOT connection-atomic. An optional ManagerJobSession
supplies same-connection completion observations and separate durable records;
ListJobs absence never substitutes for a signal. Neither mode proves exclusive
activation ownership, job retirement or pending drain.
"""
from dataclasses import asdict
import os
import re

from .broker_operations import OperationJournal, shape
from .durable import Rejected, canonical, decode, digest
from .loading import pin
from .manager import INVOCATION, UNIT, UnitBinding
from .topology import RUNTIME_ROLES

MANAGER = "org.freedesktop.systemd1"
MANAGER_PATH = "/org/freedesktop/systemd1"
JOB_PREFIX = MANAGER_PATH + "/job/"
UNIQUE = re.compile(r":[0-9]{1,10}\.[0-9]{1,10}\Z")
MAX_JOBS = 256
STOP_ROLES = RUNTIME_ROLES + ("forward",)


def roles_for_method(method):
    if method == "cold_quiesce_runtime":
        return RUNTIME_ROLES
    if method == "contain_forward":
        return ("forward",)
    return ()


def fixed_roles(units):
    return type(units) is dict and set(units) in (set(RUNTIME_ROLES), {"forward"})

JOB_PENDING_FIELDS = ("schema", "operation_id", "role", "target_sha256", "manager_owner",
                      "bus_id", "unit", "invocation_id")
JOB_RETURN_FIELDS = ("schema", "pending_sha256", "job_id", "job_path", "retirement_proven")
COMPLETION_FIELDS = ("schema", "return_sha256", "bus_id", "manager_owner", "job_id", "job_path",
                     "unit", "result", "sender_cookie", "retirement_proven")


def completion_name(sequence, role):
    return record_names(sequence, role)[0].replace("pending.json", "completion.json")


def classify_completion(raw, *, pending, returned):
    from .manager_bus import RESULTS
    value = decode(raw)
    shape(value, COMPLETION_FIELDS)
    if (raw != canonical(value) or value["schema"] != "host-recovery-manager-completion-v1"
            or returned is None or value["return_sha256"] != digest(canonical(returned))
            or value["bus_id"] != pending["bus_id"] or value["manager_owner"] != pending["manager_owner"]
            or value["job_id"] != returned["job_id"] or type(value["job_id"]) is not int
            or value["job_path"] != returned["job_path"] or value["unit"] != pending["unit"]
            or type(value["result"]) is not str or value["result"] not in RESULTS
            or type(value["sender_cookie"]) is not int or not 0 < value["sender_cookie"] < 2**64
            or value["retirement_proven"] is not False):
        raise Rejected("manager-job-completion-unbound")
    return value


def reply(raw, signature):
    if type(raw) is not bytes or len(raw) > 65536:
        raise Rejected("manager-job-reply-limit")
    value = decode(raw)
    shape(value, ("type", "data"))
    if value["type"] != signature or type(value["data"]) is not list or len(value["data"]) != 1:
        raise Rejected("manager-job-reply-schema")
    return value["data"][0]


def job_path(value):
    if type(value) is not str or not re.fullmatch(JOB_PREFIX + r"[1-9][0-9]{0,9}", value):
        raise Rejected("manager-job-path-required")
    number = int(value[len(JOB_PREFIX):])
    if number > 4294967295:
        raise Rejected("manager-job-id-range")
    return number


def jobs_reply(raw):
    rows = reply(raw, "a(usssoo)")
    if type(rows) is not list or len(rows) > MAX_JOBS:
        raise Rejected("manager-job-inventory-limit")
    result, units = {}, set()
    for row in rows:
        if (type(row) is not list or len(row) != 6 or type(row[0]) is not int
                or not 0 < row[0] <= 4294967295
                or type(row[1]) is not str or not re.fullmatch(r"[A-Za-z0-9_.@:\\-]{1,255}", row[1])
                or type(row[2]) is not str or not re.fullmatch(r"[a-z][a-z-]{0,63}", row[2])
                or row[3] not in ("waiting", "running") or type(row[3]) is not str
                or job_path(row[4]) != row[0] or type(row[5]) is not str
                or not re.fullmatch(MANAGER_PATH + r"/unit/[A-Za-z0-9_]{1,1024}", row[5])
                or row[0] in result or row[1] in units):
            raise Rejected("manager-job-inventory-schema")
        result[row[0]] = tuple(row)
        units.add(row[1])
    return result


def record_names(sequence, role):
    # Keep the existing runtime record names stable; forward uses its own slot.
    index = STOP_ROLES.index(role) + 1
    prefix = "operation-%02d-job-%02d-" % (sequence, index)
    return prefix + "pending.json", prefix + "return.json"


def classify_records(pending_raw, returned_raw, *, operation, role):
    """Historical correspondence only; never reconstruct a live submission grant."""
    pending = decode(pending_raw)
    shape(pending, JOB_PENDING_FIELDS)
    if (pending_raw != canonical(pending) or pending["schema"] != "host-recovery-manager-stop-pending-v1"
            or role not in roles_for_method(operation["method"]) or pending["operation_id"] != operation["operation_id"]
            or pending["role"] != role or type(pending["manager_owner"]) is not str
            or UNIQUE.fullmatch(pending["manager_owner"]) is None
            or type(pending["bus_id"]) is not str or INVOCATION.fullmatch(pending["bus_id"]) is None
            or type(pending["unit"]) is not str or UNIT.fullmatch(pending["unit"]) is None
            or type(pending["invocation_id"]) is not str or INVOCATION.fullmatch(pending["invocation_id"]) is None):
        raise Rejected("manager-job-pending-unbound")
    pin(pending["target_sha256"])
    if returned_raw is None:
        return pending, None
    returned = decode(returned_raw)
    shape(returned, JOB_RETURN_FIELDS)
    if (returned_raw != canonical(returned) or returned["schema"] != "host-recovery-manager-stop-return-v1"
            or returned["pending_sha256"] != digest(pending_raw) or returned["retirement_proven"] is not False
            or type(returned["job_id"]) is not int or returned["job_id"] != job_path(returned["job_path"])):
        raise Rejected("manager-job-return-unbound")
    return pending, returned


class _FixedStopJobs:
    """Shared fixed-role bookkeeping, never a caller-selected method or role set.

    check is the embedding broker's original peer/lock/unit/input barrier, never
    an IPC-supplied callback. Commands and their retained helper lifetime belong
    to that broker. No cancel, restart, StartUnit or arbitrary method exists.
    """
    method = None
    target_schema = None

    def __init__(self, *, journal, units, busctl, busctl_sha256, commands, read_helper_hash, session=None):
        from .manager_bus import ManagerJobSession
        if session is not None and (not isinstance(session, ManagerJobSession) or session.units != units):
            raise Rejected("manager-job-original-session-required")
        self.session = self._original_session = session
        self._completions = {}
        roles = roles_for_method(self.method)
        if (not roles or not isinstance(journal, OperationJournal) or type(units) is not dict
                or set(units) != set(roles) or any(not isinstance(x, UnitBinding) for x in units.values())
                or len({x.unit for x in units.values()}) != len(roles)
                or type(busctl) is not str or not os.path.isabs(busctl)):
            raise Rejected("manager-job-fixed-boundaries-required")
        pin(busctl_sha256)
        self.journal, self.units, self.busctl, self.commands = journal, dict(units), busctl, commands
        self.busctl_sha256, self.read_helper_hash = busctl_sha256, read_helper_hash
        self._configuration = self.configuration()
        self._owner, self._bus_id, self._submitted, self._attempted = None, None, {}, set()
        self.failed = False

    def configuration(self):
        return canonical({"schema": self.target_schema, "busctl": self.busctl,
            "busctl_sha256": self.busctl_sha256, "binding_sha256": digest(self.journal._binding), "epoch_sha256": digest(self.journal._epoch),
            "units": {role: asdict(self.units[role]) for role in roles_for_method(self.method)},
            "session": None if self.session is None else {"bus_id": self.session.bus_id,
                "manager_owner": self.session.owner, "library_sha256": self.session.library_sha256,
                "deadline": self.session.deadline}})

    def _current(self, deadline, check):
        if (self.failed or self.session is not self._original_session or self.configuration() != self._configuration
                or self.session is not None and (self.session.failed or self.session.deadline > deadline)):
            raise Rejected("manager-job-configuration-changed")
        self.journal._current()
        self.journal._time(deadline)
        if self.read_helper_hash(self.busctl) != self.busctl_sha256:
            raise Rejected("manager-job-helper-pin-changed")
        check()
        self.journal._current()
        self.journal._time(deadline)
        if self.session is not self._original_session or self.configuration() != self._configuration:
            raise Rejected("manager-job-configuration-changed")

    def _call(self, destination, path, interface, method, args, *, deadline):
        return self.commands.run((self.busctl, "--system", "--json=short", "--no-pager", "call",
            destination, path, interface, method) + args, deadline=deadline)

    def _manager(self, deadline, check):
        self._current(deadline, check)
        if self.session is not None:
            bus_id, owner = self.session.identity()
            if self._bus_id not in (None, bus_id) or self._owner not in (None, owner):
                raise Rejected("manager-job-original-session-changed")
            self._bus_id, self._owner = bus_id, owner
            self._current(deadline, check)
            return owner
        bus_id = reply(self._call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
            "GetId", (), deadline=deadline), "s")
        if type(bus_id) is not str or INVOCATION.fullmatch(bus_id) is None or self._bus_id not in (None, bus_id):
            raise Rejected("manager-job-bus-generation-changed")
        self._bus_id = bus_id
        self._current(deadline, check)
        owner = reply(self._call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
            "GetNameOwner", ("s", MANAGER), deadline=deadline), "s")
        if type(owner) is not str or UNIQUE.fullmatch(owner) is None or self._owner not in (None, owner):
            raise Rejected("manager-job-owner-changed")
        self._owner = owner
        self._current(deadline, check)
        return owner

    def _snapshot(self, deadline, check):
        owner = self._manager(deadline, check)
        rows = (self.session.jobs() if self.session is not None else
                jobs_reply(self._call(owner, MANAGER_PATH, MANAGER + ".Manager", "ListJobs", (), deadline=deadline)))
        self._manager(deadline, check)
        for role, unit in self.units.items():
            expected = self._submitted.get(role)
            for row in rows.values():
                if expected is not None and row[0] == expected["job_id"]:
                    if row[1] != unit.unit or row[2] != "stop" or row[4] != expected["job_path"]:
                        raise Rejected("manager-job-identity-conflict")
                if row[1] == unit.unit and (expected is None or row[0] != expected["job_id"] or row[2] != "stop"):
                    raise Rejected("manager-job-untracked-runtime-job")
        return rows

    def submit(self, role, *, operation, deadline, check):
        with self.journal._mutex:
            try:
                self._current(deadline, check)
                if (role not in roles_for_method(self.method) or role in self._attempted or type(operation) is not dict
                        or operation.get("method") != self.method
                        or canonical(operation) != self.journal._pending.get(self.method)
                        or self.method in self.journal._returned or deadline != operation["deadline"]):
                    raise Rejected("manager-job-original-pending-required")
                operation = decode(canonical(operation))
                self._attempted.add(role)
                self._snapshot(deadline, check)
                unit = self.units[role]
                pending = {"schema": "host-recovery-manager-stop-pending-v1", "operation_id": operation["operation_id"],
                    "role": role, "target_sha256": digest(self._configuration), "manager_owner": self._owner,
                    "bus_id": self._bus_id, "unit": unit.unit, "invocation_id": unit.invocation_id}
                pending_name, return_name = record_names(operation["sequence"], role)
                self.journal._write(pending_name, pending)
                self._snapshot(deadline, check)
                self._current(deadline, check)
                if self.session is not None:
                    path = self.session.stop(role)
                else:
                    raw = self._call(self._owner, MANAGER_PATH, MANAGER + ".Manager", "StopUnit",
                                     ("ss", unit.unit, "fail"), deadline=deadline)
                    path = reply(raw, "o")
                returned = {"schema": "host-recovery-manager-stop-return-v1", "pending_sha256": digest(canonical(pending)),
                    "job_id": job_path(path), "job_path": path, "retirement_proven": False}
                if any(x["job_id"] == returned["job_id"] for x in self._submitted.values()):
                    raise Rejected("manager-job-return-identity-reused")
                self.journal._write(return_name, returned)
                self._submitted[role] = decode(canonical(returned))
                self._snapshot(deadline, check)
                return decode(canonical(returned))
            except Exception:
                self.failed = self.journal._failed = True
                raise Rejected("manager-job-submission-unconfirmed") from None

    def observe(self, *, deadline, check):
        with self.journal._mutex:
            try:
                rows = self._snapshot(deadline, check)
                if self.session is not None:
                    for role, event in self.session.completions().items():
                        operation = decode(self.journal._pending[self.method])
                        self._current(deadline, check)
                        returned = self._submitted[role]
                        if returned["job_id"] in rows:
                            raise Rejected("manager-job-completion-inventory-conflict")
                        value = {"schema": "host-recovery-manager-completion-v1",
                            "return_sha256": digest(canonical(returned)), "bus_id": self._bus_id,
                            "manager_owner": self._owner, **event, "retirement_proven": False}
                        if role in self._completions:
                            if self._completions[role] != canonical(value):
                                raise Rejected("manager-job-completion-changed")
                        else:
                            self.journal._write(completion_name(operation["sequence"], role), value)
                            self._completions[role] = canonical(value)
                        self._current(deadline, check)
                    self.session.identity()
                    self._current(deadline, check)
                return {role: ("completion_" + decode(self._completions[role])["result"] + "_observed"
                               if role in self._completions else
                               "pending_observed" if item["job_id"] in rows else "absent_not_retired")
                        for role, item in self._submitted.items()}
            except Exception:
                self.failed = self.journal._failed = True
                raise Rejected("manager-job-observation-unconfirmed") from None

    def matches(self, role, value):
        item = self._submitted.get(role)
        return item is not None and value == str(item["job_id"])


class RuntimeStopJobs(_FixedStopJobs):
    """At most one StopUnit per dedicated runtime role under its pending operation."""
    method = "cold_quiesce_runtime"
    target_schema = "host-recovery-runtime-stop-target-v1"


class ForwardStopJobs(_FixedStopJobs):
    """One forward stop on a continuous session; no legacy busctl fallback."""
    method = "contain_forward"
    target_schema = "host-recovery-forward-stop-target-v1"

    def __init__(self, **kwargs):
        from .manager_bus import ManagerJobSession
        if not isinstance(kwargs.get("session"), ManagerJobSession):
            raise Rejected("manager-job-forward-session-required")
        super().__init__(**kwargs)
