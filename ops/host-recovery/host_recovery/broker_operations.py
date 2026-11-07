"""Durable one-shot broker bookkeeping, not a privileged execution interface.

The future provisioned broker alone owns this private directory and serializes
calls while independently observing the supervisor's ORIGINAL installation lock.
This module takes no installation lock, executes no privileged callback/command,
and grants no runtime, restore or start authority. Pending and returned records never prove
drain. Reopening any history requires cold/quarantine reconciliation, which is
not implemented here; it cannot renew an original request or issue it again.
"""
import math
import os
import stat
import threading
import uuid

from .durable import Rejected, atomic_write, canonical, decode, digest, read_file, signature
from .journal import identity
from .loading import pin

METHODS = frozenset(("contain_forward", "cold_quiesce_runtime", "dispatch_recovery",
                     "restore_approved_baseline", "verify_stopped_baseline", "start_verified_old"))
MAX_OPERATIONS = len(METHODS)
MAX_RECORD_BYTES = 16384
BINDING_FIELDS = ("installation_id", "attempt_id", "intent_sha256", "request_sha256",
                  "topology_sha256", "original_boot_id", "original_arm", "failure_monotonic", "recovery_deadline")
EPOCH_FIELDS = ("boot_id", "broker_invocation_id", "runtime_epoch")


def positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def uuid_value(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Rejected("broker-operation-uuid-required") from None


def shape(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise Rejected("broker-operation-schema")


def validate_binding(value):
    shape(value, BINDING_FIELDS)
    if not identity(value["installation_id"]) or not identity(value["original_boot_id"]):
        raise Rejected("broker-operation-original-identity-required")
    uuid_value(value["attempt_id"])
    for key in ("intent_sha256", "request_sha256", "topology_sha256"):
        pin(value[key])
    if (not positive(value["original_arm"]) or not positive(value["failure_monotonic"])
            or not positive(value["recovery_deadline"])
            or not value["original_arm"] <= value["failure_monotonic"] < value["recovery_deadline"]
            or value["recovery_deadline"] > min(value["original_arm"] + 300, value["failure_monotonic"] + 180)):
        raise Rejected("broker-operation-original-deadline-required")


def validate_epoch(value):
    shape(value, EPOCH_FIELDS)
    if not identity(value["boot_id"]):
        raise Rejected("broker-operation-boot-required")
    for key in ("broker_invocation_id", "runtime_epoch"):
        uuid_value(value[key])


class OperationJournal:
    """Bounded append-only records for a single original recovery request.

    Inputs must come from protected approval/request/epoch loaders; hashes and
    this object's receipts are not authentication. A fresh constructor never
    adopts saved pending/returned entries as permission. The in-memory mutex is
    broker-internal serialization, not another installation ownership lock.
    """
    def __init__(self, fd, *, binding, epoch, clock, boot_id, fault=None):
        validate_binding(binding)
        validate_epoch(epoch)
        self.fd, self.clock, self.boot_id, self.fault = fd, clock, boot_id, fault
        self._binding, self._epoch = canonical(binding), canonical(epoch)
        self._owner = (os.geteuid(), os.getegid())
        self._directory = self._metadata()
        self._mutex = threading.RLock()
        self._records, self._pending, self._returned = {}, {}, set()
        self._last_clock, self._failed = None, False
        self._reopened = bool(os.listdir(fd))
        if self._reopened:
            # Keep every byte, including uncertain staging and partial history.
            # A separate reconciler may inspect it; this object cannot replay it.
            self._failed = True
        else:
            original = decode(self._binding)
            self._time(original["recovery_deadline"])
            value = {"schema": "host-recovery-broker-epoch-v1", "binding": original, "epoch": decode(self._epoch)}
            self._write("epoch.json", value)
            self._current()
            self._time(original["recovery_deadline"])

    def _metadata(self):
        st = os.fstat(self.fd)
        if (not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700
                or (st.st_uid, st.st_gid) != self._owner or os.listxattr(self.fd)):
            raise Rejected("broker-operation-private-directory-required")
        return st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid

    def _time(self, deadline):
        binding, epoch = decode(self._binding), decode(self._epoch)
        now = self.clock()
        if (not positive(deadline) or deadline > binding["recovery_deadline"]
                or not positive(now) or now < binding["failure_monotonic"] or now >= deadline
                or self._last_clock is not None and now < self._last_clock
                or self.boot_id() != epoch["boot_id"] or epoch["boot_id"] != binding["original_boot_id"]):
            raise Rejected("broker-operation-clock-or-deadline-unconfirmed")
        self._last_clock = now

    def _current(self):
        if (self._failed or self._reopened or self._metadata() != self._directory
                or set(os.listdir(self.fd)) != set(self._records)):
            raise Rejected("broker-operation-reconciliation-required")
        for name, (expected, expected_signature) in self._records.items():
            raw, st = read_file(self.fd, name, limit=MAX_RECORD_BYTES)
            if (raw != expected or signature(st) != expected_signature
                    or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (*self._owner, 0o600)):
                raise Rejected("broker-operation-record-changed")
        if set(os.listdir(self.fd)) != set(self._records) or self._metadata() != self._directory:
            raise Rejected("broker-operation-history-changed")

    def _write(self, name, value):
        raw = canonical(value)
        if len(raw) > MAX_RECORD_BYTES or name in os.listdir(self.fd):
            raise Rejected("broker-operation-record-exists-or-too-large")
        atomic_write(self.fd, name, raw, fault=self.fault, stage_name=".stage-" + name)
        actual, st = read_file(self.fd, name, limit=MAX_RECORD_BYTES)
        if actual != raw:
            raise Rejected("broker-operation-readback-unconfirmed")
        self._records[name] = (raw, signature(st))

    def pending(self, method, *, target_sha256, deadline):
        """Publish once before a future broker submits the fixed effect.

        The digest identifies independently approved fixed parameters, never an
        arbitrary path/argv/API request. Returning this record only acknowledges
        bookkeeping. The future handler still needs live authorization inside
        its actual effect barrier. No such handler is enabled by this module.
        """
        with self._mutex:
            try:
                self._current()
                self._time(deadline)
                if type(method) is not str or method not in METHODS:
                    raise Rejected("broker-operation-fixed-recovery-method-required")
                pin(target_sha256)
                if method in self._pending or len(self._pending) >= MAX_OPERATIONS:
                    raise Rejected("broker-operation-already-consumed")
                # No later business phase may pass an unresolved operation.
                if set(self._pending) != self._returned:
                    raise Rejected("broker-operation-previous-return-unconfirmed")
                value = {"schema": "host-recovery-broker-operation-v1", "state": "pending",
                         "binding_sha256": digest(self._binding), "epoch_sha256": digest(self._epoch),
                         "sequence": len(self._pending) + 1, "method": method,
                         "target_sha256": target_sha256, "deadline": deadline}
                value["operation_id"] = digest(canonical(value))
                raw = canonical(value)
                self._write("operation-%02d-pending.json" % value["sequence"], value)
                self._pending[method] = raw
                self._current()
                self._time(deadline)
                return decode(raw)
            except Exception:
                self._failed = True
                raise Rejected("broker-operation-pending-unconfirmed") from None

    def returned(self, operation, *, result):
        """Record only the original submitted call's return, never stopped/drained.

        Results are fixed classifications, not exception strings, response bodies
        or caller-provided success receipts. Even a confirmed return leaves drain,
        restoration, readiness and settlement unproved.
        """
        with self._mutex:
            try:
                self._current()
                if type(operation) is not dict:
                    raise Rejected("broker-operation-original-record-required")
                method = operation.get("method")
                if (type(method) is not str or canonical(operation) != self._pending.get(method)
                        or method in self._returned or result not in ("returned", "ambiguous", "refused")
                        or type(result) is not str):
                    raise Rejected("broker-operation-return-unbound")
                self._time(operation["deadline"])
                value = {"schema": "host-recovery-broker-return-v1", "operation_id": operation["operation_id"],
                         "result": result, "pending_drained": False}
                self._write("operation-%02d-return.json" % operation["sequence"], value)
                self._returned.add(method)
                self._current()
                self._time(operation["deadline"])
                if result != "returned":
                    self._failed = True
                return decode(canonical(value))
            except Exception:
                self._failed = True
                raise Rejected("broker-operation-return-unconfirmed") from None

    def status(self):
        with self._mutex:
            try:
                self._current()
                self._time(decode(self._binding)["recovery_deadline"])
            except Exception:
                self._failed = True
            return {"schema": "host-recovery-broker-operations-status-v1",
                    "state": "reconciliation_required" if self._failed else "bookkeeping_only",
                    "reopened": self._reopened,
                    "pending_count": None if self._failed else len(self._pending),
                    "returned_count": None if self._failed else len(self._returned), "pending_drained": False,
                    "complete_fence_proven": False, "recovery_execution_allowed": False,
                    "start_allowed": False, "production_acceptance": False}
