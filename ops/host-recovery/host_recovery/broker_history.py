"""Read-only crash classification for the broker's retained operation history.

Callers supply independently approved inputs and an already pinned private audit
root, exclude writers, and retain the ORIGINAL installation lock. This reader
neither acquires that lock nor authenticates approval. A self-consistent history
is not a cold barrier: every result denies drain, execution, start and settlement.
No record is removed, repaired, adopted or resubmitted, including after reboot.
"""
from dataclasses import dataclass
import os
import stat

from .broker_operations import (MAX_OPERATIONS, MAX_RECORD_BYTES, METHODS, positive,
                                shape, validate_binding, validate_epoch)
from .dispatch import validate_request
from .durable import Rejected, canonical, decode, digest, read_file, signature
from .journal import validate_intent
from .loading import RecoveryInputs, owner, pin
from .manager_jobs import classify_records, record_names
from .topology import RUNTIME_ROLES

MAX_FILES = 1 + 2 * MAX_OPERATIONS + 2 * len(RUNTIME_ROLES)
PENDING_FIELDS = ("schema", "state", "binding_sha256", "epoch_sha256", "sequence", "method",
                  "target_sha256", "deadline", "operation_id")
RETURN_FIELDS = ("schema", "operation_id", "result", "pending_drained")


@dataclass(frozen=True)
class _RequestIdentity:
    request_id: str


def original_binding(inputs, *, topology_sha256):
    """Bind both journals without pretending historical validation is live authority.

    load_recovery must first authenticate/read back these inputs under the original
    lock. Repeat structural correspondence checks here because RecoveryInputs is
    also constructible by embedders. The validation instant is historical and is
    used ONLY to check the saved request's shape, never to renew its deadline.
    """
    try:
        if not isinstance(inputs, RecoveryInputs):
            raise Rejected("broker-history-original-inputs-required")
        pin(topology_sha256)
        intent, request, arm = inputs.intent, inputs.request, decode(inputs.arm_raw)
        validate_intent(intent)
        historical = request["original_arm"]["monotonic"] + request["detection_upper_bound_seconds"]
        validate_request(request, _RequestIdentity(request["request_id"]), intent["owner"]["boot_id"], historical)
        shape(arm, ("schema", "arm", "intent_sha256"))
        intent_pin = digest(canonical(intent))
        if (inputs.intent_raw != canonical(intent) or inputs.request_raw != canonical(request)
                or inputs.arm_raw != canonical(arm)
                or arm["schema"] != "host-recovery-arm-v1" or arm["intent_sha256"] != intent_pin
                or request["intent_sha256"] != intent_pin or request["attempt_id"] != intent["attempt_id"]
                or request["owner"]["installation_id"] != intent["installation_id"]
                or canonical(arm["arm"]) != canonical(request["original_arm"])):
            raise Rejected("broker-history-original-publication-mismatch")
        value = {"installation_id": intent["installation_id"], "attempt_id": intent["attempt_id"],
                 "intent_sha256": intent_pin, "request_sha256": digest(inputs.request_raw),
                 "topology_sha256": topology_sha256, "original_boot_id": intent["owner"]["boot_id"],
                 "original_arm": request["original_arm"]["monotonic"],
                 "failure_monotonic": request["failure_lower_bound"], "recovery_deadline": request["deadline"]}
        validate_binding(value)
        return value
    except Exception:
        raise Rejected("broker-history-original-inputs-unconfirmed") from None


def _metadata(fd, uid, gid):
    st = os.fstat(fd)
    if (not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700
            or (st.st_uid, st.st_gid) != (uid, gid) or os.listxattr(fd)):
        raise Rejected("broker-history-private-root-required")
    return st


def _names(fd):
    result = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(result) >= MAX_FILES:
                raise Rejected("broker-history-entry-limit")
            result.append(entry.name)
    return sorted(result)


def _capture(fd, *, uid, gid):
    before = _metadata(fd, uid, gid)
    names = _names(fd)
    allowed = {"epoch.json"}
    for sequence in range(1, MAX_OPERATIONS + 1):
        allowed.update("operation-%02d-%s.json" % (sequence, kind) for kind in ("pending", "return"))
        for role in RUNTIME_ROLES:
            allowed.update(record_names(sequence, role))
    # Unknown/staged bytes are retained, not guessed away as unsubmitted calls.
    if "epoch.json" not in names or not set(names) <= allowed:
        raise Rejected("broker-history-incomplete-or-ambiguous")
    records, signatures = {}, {}
    for name in names:
        raw, st = read_file(fd, name, limit=MAX_RECORD_BYTES)
        if ((st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (uid, gid, 0o600)
                or st.st_dev != before.st_dev):
            raise Rejected("broker-history-private-record-required")
        records[name], signatures[name] = raw, signature(st)
    # Rehash bytes, not only timestamps, even on a coarse-metadata filesystem.
    for name in names:
        raw, st = read_file(fd, name, limit=MAX_RECORD_BYTES)
        if raw != records[name] or signature(st) != signatures[name]:
            raise Rejected("broker-history-record-changed")
    if names != _names(fd) or signature(before) != signature(_metadata(fd, uid, gid)):
        raise Rejected("broker-history-root-changed")
    return records


def _record(raw):
    value = decode(raw)
    if raw != canonical(value):
        raise Rejected("broker-history-noncanonical-record")
    return value


def _classify(records, *, binding):
    saved = _record(records["epoch.json"])
    shape(saved, ("schema", "binding", "epoch"))
    if saved["schema"] != "host-recovery-broker-epoch-v1":
        raise Rejected("broker-history-epoch-schema")
    validate_binding(saved["binding"])
    validate_epoch(saved["epoch"])
    if (canonical(saved["binding"]) != canonical(binding)
            or saved["epoch"]["boot_id"] != binding["original_boot_id"]):
        raise Rejected("broker-history-original-binding-mismatch")
    binding_pin, epoch_pin = digest(canonical(binding)), digest(canonical(saved["epoch"]))
    operations, methods, consumed = [], set(), {"epoch.json"}
    stopped = False
    for sequence in range(1, MAX_OPERATIONS + 1):
        pending_name = "operation-%02d-pending.json" % sequence
        return_name = "operation-%02d-return.json" % sequence
        if pending_name not in records:
            break
        if stopped:
            raise Rejected("broker-history-operation-after-uncertainty")
        pending = _record(records[pending_name])
        shape(pending, PENDING_FIELDS)
        method = pending["method"]
        unsigned = {key: value for key, value in pending.items() if key != "operation_id"}
        if (pending["schema"] != "host-recovery-broker-operation-v1" or pending["state"] != "pending"
                or pending["binding_sha256"] != binding_pin or pending["epoch_sha256"] != epoch_pin
                or type(pending["sequence"]) is not int or pending["sequence"] != sequence
                or type(method) is not str or method not in METHODS or method in methods
                or pending["operation_id"] != digest(canonical(unsigned))
                or not positive(pending["deadline"])
                or not binding["failure_monotonic"] < pending["deadline"] <= binding["recovery_deadline"]):
            raise Rejected("broker-history-operation-unbound")
        pin(pending["target_sha256"])
        methods.add(method)
        consumed.add(pending_name)
        classification = "unreturned"
        if return_name in records:
            returned = _record(records[return_name])
            shape(returned, RETURN_FIELDS)
            if (returned["schema"] != "host-recovery-broker-return-v1"
                    or returned["operation_id"] != pending["operation_id"]
                    or returned["pending_drained"] is not False or type(returned["result"]) is not str
                    or returned["result"] not in ("returned", "ambiguous", "refused")):
                raise Rejected("broker-history-return-unbound")
            consumed.add(return_name)
            classification = "returned_unproven" if returned["result"] == "returned" else returned["result"]
        stopped = classification != "returned_unproven"
        item = {"sequence": sequence, "method": method, "operation_id": pending["operation_id"],
                "classification": classification}
        jobs, job_owner, job_ids, job_uncertain = [], None, set(), False
        for role in RUNTIME_ROLES:
            job_pending, job_return = record_names(sequence, role)
            if job_pending not in records:
                continue
            if job_uncertain:
                raise Rejected("broker-history-job-after-uncertainty")
            submitted, observed = classify_records(records[job_pending], records.get(job_return),
                                                   operation=pending, role=role)
            manager_identity = (submitted["manager_owner"], submitted["bus_id"], submitted["target_sha256"])
            if job_owner not in (None, manager_identity):
                raise Rejected("broker-history-manager-owner-conflict")
            job_owner = manager_identity
            consumed.add(job_pending)
            job_uncertain = observed is None
            if observed is not None:
                if observed["job_id"] in job_ids:
                    raise Rejected("broker-history-job-id-reused")
                job_ids.add(observed["job_id"])
                consumed.add(job_return)
            elif return_name in records:
                raise Rejected("broker-history-return-before-job-identity")
            jobs.append({"role": role, "classification": "submission_unreturned" if job_uncertain else "submitted_unproven",
                         "job_id": None if job_uncertain else observed["job_id"], "retirement_proven": False})
        if jobs:
            item["manager_jobs"] = jobs
        operations.append(item)
    if consumed != set(records):
        raise Rejected("broker-history-gap-or-orphan-return")
    return saved["epoch"], operations


def inspect_history(fd, *, inputs, topology_sha256, current_epoch, uid, gid):
    """Capture/classify only; cold/quarantine proof must come from actual runtime reads.

    Missing, partial, conflicting or changed publication rejects with a fixed code
    and no counts. Even epoch-only or fully returned history requires cold recovery.
    No elapsed time is compared across boots and no prior grant is reconstructed.
    """
    try:
        owner(uid, gid)
        validate_epoch(current_epoch)
        current_epoch = decode(canonical(current_epoch))
        binding = original_binding(inputs, topology_sha256=topology_sha256)
        records = _capture(fd, uid=uid, gid=gid)
        saved_epoch, operations = _classify(records, binding=binding)
        boot_changed = current_epoch["boot_id"] != binding["original_boot_id"]
        return {"schema": "host-recovery-broker-history-v1",
                "state": "cross_boot_continuation_required" if boot_changed else "cold_reconciliation_required",
                "history_sha256": digest(canonical({name: digest(raw) for name, raw in records.items()})),
                "boot_changed": boot_changed, "epoch_changed": current_epoch != saved_epoch,
                "recorded_operation_count": len(operations), "operations": operations,
                "pending_drained": False, "complete_fence_proven": False, "recovery_execution_allowed": False,
                "start_allowed": False, "settlement_allowed": False, "production_acceptance": False}
    except Exception:
        raise Rejected("broker-history-unconfirmed") from None
