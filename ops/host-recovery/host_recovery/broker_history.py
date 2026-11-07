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
from .manager_jobs import STOP_ROLES, classify_completion, classify_records, completion_name, record_names
from .mask_reload import classify_records as classify_reload, record_names as reload_names
from .job_cancellation import classify_records as classify_cancellation, record_names as cancellation_names
from .runtime_kill import classify_records as classify_kill, record_names as kill_names
from .topology import RUNTIME_ROLES

MAX_FILES = 1 + 4 * MAX_OPERATIONS + 6 * len(STOP_ROLES) + 3
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
        allowed.update(reload_names(sequence))
        allowed.update(kill_names(sequence))
        for role in STOP_ROLES:
            allowed.update(record_names(sequence, role))
            allowed.add(completion_name(sequence, role))
            allowed.update(cancellation_names(sequence, role))
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
        for role in STOP_ROLES:
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
            job = {"role": role, "classification": "submission_unreturned" if job_uncertain else "submitted_unproven",
                   "job_id": None if job_uncertain else observed["job_id"], "retirement_proven": False}
            completion = completion_name(sequence, role)
            if completion in records:
                event = classify_completion(records[completion], pending=submitted, returned=observed)
                consumed.add(completion)
                job["classification"] = "completion_" + event["result"] + "_observed"
                job["sender_cookie"] = event["sender_cookie"]
            jobs.append(job)
        if jobs:
            item["manager_jobs"] = jobs
        cancellations, cancel_identity, cancel_ids, cancel_uncertain = [], None, set(), False
        for role in sorted(STOP_ROLES):
            cancel_pending, cancel_return, cancel_completion = cancellation_names(sequence, role)
            if cancel_pending not in records:
                continue
            if cancel_uncertain:
                raise Rejected("broker-history-cancellation-after-uncertainty")
            submitted, observed, completed = classify_cancellation(records[cancel_pending], records.get(cancel_return),
                records.get(cancel_completion), operation=pending, role=role)
            identity = (submitted["manager_owner"], submitted["bus_id"], submitted["target_sha256"])
            if cancel_identity not in (None, identity) or submitted["job"][0] in cancel_ids:
                raise Rejected("broker-history-cancellation-identity-conflict")
            stop_pending = record_names(sequence, role)[0]
            if ((job_owner is not None and identity[:2] != job_owner[:2]) or submitted["job"][0] in job_ids
                    or stop_pending in records and submitted["job"][1] != _record(records[stop_pending])["unit"]):
                raise Rejected("broker-history-cancellation-stop-conflict")
            cancel_identity = identity
            cancel_ids.add(submitted["job"][0])
            consumed.add(cancel_pending)
            if observed is not None:
                consumed.add(cancel_return)
            if completed is not None:
                consumed.add(cancel_completion)
            cancel_uncertain = completed is None
            if cancel_uncertain and (jobs or return_name in records or reload_names(sequence)[0] in records):
                raise Rejected("broker-history-effect-after-uncertain-cancellation")
            cancellations.append({"role": role, "classification": "canceled_observed" if completed is not None else
                "return_without_completion" if observed is not None else "unreturned", "retirement_proven": False})
        if cancellations:
            item["waiting_start_cancellations"] = cancellations
        reload_pending, reload_return = reload_names(sequence)
        if reload_pending in records:
            _, reloaded = classify_reload(records[reload_pending], records.get(reload_return), operation=pending)
            consumed.add(reload_pending)
            if reloaded is None:
                # No live writer can proceed past an uncertain reload. Do not
                # reinterpret a later outer return or stop record as its result.
                if return_name in records or jobs:
                    raise Rejected("broker-history-effect-after-uncertain-reload")
            else:
                consumed.add(reload_return)
            item["mask_reload"] = {"classification": "unreturned" if reloaded is None else "returned_unproven",
                                   "pending_drained": False}
        kill_pending, kill_return, kill_empty = kill_names(sequence)
        if kill_pending in records:
            if (method != "cold_quiesce_runtime"
                    or not any(prior["method"] == "contain_forward" and prior["classification"] == "returned_unproven"
                               for prior in operations)
                    or item.get("mask_reload", {}).get("classification") != "returned_unproven"
                    or {job["role"] for job in jobs} != set(RUNTIME_ROLES)
                    or any(job["classification"] != "completion_done_observed" for job in jobs)):
                raise Rejected("broker-history-kill-before-runtime-stop-completions")
            phase = classify_kill(records[kill_pending], records.get(kill_return), records.get(kill_empty),
                operation=pending, completions={role: digest(records[completion_name(sequence, role)])
                                               for role in RUNTIME_ROLES})
            consumed.update(name for name in (kill_pending, kill_return, kill_empty) if name in records)
            if return_name in records and phase != "empty_observed_unproven":
                raise Rejected("broker-history-outer-return-after-uncertain-runtime-kill")
            item["runtime_kill"] = {"classification": phase, "pending_drained": False,
                                    "runtime_containment_coverage_proven": False}
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
