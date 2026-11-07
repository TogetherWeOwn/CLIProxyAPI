"""Retained recursive runtime-kill correspondence, never replay or drain authority."""
from .broker_operations import shape
from .durable import Rejected, canonical, decode, digest
from .loading import pin
from .topology import RUNTIME_ROLES


def record_names(sequence):
    prefix = "operation-%02d-runtime-kill-" % sequence
    return tuple(prefix + phase + ".json" for phase in ("pending", "return", "empty"))


def classify_records(pending_raw, returned_raw, empty_raw, *, operation, completions):
    """Check saved phase links without upgrading an older policy's observations.

    v1 is kill-only; v2 adds freezing; v3 also requires the zero descendant limit.
    Mixed versions refuse. No version reconstructs a live cgroup/peer, proves
    writer/lifecycle exclusion, or permits redispatch, thaw or limit reopening.
    """
    pending = decode(pending_raw)
    if type(pending) is not dict or type(pending.get("schema")) is not str:
        raise Rejected("runtime-kill-history-pending-schema")
    schemas = {"host-recovery-runtime-kill-pending-v%d" % version: version for version in (1, 2, 3)}
    version = schemas.get(pending.get("schema"))
    if version is None:
        raise Rejected("runtime-kill-history-pending-schema")
    pending_flags = (("domain_freeze_required",) if version >= 2 else ()) + (
        ("domain_descendants_seal_required",) if version >= 3 else ())
    observed_flags = (("domain_frozen_observed",) if version >= 2 else ()) + (
        ("domain_descendants_sealed_observed",) if version >= 3 else ())
    shape(pending, ("schema", "operation_id", "domain_sha256", "stop_completions_sha256") + pending_flags)
    if (pending_raw != canonical(pending) or operation["method"] != "cold_quiesce_runtime"
            or pending["operation_id"] != operation["operation_id"]
            or any(pending[key] is not True for key in pending_flags)
            or type(completions) is not dict or set(completions) != set(RUNTIME_ROLES)
            or pending["stop_completions_sha256"] != completions):
        raise Rejected("runtime-kill-history-pending-unbound")
    pin(pending["domain_sha256"])
    for value in completions.values():
        pin(value)
    if returned_raw is None:
        if empty_raw is not None:
            raise Rejected("runtime-kill-history-empty-without-return")
        return "unreturned"
    returned = decode(returned_raw)
    shape(returned, ("schema", "pending_sha256", "recursive_domain_kill_returned", "pending_drained") + observed_flags)
    if (returned_raw != canonical(returned) or returned["schema"] != "host-recovery-runtime-kill-return-v%d" % version
            or returned["pending_sha256"] != digest(pending_raw)
            or any(returned[key] is not True for key in observed_flags)
            or returned["recursive_domain_kill_returned"] is not True or returned["pending_drained"] is not False):
        raise Rejected("runtime-kill-history-return-unbound")
    if empty_raw is None:
        return "returned_without_empty_observation"
    empty = decode(empty_raw)
    shape(empty, ("schema", "return_sha256", "domain_empty_observed", "runtime_containment_coverage_proven") + observed_flags)
    if (empty_raw != canonical(empty) or empty["schema"] != "host-recovery-runtime-kill-empty-v%d" % version
            or empty["return_sha256"] != digest(returned_raw) or empty["domain_empty_observed"] is not True
            or any(empty[key] is not True for key in observed_flags)
            or empty["runtime_containment_coverage_proven"] is not False):
        raise Rejected("runtime-kill-history-empty-unbound")
    return "empty_observed_unproven"
