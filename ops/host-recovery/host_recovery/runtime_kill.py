"""Retained recursive runtime-kill correspondence, never replay or drain authority."""
from .broker_operations import shape
from .durable import Rejected, canonical, decode, digest
from .loading import pin
from .topology import RUNTIME_ROLES


def record_names(sequence):
    prefix = "operation-%02d-runtime-kill-" % sequence
    return tuple(prefix + phase + ".json" for phase in ("pending", "return", "empty"))


def classify_records(pending_raw, returned_raw, empty_raw, *, operation, completions):
    """Check saved phase links; even an empty observation is historical only."""
    pending = decode(pending_raw)
    shape(pending, ("schema", "operation_id", "domain_sha256", "stop_completions_sha256"))
    if (pending_raw != canonical(pending) or operation["method"] != "cold_quiesce_runtime"
            or pending["schema"] != "host-recovery-runtime-kill-pending-v1"
            or pending["operation_id"] != operation["operation_id"]
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
    shape(returned, ("schema", "pending_sha256", "recursive_domain_kill_returned", "pending_drained"))
    if (returned_raw != canonical(returned) or returned["schema"] != "host-recovery-runtime-kill-return-v1"
            or returned["pending_sha256"] != digest(pending_raw)
            or returned["recursive_domain_kill_returned"] is not True or returned["pending_drained"] is not False):
        raise Rejected("runtime-kill-history-return-unbound")
    if empty_raw is None:
        return "returned_without_empty_observation"
    empty = decode(empty_raw)
    shape(empty, ("schema", "return_sha256", "domain_empty_observed", "runtime_containment_coverage_proven"))
    if (empty_raw != canonical(empty) or empty["schema"] != "host-recovery-runtime-kill-empty-v1"
            or empty["return_sha256"] != digest(returned_raw) or empty["domain_empty_observed"] is not True
            or empty["runtime_containment_coverage_proven"] is not False):
        raise Rejected("runtime-kill-history-empty-unbound")
    return "empty_observed_unproven"
