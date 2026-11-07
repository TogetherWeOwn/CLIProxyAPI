"""Separately approved recovery-only reserve; never renew the original target.

The installation-lock owner authenticates the new manager invocation and approval
through its independent boundary. A digest only binds that decision's bytes.
Neither this clock nor a successful late restore clears the original start latch.
"""
import copy
import os
import stat

from .budget import Budget, positive
from .durable import Rejected, canonical, decode, digest, read_file, signature
from .inventory import HASH
from .journal import identity


MAX_CONTINUATIONS = 8


def continuation_names(index):
    suffix = "" if index == 1 else "-" + str(index).zfill(2)
    return "continuation-request" + suffix + ".json", "continuation-outcome" + suffix + ".json"


def validate_continuation(value, *, approval_sha256, intent, arm, boot_id, now, previous=None):
    fields = {"schema", "continuation_id", "intent_sha256", "arm_sha256", "owner", "started_at", "deadline"}
    schema = "host-recovery-continuation-v1"
    if previous is not None:
        fields.add("previous_sha256")
        schema = "host-recovery-continuation-v2"
    if (type(value) is not dict or set(value) != fields
            or value["schema"] != schema
            or type(approval_sha256) is not str or not HASH.fullmatch(approval_sha256)
            or digest(canonical(value)) != approval_sha256
            or not identity(value["continuation_id"])
            or value["intent_sha256"] != digest(canonical(intent))
            or value["arm_sha256"] != digest(canonical(arm))):
        raise Rejected("continuation-approved-original-inputs-required")
    owner = value["owner"]
    if (type(owner) is not dict or set(owner) != set(intent["owner"])
            or any(not identity(part) for part in owner.values())
            or owner["installation_id"] != intent["installation_id"]
            or owner["attempt_id"] != intent["attempt_id"]
            or owner["boot_id"] != boot_id
            or owner["invocation_id"] == intent["owner"]["invocation_id"]):
        raise Rejected("continuation-new-recovery-owner-required")
    if (not positive(now) or not positive(value["started_at"]) or not positive(value["deadline"])
            or not value["started_at"] <= now < value["deadline"]
            or value["deadline"] - value["started_at"] > intent["budget"]["recovery_seconds"]):
        raise Rejected("continuation-bounded-reserve-required")
    # Ordinary same-boot resume must not turn into a fresh reserve while its
    # original conservative detection allocation is still available.
    if (boot_id == arm["boot_id"]
            and value["started_at"] < arm["monotonic"] + intent["budget"]["recovery"]["caps"]["detection"]):
        raise Rejected("continuation-original-resume-still-available")
    if previous is not None:
        if (value["previous_sha256"] != digest(canonical(previous))
                or owner["invocation_id"] == previous["owner"]["invocation_id"]
                or value["continuation_id"] == previous["continuation_id"]
                or (owner["boot_id"] == previous["owner"]["boot_id"]
                    and value["started_at"] < previous["started_at"])):
            raise Rejected("continuation-successor-unbound")


def continuation_history(fd, entries, *, intent, arm):
    """Read consumed requests without adopting their owner, effects or outcome.

    Every request is immutable and consecutive. Outcomes are correspondence only;
    even a complete-looking prior receipt cannot skip current recovery/oracles.
    Staged, unknown, gapped or noncanonical history remains unadoptable.
    """
    allowed = {name for index in range(1, MAX_CONTINUATIONS + 1) for name in continuation_names(index)}
    present = {name for name in entries if name.startswith("continuation-")}
    if present - allowed:
        raise Rejected("continuation-history-unknown")
    history, records, consumed = [], {}, set()
    seen_ids, seen_owners = set(), {intent["owner"]["invocation_id"]}

    def read(name):
        raw, info = read_file(fd, name, limit=65536)
        if ((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                != (os.geteuid(), os.getegid(), 0o600)):
            raise Rejected("continuation-private-record-required")
        value = decode(raw)
        if raw != canonical(value):
            raise Rejected("continuation-canonical-record-required")
        records[name] = raw, signature(info)
        consumed.add(name)
        return value

    for index in range(1, MAX_CONTINUATIONS + 1):
        request_name, outcome_name = continuation_names(index)
        if request_name not in present:
            break
        value = read(request_name)
        validate_continuation(value, approval_sha256=digest(canonical(value)), intent=intent, arm=arm,
            boot_id=value["owner"]["boot_id"], now=value["started_at"],
            previous=history[-1] if history else None)
        if value["continuation_id"] in seen_ids or value["owner"]["invocation_id"] in seen_owners:
            raise Rejected("continuation-history-owner-reused")
        seen_ids.add(value["continuation_id"])
        seen_owners.add(value["owner"]["invocation_id"])
        history.append(value)
        if outcome_name in present:
            outcome = read(outcome_name)
            if (set(outcome) != {"schema", "continuation_sha256", "intent_sha256", "receipt",
                    "baseline_restored", "original_target_met", "installation_settled"}
                    or outcome["schema"] != "host-recovery-continuation-outcome-v1"
                    or outcome["continuation_sha256"] != digest(canonical(value))
                    or outcome["intent_sha256"] != digest(canonical(intent))
                    or type(outcome["receipt"]) is not dict
                    or outcome["baseline_restored"] is not True
                    or outcome["original_target_met"] is not False
                    or outcome["installation_settled"] is not False):
                raise Rejected("continuation-history-outcome-unbound")
    if consumed != present:
        raise Rejected("continuation-history-gap-or-orphan")
    return history, records


class ContinuationBudget(Budget):
    """Meter a distinct recovery invocation with the original arm left intact.

    The original target is missed or unprovable, never measured across boots.
    Forward deadlines and triggering another reserve are deliberately unavailable.
    The original positive phase caps and safety margin still bound this reserve.
    """
    def __init__(self, policy, arm, continuation, clock, boot_id):
        super().__init__(policy, arm, clock, boot_id)
        self.continuation = copy.deepcopy(continuation)
        self.last = self.failure_at = continuation["started_at"]
        self.events.append({"phase": "recovery-continuation", "monotonic": self.last,
                            "continuation_id": continuation["continuation_id"],
                            "original_target_met": False,
                            "original_elapsed_seconds": (self.last - arm["monotonic"]
                                if arm["boot_id"] == continuation["owner"]["boot_id"] else None)})

    def now(self):
        value = self.clock()
        if (self.boot_id() != self.continuation["owner"]["boot_id"]
                or not positive(value) or value < self.last):
            raise Rejected("continuation-clock-discontinuity")
        self.last = value
        return value

    def trigger_recovery(self, failure_at):
        raise Rejected("continuation-reserve-cannot-renew")

    def deadline(self, direction):
        if direction != "recovery":
            raise Rejected("continuation-recovery-only")
        return self.continuation["deadline"]
