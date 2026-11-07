"""Separately approved recovery-only reserve; never renew the original target.

The installation-lock owner authenticates the new manager invocation and approval
through its independent boundary. A digest only binds that decision's bytes.
Neither this clock nor a successful late restore clears the original start latch.
"""
import copy

from .budget import Budget, positive
from .durable import Rejected, canonical, digest
from .inventory import HASH
from .journal import identity


def validate_continuation(value, *, approval_sha256, intent, arm, boot_id, now):
    fields = {"schema", "continuation_id", "intent_sha256", "arm_sha256", "owner", "started_at", "deadline"}
    if (type(value) is not dict or set(value) != fields
            or value["schema"] != "host-recovery-continuation-v1"
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
