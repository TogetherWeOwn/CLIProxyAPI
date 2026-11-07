"""Inclusive monotonic budget accounting, not a blocking-operation watchdog.

The supervisor must enforce the returned deadlines at the manager/daemon boundary.
No phase allocations are defaults: admission requires a separately accepted,
source-bound drill measurement and explicit positive caps and safety margins.
"""
import copy
import math

from .durable import Rejected
from .inventory import HASH

FORWARD_PHASES = frozenset(("stop", "revalidate", "mutate", "candidate-start", "postchecks", "persistence"))
RECOVERY_PHASES = frozenset(("detection", "quiescence", "restore", "verification-start", "persistence", "alert"))


def positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def validate_policy(policy):
    if type(policy) is not dict or set(policy) != {"schema", "work_seconds", "recovery_seconds", "total_seconds", "forward", "recovery", "measurement_sha256"}:
        raise Rejected("budget-schema")
    if policy["schema"] != "host-recovery-budget-v1":
        raise Rejected("budget-version")
    for name, expected in (("work_seconds", 120), ("recovery_seconds", 180), ("total_seconds", 300)):
        if not positive(policy[name]) or policy[name] != expected:
            raise Rejected("budget-target")
    pin = policy["measurement_sha256"]
    if type(pin) is not str or not HASH.fullmatch(pin):
        raise Rejected("drill-measurement-required")
    for name, phases, limit in (("forward", FORWARD_PHASES, 120), ("recovery", RECOVERY_PHASES, 180)):
        group = policy[name]
        if type(group) is not dict or set(group) != {"caps", "safety_margin"}:
            raise Rejected("budget-phase-schema")
        caps = group["caps"]
        if type(caps) is not dict or set(caps) != phases or not positive(group["safety_margin"]):
            raise Rejected("budget-phases-or-margin")
        if any(not positive(value) for value in caps.values()) or sum(caps.values()) + group["safety_margin"] > limit:
            raise Rejected("budget-insufficient-reserve")


class Budget:
    def __init__(self, policy, arm, clock, boot_id):
        validate_policy(policy)
        if type(arm) is not dict or set(arm) != {"boot_id", "monotonic"}:
            raise Rejected("arm-clock-schema")
        if type(arm["boot_id"]) is not str or not arm["boot_id"] or not positive(arm["monotonic"]):
            raise Rejected("arm-clock-identity")
        self.policy = copy.deepcopy(policy)
        self.arm = dict(arm)
        self.clock = clock
        self.boot_id = boot_id
        self.failure_at = None
        self.last = arm["monotonic"]
        self.events = []
        self.phase_ends = {}

    def now(self):
        value = self.clock()
        if self.boot_id() != self.arm["boot_id"]:
            raise Rejected("clock-discontinuity-recovery-required")
        if not positive(value) or value < self.last:
            raise Rejected("clock-regressed-recovery-required")
        self.last = value
        return value

    def trigger_recovery(self, failure_at):
        now = self.now()
        if type(failure_at) not in (int, float) or not math.isfinite(failure_at) or not self.arm["monotonic"] <= failure_at <= now:
            raise Rejected("failure-clock-invalid")
        # A late detector must not reset the reserve at the time it noticed.
        at = min(failure_at, self.arm["monotonic"] + 120)
        self.failure_at = at if self.failure_at is None else min(at, self.failure_at)
        self.events.append({"phase": "recovery-trigger", "monotonic": now, "failure_at": self.failure_at,
                            "detection_seconds": now - self.failure_at})
        return self.deadline("recovery")

    def deadline(self, direction):
        if direction == "forward":
            if self.failure_at is not None:
                raise Rejected("forward-promotion-forbidden")
            return self.arm["monotonic"] + 120
        if direction != "recovery" or self.failure_at is None:
            raise Rejected("recovery-trigger-required")
        return min(self.failure_at + 180, self.arm["monotonic"] + 300)

    def phase_deadline(self, direction, phase):
        now = self.now()
        deadline = self.deadline(direction)
        caps = self.policy[direction]["caps"]
        if phase not in caps:
            raise Rejected("unknown-budget-phase")
        margin = self.policy[direction]["safety_margin"]
        start = self.failure_at if direction == "recovery" and phase == "detection" else now
        phase_end = min(start + caps[phase], deadline - margin)
        key = (direction, phase)
        phase_end = min(self.phase_ends.get(key, phase_end), phase_end)
        self.phase_ends[key] = phase_end
        if now >= phase_end:
            raise Rejected("budget-deadline-missed")
        self.events.append({"phase": phase, "direction": direction, "monotonic": now,
                            "deadline": phase_end, "inclusive_deadline": deadline})
        return phase_end

    def check(self, deadline):
        if self.now() >= deadline:
            raise Rejected("budget-deadline-missed")
