"""Restored-input checks; not the complete independent restoration/start oracle.

The caller retains the installation lock and authenticates role/policy/helper
approvals independently. The manager/daemon/current-state oracle and complete
writer/start fence remain separate requirements, never inferred from file hashes.
"""
import base64
import copy
from dataclasses import dataclass

from .commands import Deadline
from .coordinator import validate_baseline_receipt
from .durable import Rejected, canonical, decode, digest
from .input_gate import ExactInputGate
from .loading import pin
from .write_set import WriteSetRecovery

ROLES = frozenset(("config", "compose_source", "frozen_rendered_compose", "environment"))


@dataclass(frozen=True)
class BaselineApproval:
    intent_sha256: str
    roles_sha256: str
    policy_sha256: str

    def __post_init__(self):
        for value in (self.intent_sha256, self.roles_sha256, self.policy_sha256):
            pin(value)


class RestoredInputSnapshot:
    """Capture original role files from a freshly verified complete write set.

    Environment is an explicit restored JSON map, not the process environment.
    Policy and role hashes are comparison pins, not signatures or provisioning.
    No candidate validator is required to run safe baseline restoration.
    """
    def __init__(self, *, recovery, roles, policy, approval, check, clock):
        if (not isinstance(recovery, WriteSetRecovery) or not isinstance(approval, BaselineApproval)
                or type(roles) is not dict or set(roles) != ROLES or type(policy) is not dict
                or not callable(check) or not callable(clock)):
            raise Rejected("baseline-input-explicit-boundary-required")
        self.recovery, self.approval = recovery, approval
        self.roles, self.policy = copy.deepcopy(roles), copy.deepcopy(policy)
        self.check, self.clock = check, clock

    def _current(self, intent, deadline, remaining):
        remaining()
        if (digest(canonical(intent)) != self.approval.intent_sha256
                or digest(canonical(self.roles)) != self.approval.roles_sha256
                or digest(canonical(self.policy)) != self.approval.policy_sha256
                or self.check(deadline=deadline) is not True):
            raise Rejected("baseline-input-approval-or-boundary-changed")
        remaining()

    def __call__(self, intent, *, deadline):
        remaining = Deadline(self.clock, deadline).remaining
        try:
            self._current(intent, deadline, remaining)
            files = self.recovery.capture_files(intent, self.roles, deadline=deadline)
            request = {"schema": "host-recovery-baseline-input-v1", "policy": copy.deepcopy(self.policy),
                       "environment": decode(files["environment"])}
            for role in ROLES - {"environment"}:
                request[role] = {"bytes": base64.b64encode(files[role]).decode("ascii"),
                                 "sha256": digest(files[role])}
            raw = canonical(request)
            self._current(intent, deadline, remaining)
            # Serialize before recapturing: even same-inode/coarse-metadata byte
            # changes during serialization must not leave an accepted stale input.
            if self.recovery.capture_files(intent, self.roles, deadline=deadline) != files:
                raise Rejected("baseline-input-restored-files-changed")
            self._current(intent, deadline, remaining)
            return raw
        except Exception:
            raise Rejected("baseline-input-capture-unconfirmed") from None


class RestoredInputGate(ExactInputGate):
    """Reuse the pinned descriptor/deadline transport with a distinct receipt."""
    receipt = (b'{"schema":"host-recovery-baseline-input-result-v1",'
               b'"baseline_inputs_validated":true,"start_authorized":false}\n')


class RecoveredInputBoundary:
    """Add restored-input checks without replacing any independent host oracle.

    The existing oracle must still supply every coordinator fact and the actual
    start boundary must revalidate current manager/daemon/fence/effective mounts.
    Checks run after that oracle and again just before its one-shot old start.
    A matching dictionary in tests is not implementation of that host boundary.
    """
    def __init__(self, boundary, gate):
        if not isinstance(gate, RestoredInputGate):
            raise Rejected("baseline-input-gate-required")
        self.boundary, self.gate = boundary, gate
        self.attempted, self.pending, self.failed = False, None, False

    def verify_baseline_stopped(self, intent, *, deadline):
        try:
            if self.attempted or self.failed:
                raise Rejected("baseline-input-oracle-once-only")
            self.attempted = True
            receipt = self.boundary.verify_baseline_stopped(copy.deepcopy(intent), deadline=deadline)
            validate_baseline_receipt(intent, receipt)
            if self.gate.verify(copy.deepcopy(intent), deadline=deadline) is not True:
                raise Rejected("baseline-input-gate-unconfirmed")
            self.pending = (digest(canonical(intent)), canonical(receipt))
            return copy.deepcopy(receipt)
        except Exception:
            self.failed = True
            raise Rejected("baseline-input-oracle-unconfirmed") from None

    def start_old(self, intent, receipt, *, deadline):
        try:
            if (self.failed or self.pending is None
                    or self.pending != (digest(canonical(intent)), canonical(receipt))):
                raise Rejected("baseline-input-original-oracle-required")
            self.pending = None  # Never reuse a grant after a lost start response.
            if self.gate.verify(copy.deepcopy(intent), deadline=deadline) is not True:
                raise Rejected("baseline-input-gate-unconfirmed")
            return self.boundary.start_old(copy.deepcopy(intent), copy.deepcopy(receipt), deadline=deadline)
        except Exception:
            self.failed = True
            raise Rejected("baseline-input-old-start-unconfirmed") from None

    def __getattr__(self, name):
        return getattr(self.boundary, name)
