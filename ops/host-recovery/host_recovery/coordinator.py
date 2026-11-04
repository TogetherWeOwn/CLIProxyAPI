"""Attempt ordering component; NOT a persistent systemd supervisor/host adapter.

The boundary below is injected and must eventually be implemented by the narrow,
reviewed systemd/daemon adapter. Every call receives an inclusive phase deadline;
Python calls alone cannot bound a wedged filesystem, daemon or manager. The caller
holds the installation lock throughout. No live commands or host defaults exist.
"""
import copy
import os
import stat

from .budget import Budget, positive
from .durable import Rejected, canonical, decode, digest, notify, read_file, signature
from .journal import OBJECT_ID, validate_intent

CHECKS = frozenset(("model", "replay", "quota", "fingerprint", "subscription", "claude",
                    "sol", "no_client_repin", "alias_inert", "config_policy"))


def validate_baseline_receipt(intent, receipt):
    expected = {"baseline_sha256": intent["baseline_sha256"], "object_id": intent["old_object_id"],
                "original_image": True, "original_replay": True, "new_plugin_absent": True,
                "complete_write_set": True, "metadata_verified": True, "all_writers_stopped": True}
    if (type(receipt) is not dict or set(receipt) != set(expected)
            or any(type(receipt[k]) is not type(v) or receipt[k] != v for k, v in expected.items())):
        raise Rejected("baseline-start-oracle-incomplete")


def recover_baseline(call, intent):
    """Shared stop/restore/verify/start ordering; call enforces each live lease.

    This sequence grants no authority. The caller must authenticate the recovery
    boundary independently and supply inclusive, non-renewing phase deadlines.
    Journal terminal persistence remains with the installation-lock owner.
    """
    AttemptCoordinator._confirmed(call("detection", "fence", intent))
    AttemptCoordinator._confirmed(call("quiescence", "quiesce", intent))
    AttemptCoordinator._confirmed(call("restore", "validate_recovery", intent))
    AttemptCoordinator._confirmed(call("restore", "restore_complete", intent))
    receipt = call("verification-start", "verify_baseline_stopped", intent)
    validate_baseline_receipt(intent, receipt)
    AttemptCoordinator._confirmed(call("verification-start", "start_old", intent, receipt))
    AttemptCoordinator._confirmed(call("verification-start", "old_ready", intent))
    return receipt


class AmbiguousCreate(Exception):
    """Create may have succeeded; reconcile its preassigned ownership identity."""


class ObservedFailure(Exception):
    """A manager-observed monotonic failure time, without arbitrary log text."""
    def __init__(self, monotonic):
        super().__init__("boundary-observed-failure")
        self.monotonic = monotonic


class AttemptCoordinator:
    """One admitted attempt, with a recovery path distinct from forward mutation.

    Boundary methods must inspect actual unit/invocation, fence and all owned
    daemon objects, never just a PID or the mutation cgroup. A strict True is an
    adapter acknowledgment, not evidence of an actual manager in component tests.
    """
    def __init__(self, journal, boundary, clock, boot_id, persist_alert, transport_alert):
        self.journal = journal
        self.boundary = boundary
        self.clock = clock
        self.boot_id = boot_id
        self.persist_alert = persist_alert
        self.transport_alert = transport_alert
        self.meter = None
        self.original_cause = None
        self.recovery_error = None
        self.start_fenced = True
        self.started_forward = False
        self.recovery_attempted = False
        self.resume_attempted = False
        self.resume_records = None
        self.resume_entries = None
        self.active_phase = "admission"
        self.failure_since = None
        self.result = {"outcome": "fenced", "production_acceptance": False}

    def admit(self, intent):
        # The concrete adapter must authenticate policy approval and package,
        # baseline, manager/start-fence and independent-listener challenge here.
        # Merely checking digest syntax or mock responses is not that proof.
        validate_intent(intent)
        value = copy.deepcopy(intent)
        if self.journal.intent is not None or self.journal.reopened:
            raise Rejected("recovery-reconciliation-required")
        if value["owner"]["boot_id"] != self.boot_id():
            raise Rejected("admission-boot-mismatch")
        if self.boundary.preflight(copy.deepcopy(value)) is not True:
            raise Rejected("preflight-or-listener-unconfirmed")
        try:
            self.journal.prepare(value)
            arm = {"boot_id": self.boot_id(), "monotonic": self.clock()}
            self.journal.arm(arm)
            self.meter = Budget(value["budget"], arm, self.clock, self.boot_id)
            self.meter.check(self.meter.deadline("forward"))
        except Exception:
            self.original_cause = "admission-persistence-or-clock-failed"
            self._alert()
            raise Rejected(self.original_cause) from None
        return {"attempt_id": value["attempt_id"], "intent_sha256": digest(canonical(value)),
                "baseline_sha256": value["baseline_sha256"], "start_fenced": True}

    def _resume_current(self):
        if self.resume_records is None:
            return
        entries = set(os.listdir(self.journal.fd))
        if entries != self.resume_entries:
            raise Rejected("resume-journal-entries-changed")
        for name, (raw, before) in self.resume_records.items():
            current, after = read_file(self.journal.fd, name, limit=65536)
            if current != raw or signature(after) != before:
                raise Rejected("resume-original-record-changed")
        if canonical(self.journal.intent) != canonical(decode(self.resume_records["intent.json"][0])):
            raise Rejected("resume-original-intent-changed")

    def resume(self):
        """Recover a reopened same-boot intent; never resume candidate promotion.

        The caller retains the installation lock and supplies the independently
        authenticated recovery owner/boundary. This subset refuses prior dispatch,
        claim and staged/unknown state rather than adopting a possibly live worker.
        recovery_preflight must authenticate the package, policy and complete
        baseline and prove the independent listener before any mutating call. It
        must not infer ownership/quiescence from an old terminal or worker exit.
        This component does not install that owner, broker or complete host fence.
        """
        if (self.resume_attempted or self.started_forward or self.recovery_attempted
                or self.meter is not None or not self.journal.reopened or self.journal.intent is None):
            raise Rejected("resume-reopened-journal-required")
        self.resume_attempted = True
        self.journal.revoke_forward()
        self.original_cause = "restart-original-cause-unavailable"
        self.active_phase = "resume-inputs"
        try:
            if self.journal.uncertain:
                raise Rejected("resume-reopen-after-uncertainty-required")
            self.resume_entries = set(os.listdir(self.journal.fd))
            allowed = {"intent.json", "arm.json", "outcome.json", "recovery-outcome.json"}
            for name in self.resume_entries - allowed:
                if not (name.startswith("object-") and name.endswith(".json")
                        and OBJECT_ID.fullmatch(name[7:-5])):
                    raise Rejected("resume-state-reconciliation-required")
            records = {}
            for name in ("intent.json", "arm.json"):
                raw, info = read_file(self.journal.fd, name, limit=65536)
                if ((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                        != (os.geteuid(), os.getegid(), 0o600)):
                    raise Rejected("resume-private-original-record-required")
                records[name] = (raw, signature(info))
            intent = decode(records["intent.json"][0])
            validate_intent(intent)
            if canonical(intent) != canonical(self.journal.intent):
                raise Rejected("resume-original-intent-changed")
            record = decode(records["arm.json"][0])
            if (set(record) != {"schema", "arm", "intent_sha256"}
                    or record["schema"] != "host-recovery-arm-v1"
                    or record["intent_sha256"] != digest(canonical(intent))):
                raise Rejected("resume-original-arm-pin")
            arm = record["arm"]
            if (type(arm) is not dict or set(arm) != {"boot_id", "monotonic"}
                    or arm["boot_id"] != intent["owner"]["boot_id"] or not positive(arm["monotonic"])):
                raise Rejected("resume-original-arm-schema")
            self.resume_records = records
            self._resume_current()
            self.meter = Budget(intent["budget"], arm, self.clock, self.boot_id)
            # Unknown failure time is not zero detection overhead. Charge from t0,
            # including the detection cap; a late restart may already be too late.
            self.meter.trigger_recovery(arm["monotonic"])
            self.meter.events[-1]["failure_time_basis"] = "original_arm_lower_bound"
            self._confirmed(self._call("recovery", "detection", "recovery_preflight", intent))
        except Exception:
            self.recovery_attempted = True
            self.recovery_error = "recovery-" + self.active_phase + "-failed"
            self.result = {"outcome": "recovery_unresolved", "production_acceptance": False}
            self._alert()
            return self.status()
        return self.recover()

    def _call(self, direction, phase, method, *args):
        self.active_phase = phase
        self._resume_current()
        deadline = self.meter.phase_deadline(direction, phase)
        if direction == "forward":
            self.failure_since = self.meter.now()
        result = getattr(self.boundary, method)(*copy.deepcopy(args), deadline=deadline)
        self._resume_current()
        self.meter.check(deadline)
        self.meter.events.append({"phase": phase, "direction": direction,
                                  "event": "completed", "monotonic": self.meter.now()})
        return result

    @staticmethod
    def _confirmed(value):
        if value is not True:
            raise Rejected("boundary-operation-unconfirmed")

    def forward(self):
        log = self.journal
        if (self.meter is None or log.reopened or log.uncertain or log.armed is None
                or self.started_forward or self.recovery_attempted):
            raise Rejected("forward-not-authorized")
        self.started_forward = True
        intent = copy.deepcopy(log.intent)
        try:
            self._confirmed(self._call("forward", "stop", "quiesce", intent))
            self._confirmed(self._call("forward", "revalidate", "revalidate_stopped", intent))
            self._confirmed(self._call("forward", "mutate", "mutate", intent))
            # create_candidate must never start it. If the create reply is lost,
            # reconcile by the preassigned ownership ID, not a guessed short ID.
            self.active_phase = "candidate-start"
            deadline = self.meter.phase_deadline("forward", "candidate-start")
            self.failure_since = self.meter.now()
            try:
                self.boundary.create_candidate(copy.deepcopy(intent), deadline=deadline)
            except AmbiguousCreate:
                pass
            self.meter.check(deadline)
            objects = self._call("forward", "candidate-start", "owned_candidates", intent)
            if type(objects) is not list or len(objects) != 1:
                raise Rejected("ambiguous-candidate-create")
            record = objects[0]
            log.register(record)
            self.meter.check(deadline)
            if not log.can_start_candidate(record["object_id"]):
                raise Rejected("unregistered-candidate-start")
            self._confirmed(self._call("forward", "candidate-start", "start_candidate", intent, record))
            receipt = self._call("forward", "postchecks", "candidate_checks", intent, record)
            if (type(receipt) is not dict or set(receipt) != {"object_id", "image_id", "checks"}
                    or receipt["object_id"] != record["object_id"]
                    or receipt["image_id"] != intent["candidate_image_id"]
                    or type(receipt["checks"]) is not dict or set(receipt["checks"]) != CHECKS
                    or any(flag is not True for flag in receipt["checks"].values())):
                raise Rejected("candidate-postchecks-incomplete")
            self.active_phase = "persistence"
            deadline = self.meter.phase_deadline("forward", "persistence")
            self.failure_since = self.meter.now()
            log.finish("candidate_verified", receipt)
            self.meter.check(deadline)
            # This only authorizes the current invocation's verified running
            # object. The durable latch and the global startup fence remain.
            self.result = {"outcome": "candidate_verified", "production_acceptance": False}
        except Exception as failure:
            self.original_cause = "forward-" + self.active_phase + "-failed"
            return self.recover(failure.monotonic if isinstance(failure, ObservedFailure) else None)
        return self.status()

    def recover(self, failure_at=None):
        if self.recovery_attempted or self.meter is None:
            raise Rejected("separate-recovery-continuation-required")
        self.recovery_attempted = True
        self.journal.revoke_forward()
        intent = copy.deepcopy(self.journal.intent)
        self.original_cause = self.original_cause or "explicit-recovery-request"
        try:
            # ObservedFailure carries the manager's earlier raw failure event.
            # A missing timestamp is not evidence of zero detection overhead.
            self.active_phase = "detection"
            if self.meter.failure_at is None or failure_at is not None:
                basis = "manager_observed"
                if failure_at is None:
                    # A callback may fail long before returning control. Charge
                    # its entire uncertain interval, not zero detection time.
                    failure_at = self.meter.arm["monotonic"]
                    basis = "original_arm_lower_bound"
                    if self.original_cause.startswith("forward-") and self.failure_since is not None:
                        failure_at = self.failure_since
                        basis = "forward_boundary_entry_lower_bound"
                self.meter.trigger_recovery(failure_at)
                self.meter.events[-1]["failure_time_basis"] = basis
            receipt = recover_baseline(lambda phase, method, *args:
                self._call("recovery", phase, method, *args), intent)
            self.active_phase = "persistence"
            deadline = self.meter.phase_deadline("recovery", "persistence")
            self._resume_current()
            self.journal.finish("baseline_restored", receipt)
            if self.resume_entries is not None:
                self.resume_entries.add("recovery-outcome.json")
            self._resume_current()
            self.meter.check(deadline)
            self.result = {"outcome": "baseline_restored", "production_acceptance": False}
        except Exception:
            self.recovery_error = "recovery-" + self.active_phase + "-failed"
            self.result = {"outcome": "recovery_unresolved", "production_acceptance": False}
        # Even budget/receipt failure must not prevent the independent transport
        # attempt. Its concrete implementation must be nonblocking; this does
        # not add a notification allowance outside the engineering target.
        self._alert()
        return self.status()

    def _alert(self):
        deadline = None
        if self.meter is not None and self.meter.failure_at is not None:
            try:
                deadline = self.meter.phase_deadline("recovery", "alert")
            except Rejected:
                self.recovery_error = self.recovery_error or "alert-budget-or-clock-unavailable"
                self.result = {"outcome": "recovery_unresolved", "production_acceptance": False}
        notice = {"schema": "host-recovery-notice-v1", "attempt_id": self.journal.intent["attempt_id"] if self.journal.intent else None,
                  "original_cause": self.original_cause, "recovery_error": self.recovery_error,
                  "outcome": self.result["outcome"], "start_fenced": True}
        self.alert = notify(notice, self.persist_alert, self.transport_alert)
        if deadline is not None:
            try:
                self.meter.check(deadline)
            except Rejected:
                self.recovery_error = self.recovery_error or "alert-budget-or-clock-unavailable"
                self.result = {"outcome": "recovery_unresolved", "production_acceptance": False}
        if not self.alert["transport_delivered"]:
            self.recovery_error = self.recovery_error or "independent-alert-delivery-failed"
            self.result = {"outcome": "recovery_unresolved", "production_acceptance": False}

    def status(self):
        return {**self.result, "original_cause": self.original_cause, "recovery_error": self.recovery_error,
                "start_fenced": self.start_fenced, "journal_uncertain": self.journal.uncertain,
                "timing_events": copy.deepcopy(self.meter.events) if self.meter else [],
                "alert": copy.deepcopy(getattr(self, "alert", None))}
