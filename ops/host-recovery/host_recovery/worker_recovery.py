"""Original-request worker execution with separate recovery authority.

The supervisor keeps the installation lock; the worker never takes that lock or
writes the supervisor journal. A claim is identity only. The independently
provisioned boundary must authorize this exact claim/request, enforce the complete
host fence and validate the original package/baseline before recovery. Scripted
boundaries do not implement those requirements. No live defaults or installer.
"""
import copy
import os
import time

from .bootstrap import kernel_boot_id
from .budget import Budget
from .commands import Deadline
from .coordinator import recover_baseline
from .dispatch import validate_request
from .durable import Rejected, atomic_write, canonical, digest, notify, read_file
from .installation import DirectoryApproval, open_approved_directory
from .jobs import RecoveryJobBinding, validate_worker
from .journal import identity, validate_intent
from .loading import RecoveryApproval
from .supervisor import validate_owner


class WorkerEvidence:
    """One private evidence file, separate from the installation journal.

    This is a worker report, never a journal terminal or installation settlement.
    The independent supervisor oracle must read/authenticate it and inspect the
    actual baseline/readiness; a digest or a successful worker exit is not proof.
    """
    def __init__(self, directory, request_id, *, clock=time.monotonic, fault=None):
        if (not isinstance(directory, DirectoryApproval) or directory.mode != 0o700
                or (directory.uid, directory.gid) != (os.geteuid(), os.getegid())
                or type(request_id) is not str or len(request_id) != 64
                or any(c not in "0123456789abcdef" for c in request_id)):
            raise Rejected("worker-evidence-approval-required")
        self.directory, self.request_id = directory, request_id
        self.clock, self.fault, self.attempted = clock, fault, False

    def write(self, value, *, deadline, check):
        if self.attempted:
            raise Rejected("worker-evidence-exhausted")
        self.attempted = True
        timer = Deadline(self.clock, deadline)
        raw = canonical(value)
        expected = digest(raw)
        if value.get("request_id") != self.request_id:
            raise Rejected("worker-evidence-request-mismatch")
        name = "worker-evidence-" + self.request_id + ".json"
        stage = ".stage-" + name
        with open_approved_directory(self.directory) as directory:
            def current():
                timer.remaining()
                directory.validate()
                if check(deadline=deadline) is not True:
                    raise Rejected("worker-evidence-peer-unconfirmed")
                directory.validate()
                timer.remaining()
            current()
            if name in os.listdir(directory.fd) or stage in os.listdir(directory.fd):
                raise Rejected("worker-evidence-reconciliation-required")
            atomic_write(directory.fd, name, raw, stage_name=stage, fault=self.fault)
            current()
            again, _ = read_file(directory.fd, name)
            if again != raw:
                raise Rejected("worker-evidence-changed")
            directory.validate()
            timer.remaining()
        timer.remaining()
        return expected


class WorkerRecovery:
    """Once-only provider for the manager-bound client's recovery_provider path.

    authorize_worker_recovery(intent, request, claim, deadline=..., check=...)
    must authenticate independently provisioned execution approval for the exact
    original request/claim, all package/policy/baseline pins and the operational
    listener/fence. A True callback result is only its contract, NOT authority
    inferred from a claim or matching hashes. Every recovery method additionally
    receives check(deadline=...) and must call it at internal mutation/start
    barriers, including inside long restoration operations. It must enforce the
    supplied phase deadline while running, not just return before a later check.

    WorkerEvidence writes only the final worker report. No supervisor journal fd,
    new lock namespace, terminal commit, forward method or admission route exists.
    """
    def __init__(self, *, approval, binding, intent, request, boundary, evidence,
                 persist_alert, transport_alert, clock=time.monotonic, boot_id=kernel_boot_id):
        if (not isinstance(approval, RecoveryApproval) or not isinstance(binding, RecoveryJobBinding)
                or not isinstance(evidence, WorkerEvidence)
                or not all(callable(f) for f in (persist_alert, transport_alert, clock, boot_id))):
            raise Rejected("worker-recovery-explicit-boundaries-required")
        validate_intent(intent)
        if digest(canonical(intent)) != approval.intent_sha256:
            raise Rejected("worker-recovery-original-intent-required")
        for key in ("package_sha256", "manifest_sha256", "baseline_sha256", "policy_sha256",
                    "installation_id", "attempt_id"):
            if intent[key] != getattr(approval, key):
                raise Rejected("worker-recovery-approval-mismatch")
        if (evidence.request_id != binding.request_id
                or (approval.uid, approval.gid) != (os.geteuid(), os.getegid())):
            raise Rejected("worker-recovery-owner-mismatch")
        self.approval, self.binding = approval, binding
        self.intent, self.request = copy.deepcopy(intent), copy.deepcopy(request)
        self.boundary, self.evidence = boundary, evidence
        self.persist_alert, self.transport_alert = persist_alert, transport_alert
        self.clock, self.boot_id, self.attempted = clock, boot_id, False
        self.meter, self.phase, self.status = None, "detection", None

    def _inputs(self, claim):
        validate_request(self.request, self.binding, self.boot_id(), self.clock())
        request, intent = self.request, self.intent
        validate_owner(request["owner"])
        fields = {"schema", "request_id", "intent_sha256", "supervisor_owner", "worker", "peer", "nonce",
                  "restoration_permission", "start_permission"}
        if (type(claim) is not dict or set(claim) != fields
                or claim["schema"] != "host-recovery-worker-claim-v1"
                or claim["request_id"] != request["request_id"]
                or claim["intent_sha256"] != self.approval.intent_sha256
                or request["intent_sha256"] != self.approval.intent_sha256
                or request["attempt_id"] != intent["attempt_id"]
                or request["owner"]["installation_id"] != intent["installation_id"]
                or request["original_arm"]["boot_id"] != intent["owner"]["boot_id"]
                or canonical(claim["supervisor_owner"]) != canonical(request["owner"])
                or canonical(claim["peer"]) != canonical({"pid": os.getpid(), "uid": os.geteuid(), "gid": os.getegid()})
                or not identity(claim["nonce"]) or claim["restoration_permission"] is not False
                or claim["start_permission"] is not False):
            raise Rejected("worker-recovery-original-claim-required")
        validate_worker(claim["worker"], request["request_id"], self.boot_id(), os.getpid())
        if (claim["worker"]["unit"] == request["owner"]["unit"]
                or claim["worker"]["invocation_id"] == request["owner"]["invocation_id"]):
            raise Rejected("worker-recovery-separate-owner-required")

    def __call__(self, claim, *, deadline, check):
        if self.attempted or not callable(check):
            raise Rejected("worker-recovery-exhausted")
        self.attempted = True
        end = min(deadline, self.request["deadline"])
        timer = Deadline(self.clock, end)
        claim = copy.deepcopy(claim)
        self.status = {"outcome": "recovery_unresolved", "recovery_error": None,
                       "alert_error": None, "evidence_error": None,
                       "start_fenced": True, "installation_settled": False, "production_acceptance": False}
        receipt, revoked = None, False
        def current(*, deadline):
            nonlocal revoked
            try:
                if revoked or deadline > end:
                    raise Rejected("worker-recovery-original-deadline-required")
                timer.remaining()
                self.meter.check(deadline)
                if check(deadline=deadline) is not True:
                    raise Rejected("worker-recovery-peer-unconfirmed")
                self.meter.check(deadline)
                return True
            except BaseException:
                revoked = True
                raise
        def call(phase, method, *args):
            nonlocal revoked
            self.phase = phase
            bound = min(end, self.meter.phase_deadline("recovery", phase))
            active = True
            def phase_check(*, deadline):
                nonlocal revoked
                try:
                    if not active or deadline > bound:
                        raise Rejected("worker-recovery-phase-lease-unavailable")
                    return current(deadline=deadline)
                except BaseException:
                    revoked = True
                    raise
            try:
                phase_check(deadline=bound)
                value = getattr(self.boundary, method)(*copy.deepcopy(args), deadline=bound, check=phase_check)
                phase_check(deadline=bound)
                self.meter.events.append({"phase": phase, "direction": "recovery", "event": "completed",
                                          "monotonic": self.meter.now()})
                return copy.deepcopy(value)
            finally:
                active = False
        try:
            timer.remaining()
            self._inputs(claim)
            self.meter = Budget(self.intent["budget"], self.request["original_arm"], self.clock, self.boot_id)
            self.meter.trigger_recovery(self.request["failure_lower_bound"])
            self.meter.events[-1]["failure_time_basis"] = "original_request_lower_bound"
            if call("detection", "authorize_worker_recovery", self.intent, self.request, claim) is not True:
                raise Rejected("worker-recovery-authority-unconfirmed")
            receipt = recover_baseline(call, copy.deepcopy(self.intent))
            self.status["outcome"] = "baseline_restored"
        except Exception:
            self.status["recovery_error"] = "recovery-" + self.phase + "-failed"
        # Transport is attempted even after peer, clock, authority or disk failure.
        # Its own bounded implementation is independent of this peer connection.
        self.phase = "alert"
        alert_end = None
        try:
            if self.meter is None:
                raise Rejected("worker-recovery-budget-unavailable")
            alert_end = min(end, self.meter.phase_deadline("recovery", "alert"))
        except Exception:
            self.status.update(outcome="recovery_unresolved",
                               recovery_error=self.status["recovery_error"] or "alert-budget-or-clock-unavailable")
        notice = {"schema": "host-recovery-notice-v1", "attempt_id": self.approval.attempt_id,
                  "original_cause": "supervisor-restart-recovery-required",
                  "recovery_error": self.status["recovery_error"], "outcome": "recovery_unresolved", "start_fenced": True}
        self.status["alert"] = notify(notice, self.persist_alert, self.transport_alert)
        try:
            if alert_end is None:
                raise Rejected("worker-recovery-alert-unconfirmed")
            self.meter.check(alert_end)
            if not self.status["alert"]["transport_delivered"]:
                self.status["alert_error"] = "independent-alert-delivery-failed"
                raise Rejected("worker-recovery-alert-unconfirmed")
            self.phase = "persistence"
            bound = min(end, self.meter.phase_deadline("recovery", "persistence"))
            current(deadline=bound)
            report = {"schema": "host-recovery-worker-evidence-v1", "request_id": self.request["request_id"],
                      "intent_sha256": self.approval.intent_sha256, "claim_sha256": digest(canonical(claim)),
                      "status": copy.deepcopy(self.status), "stopped_receipt": receipt,
                      "timing_events": copy.deepcopy(self.meter.events), "worker_report_only": True,
                      "start_permission": False, "recovery_completed": False, "installation_settled": False}
            sha256 = self.evidence.write(report, deadline=bound, check=current)
            current(deadline=bound)
            return {"outcome": self.status["outcome"], "evidence_sha256": sha256}
        except Exception:
            # Visible evidence after failed fsync/readback is not a usable report.
            # Keep the first recovery failure; delivery and evidence persistence
            # are separate failures, never evidence that the original cause changed.
            if self.phase == "alert":
                error = self.status["alert_error"] or "alert-budget-or-clock-unavailable"
                self.status["alert_error"] = error
            else:
                error = "recovery-" + self.phase + "-failed"
                self.status["evidence_error"] = error
            self.status.update(outcome="recovery_unresolved",
                               recovery_error=self.status["recovery_error"] or error)
            notify({**notice, "outcome": "recovery_unresolved", "recovery_error": self.status["recovery_error"]},
                   self.persist_alert, self.transport_alert)
            raise Rejected("worker-recovery-report-unconfirmed") from None
