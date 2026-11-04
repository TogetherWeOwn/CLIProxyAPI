"""Real restoration/evidence files; SCRIPTED execution authority/manager/oracle."""
import copy
from dataclasses import replace
import errno
import os
from pathlib import Path
import pwd
import tempfile
import unittest

from host_recovery import alert, durable, inventory, jobs, loading, worker, worker_recovery
from test_installation import approve
import test_coordinator


class Boundary(test_coordinator.Boundary):
    def authorize_worker_recovery(self, intent, request, claim, *, deadline, check):
        self.test.assertEqual(request, self.test.request)
        self.test.assertEqual(claim, self.test.claim)
        return self.event("authorize", deadline)

    def __getattribute__(self, name):
        value = super().__getattribute__(name)
        if name in super().__getattribute__("__dict__"):
            return value
        if name in {"authorize_worker_recovery", "fence", "quiesce", "validate_recovery", "restore_complete",
                    "verify_baseline_stopped", "start_old", "old_ready"}:
            def leased(*args, deadline, check):
                self.test.assertTrue(check(deadline=deadline))
                if name == "authorize_worker_recovery":
                    result = value(*args, deadline=deadline, check=check)
                else:
                    result = value(*args, deadline=deadline)
                self.test.assertTrue(check(deadline=deadline))
                return result
            return leased
        return value


class WorkerRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.case = test_coordinator.CoordinatorTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.case.admit()
        self.intent = self.case.log.intent
        self.case.file.write_bytes(b"partial-candidate")
        self.case.time = 1005.
        self.request = {"schema": "host-recovery-reconcile-request-v1", "attempt_id": self.intent["attempt_id"],
            "intent_sha256": durable.digest(durable.canonical(self.intent)), "owner": copy.deepcopy(self.intent["owner"]),
            "original_arm": {"boot_id": self.case.boot, "monotonic": 1000.}, "failure_lower_bound": 1000.,
            "deadline": 1100., "detection_upper_bound_seconds": 5., "forward_allowed": False,
            "production_acceptance": False}
        self.request["owner"]["invocation_id"] = "a" * 32
        self.request["request_id"] = durable.digest(durable.canonical(self.request))
        self.binding = jobs.RecoveryJobBinding(self.request["request_id"], "/synthetic/unit", "e" * 64, "f" * 64)
        self.claim = {"schema": "host-recovery-worker-claim-v1", "request_id": self.binding.request_id,
            "intent_sha256": self.request["intent_sha256"], "supervisor_owner": self.request["owner"],
            "worker": {"schema": "host-recovery-job-observation-v1", "request_id": self.binding.request_id,
                "boot_id": self.case.boot, "unit": jobs.recovery_unit(self.binding.request_id),
                "invocation_id": "b" * 32, "state": "running", "job_id": 0,
                "pid": os.getpid(), "cgroup": "/scripted/recovery.service"},
            "peer": {"pid": os.getpid(), "uid": os.geteuid(), "gid": os.getegid()}, "nonce": "nonce",
            "restoration_permission": False, "start_permission": False}
        keys = ("package_sha256", "manifest_sha256", "baseline_sha256", "policy_sha256", "installation_id", "attempt_id")
        self.approval = loading.RecoveryApproval(self.request["intent_sha256"],
            **{k: self.intent[k] for k in keys}, uid=os.geteuid(), gid=os.getegid())
        temp = tempfile.TemporaryDirectory(prefix=".worker-recovery-", dir=pwd.getpwuid(os.geteuid()).pw_dir)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.evidence = worker_recovery.WorkerEvidence(approve(self.root), self.binding.request_id,
                                                       clock=lambda: self.case.time)
        self.boundary = Boundary(self.case)
        self.case.request, self.case.claim = self.request, self.claim
        self.notices, self.checked = [], []
        self.peer_ok = True
        self.engine = self.make()
        # The reused restoration fixture checks the current meter through engine.
        self.case.engine = self.engine

    def make(self, **changes):
        args = dict(approval=self.approval, binding=self.binding, intent=self.intent, request=self.request,
                    boundary=self.boundary, evidence=self.evidence, persist_alert=self.case.persist_alert,
                    transport_alert=self.transport, clock=lambda: self.case.time, boot_id=lambda: self.case.boot)
        args.update(changes)
        return worker_recovery.WorkerRecovery(**args)

    def transport(self, notice):
        alert.validate_notice(notice)
        self.notices.append(copy.deepcopy(notice))
        return self.case.transport_ok

    def check(self, *, deadline):
        self.checked.append(deadline)
        return self.peer_ok

    def run_recovery(self, **changes):
        args = dict(deadline=1100., check=self.check)
        args.update(changes)
        return self.engine(self.claim, **args)

    def report(self):
        return durable.decode((self.root / ("worker-evidence-" + self.binding.request_id + ".json")).read_bytes())

    def test_original_sequence_restores_and_reports_without_touching_supervisor_journal(self):
        before = {p.name: p.read_bytes() for p in self.case.state.iterdir()}
        result = self.run_recovery()
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertEqual(self.boundary.calls, ["authorize", "fence", "quiesce", "validate-recovery", "restore",
                                              "baseline-oracle", "start-old", "old-ready"])
        self.assertEqual(inventory.snapshot(self.case.tree_fd, uid=os.geteuid(), gid=os.getegid()),
                         (self.case.tree, self.case.blobs))
        raw = durable.canonical(self.report())
        self.assertEqual(result["evidence_sha256"], durable.digest(raw))
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.case.state.iterdir()})
        self.assertFalse(self.report()["installation_settled"])
        self.assertFalse(self.report()["recovery_completed"])
        self.assertFalse(self.report()["start_permission"])
        self.assertEqual(self.notices[0]["outcome"], "recovery_unresolved")
        self.assertEqual(self.engine.meter.arm["monotonic"], 1000.)
        self.assertEqual(self.engine.meter.phase_ends[("recovery", "detection")], 1020.)
        self.assertTrue(all(d <= 1100. for d in self.checked))
        with self.assertRaises(durable.Rejected):
            self.run_recovery()

    def test_identity_claim_never_replaces_separate_execution_authority(self):
        for authority in (False, 1, None):
            with self.subTest(authority=authority):
                self.setUp()
                self.boundary.overrides["authorize"] = authority
                result = self.run_recovery()
                self.assertEqual(result["outcome"], "recovery_unresolved")
                self.assertEqual(self.boundary.calls, ["authorize"])
                self.assertEqual(self.case.file.read_bytes(), b"partial-candidate")

    def test_every_boundary_failure_blocks_later_start_and_remains_unresolved(self):
        for phase in ("fence", "quiesce", "validate-recovery", "restore", "baseline-oracle", "start-old", "old-ready"):
            with self.subTest(phase=phase):
                self.setUp()
                self.boundary.overrides[phase] = False
                self.assertEqual(self.run_recovery()["outcome"], "recovery_unresolved")
                if phase not in ("start-old", "old-ready"):
                    self.assertNotIn("start-old", self.boundary.calls)
                self.assertFalse(self.report()["recovery_completed"])
                self.assertTrue(self.notices)

    def test_peer_loss_after_restore_refuses_before_old_start_and_sends_alert(self):
        def lost():
            self.peer_ok = False
            return True
        self.boundary.overrides["restore"] = lost
        with self.assertRaises(durable.Rejected):
            self.run_recovery()
        self.assertNotIn("start-old", self.boundary.calls)
        self.assertTrue(self.notices)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_swallowed_transient_lease_failure_is_sticky(self):
        def authority(*args, deadline, check):
            self.peer_ok = False
            with self.assertRaises(durable.Rejected):
                check(deadline=deadline)
            self.peer_ok = True
            return True
        self.boundary.authorize_worker_recovery = authority
        with self.assertRaises(durable.Rejected):
            self.run_recovery()
        self.assertNotIn("fence", self.boundary.calls)

    def test_expired_cross_boot_and_regressed_clock_never_authorize(self):
        for time, boot in ((1100., "boot-a"), (1020., "boot-a"), (999., "boot-a"), (1005., "boot-b")):
            with self.subTest(time=time, boot=boot):
                self.setUp()
                self.case.time, self.case.boot = time, boot
                if time == 1020. and boot == "boot-a":
                    self.assertEqual(self.run_recovery()["outcome"], "recovery_unresolved")
                else:
                    with self.assertRaises(durable.Rejected):
                        self.run_recovery()
                self.assertEqual(self.boundary.calls, [])
                self.assertTrue(self.notices)

    def test_changed_request_claim_or_grant_never_runs_authority(self):
        for key, value in (("request_id", "e" * 64), ("intent_sha256", "e" * 64),
                           ("restoration_permission", True), ("start_permission", True)):
            with self.subTest(key=key):
                self.setUp()
                self.claim[key] = value
                with self.assertRaises(durable.Rejected):
                    self.run_recovery()
                self.assertEqual(self.boundary.calls, [])
                self.assertTrue(self.notices)

    def test_readiness_clock_or_boot_loss_cannot_create_success_report(self):
        for mutation in (lambda: setattr(self.case, "time", 1100.), lambda: setattr(self.case, "boot", "boot-b")):
            with self.subTest(mutation=mutation):
                self.setUp()
                self.boundary.overrides["old-ready"] = lambda: mutation() or True
                with self.assertRaises(durable.Rejected):
                    self.run_recovery()
                self.assertEqual(list(self.root.iterdir()), [])
                self.assertTrue(self.notices)

    def test_storage_faults_reach_exact_hook_and_never_return_report(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point):
                    self.setUp()
                    reached = []
                    def fault(hook):
                        if hook == point:
                            reached.append(hook)
                            raise OSError(code, "injected")
                    self.evidence.fault = fault
                    self.case.receipt_fault = True
                    with self.assertRaises(durable.Rejected):
                        self.run_recovery()
                    self.assertEqual(reached, [point])
                    self.assertTrue(self.notices)
                    self.assertEqual(self.engine.status["outcome"], "recovery_unresolved")
                    with self.assertRaises(durable.Rejected):
                        self.run_recovery()

    def test_retained_evidence_and_staging_are_not_overwritten(self):
        for prefix in ("worker-evidence-", ".stage-worker-evidence-"):
            with self.subTest(prefix=prefix):
                self.setUp()
                path = self.root / (prefix + self.binding.request_id + ".json")
                path.write_bytes(b"ambiguous")
                with self.assertRaises(durable.Rejected):
                    self.run_recovery()
                self.assertEqual(path.read_bytes(), b"ambiguous")

    def test_alert_loss_refuses_report_and_preserves_local_fence(self):
        self.case.transport_ok = False
        with self.assertRaises(durable.Rejected):
            self.run_recovery()
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(self.engine.status["outcome"], "recovery_unresolved")
        self.assertFalse(self.engine.status["installation_settled"])

    def test_internal_callback_cannot_expand_its_phase_to_original_request_deadline(self):
        reached, accepted = [], []
        def restore(*args, deadline, check):
            reached.append(deadline)
            try:
                check(deadline=1100.)
            except durable.Rejected:
                pass
            else:
                accepted.append(True)
            return True
        self.boundary.restore_complete = restore
        try:
            self.run_recovery()
        except durable.Rejected:
            pass
        self.assertEqual(reached, [1025.])
        self.assertEqual(accepted, [])
        self.assertNotIn("start-old", self.boundary.calls)

    def test_retained_phase_callback_is_revoked_before_next_operation(self):
        saved, reached, accepted = [], [], []
        original = self.boundary.authorize_worker_recovery
        def authorize(*args, deadline, check):
            saved.append(check)
            return original(*args, deadline=deadline, check=check)
        self.boundary.authorize_worker_recovery = authorize
        original_fence = self.boundary.fence
        def fence(*args, deadline, check):
            reached.append(deadline)
            try:
                saved[0](deadline=deadline)
            except durable.Rejected:
                pass
            else:
                accepted.append(True)
            return original_fence(*args, deadline=deadline, check=check)
        self.boundary.fence = fence
        try:
            self.run_recovery()
        except durable.Rejected:
            pass
        self.assertEqual(reached, [1020.])
        self.assertEqual(accepted, [])
        self.assertNotIn("start-old", self.boundary.calls)

    def test_client_requires_live_independent_verifier_before_executing_provider(self):
        client = worker.WorkerClient("/synthetic/socket", supervisor_uid=os.geteuid(), supervisor_pid=os.getpid() + 1,
            supervisor_owner=self.request["owner"], request_id=self.binding.request_id,
            intent_sha256=self.approval.intent_sha256, clock=lambda: self.case.time)
        with self.assertRaises(durable.Rejected):
            client.claim(deadline=1100., recovery_provider=self.engine)
        self.assertFalse(self.engine.attempted)
        self.assertEqual(self.boundary.calls, [])
        with self.assertRaises(durable.Rejected):
            client.claim(deadline=1100., recovery_provider=self.engine, result_provider=lambda *a, **kw: None)

    def test_delivery_failure_is_not_misreported_as_clock_or_budget_failure(self):
        for raises in (False, True):
            with self.subTest(raises=raises):
                self.setUp()
                if raises:
                    def transport(notice):
                        self.notices.append(copy.deepcopy(notice))
                        raise OSError(errno.EIO, "synthetic alert route unavailable")
                    self.engine.transport_alert = transport
                else:
                    self.case.transport_ok = False
                with self.assertRaises(durable.Rejected):
                    self.run_recovery()
                self.assertEqual(self.case.time, 1005.)
                self.assertEqual(self.engine.status["recovery_error"], "independent-alert-delivery-failed")
                self.assertEqual(self.notices[-1]["recovery_error"], "independent-alert-delivery-failed")
                self.assertEqual(self.engine.status["alert_error"], "independent-alert-delivery-failed")
                self.assertIsNone(self.engine.status["evidence_error"])

    def test_alert_failure_preserves_earlier_restore_error_in_status_and_notice(self):
        self.boundary.overrides["restore"] = False
        self.case.transport_ok = False
        with self.assertRaises(durable.Rejected):
            self.run_recovery()
        self.assertEqual(self.engine.status["recovery_error"], "recovery-restore-failed")
        self.assertEqual(self.engine.status["alert_error"], "independent-alert-delivery-failed")
        self.assertEqual(self.notices[-1]["recovery_error"], "recovery-restore-failed")
        self.assertNotIn("start-old", self.boundary.calls)

    def test_evidence_failure_preserves_earlier_restore_error(self):
        self.boundary.overrides["restore"] = False
        reached = []
        def fault(hook):
            if hook == "create":
                reached.append(hook)
                raise OSError(errno.ENOSPC, "synthetic full evidence store")
        self.evidence.fault = fault
        with self.assertRaises(durable.Rejected):
            self.run_recovery()
        self.assertEqual(reached, ["create"])
        self.assertEqual(self.engine.status["recovery_error"], "recovery-restore-failed")
        self.assertEqual(self.engine.status["evidence_error"], "recovery-persistence-failed")
        self.assertEqual(self.notices[-1]["recovery_error"], "recovery-restore-failed")

    def test_actual_alert_phase_overrun_still_reports_budget_failure(self):
        original = self.engine.transport_alert
        def transport(notice):
            result = original(notice)
            self.case.time = 1025.
            return result
        self.engine.transport_alert = transport
        with self.assertRaises(durable.Rejected):
            self.run_recovery()
        self.assertEqual(self.engine.status["recovery_error"], "alert-budget-or-clock-unavailable")
        self.assertEqual(self.engine.status["alert_error"], "alert-budget-or-clock-unavailable")
        self.assertTrue(self.engine.status["alert"]["transport_delivered"])

    def test_approval_and_evidence_owner_mismatches_refuse(self):
        for changes in ({"approval": replace(self.approval, intent_sha256="e" * 64)},
                        {"binding": replace(self.binding, request_id="e" * 64)}):
            with self.subTest(changes=changes), self.assertRaises(durable.Rejected):
                self.make(**changes)
