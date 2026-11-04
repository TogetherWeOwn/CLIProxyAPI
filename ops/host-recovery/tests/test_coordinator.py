"""Mock manager/daemon ordering only. No unit, container or availability proof."""
import copy
import errno
import os
from pathlib import Path
import tempfile
import unittest

from host_recovery import coordinator, durable, inventory, journal, restore
from test_recovery_state import candidate, intent


class Boundary:
    def __init__(self, test):
        self.test = test
        self.calls = []
        self.overrides = {}
        self.created = []
        self.create_reply_lost = False

    def event(self, name, deadline, default=True):
        self.calls.append(name)
        if deadline is not None:
            self.test.assertGreater(deadline, self.test.time)
        value = self.overrides.get(name, default)
        if callable(value):
            return value()
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)

    def preflight(self, value):
        return self.event("preflight", None)

    def quiesce(self, value, *, deadline):
        return self.event("quiesce", deadline)

    def revalidate_stopped(self, value, *, deadline):
        return self.event("revalidate", deadline)

    def mutate(self, value, *, deadline):
        result = self.event("mutate", deadline)
        self.test.file.write_bytes(b"partial-candidate-config")
        return result

    def create_candidate(self, value, *, deadline):
        self.event("create", deadline)
        self.created = [candidate(value)]
        if self.create_reply_lost:
            raise coordinator.AmbiguousCreate()

    def owned_candidates(self, value, *, deadline):
        return self.event("owned", deadline, self.created)

    def start_candidate(self, value, record, *, deadline):
        self.test.assertTrue(self.test.log.can_start_candidate(record["object_id"]))
        self.test.assertTrue((self.test.state / ("object-" + record["object_id"] + ".json")).exists())
        return self.event("start-candidate", deadline)

    def candidate_checks(self, value, record, *, deadline):
        return self.event("postchecks", deadline, {"object_id": record["object_id"],
                          "image_id": value["candidate_image_id"],
                          "checks": dict.fromkeys(coordinator.CHECKS, True)})

    def fence(self, value, *, deadline):
        return self.event("fence", deadline)

    def validate_recovery(self, value, *, deadline):
        return self.event("validate-recovery", deadline)

    def restore_complete(self, value, *, deadline):
        result = self.event("restore", deadline)
        if result is True:
            restore.restore_tree(self.test.tree_fd, self.test.tree, self.test.blobs, {},
                                 check=lambda: self.test.engine.meter.check(deadline))
        return result

    def verify_baseline_stopped(self, value, *, deadline):
        got = inventory.snapshot(self.test.tree_fd, uid=os.geteuid(), gid=os.getegid())
        self.test.assertEqual(got, (self.test.tree, self.test.blobs))
        receipt = {"baseline_sha256": value["baseline_sha256"], "object_id": value["old_object_id"],
                   "original_image": True, "original_replay": True, "new_plugin_absent": True,
                   "complete_write_set": True, "metadata_verified": True, "all_writers_stopped": True}
        return self.event("baseline-oracle", deadline, receipt)

    def start_old(self, value, receipt, *, deadline):
        self.test.assertIn("baseline-oracle", self.calls)
        self.test.assertEqual(self.test.file.read_bytes(), b"original-baseline-config")
        return self.event("start-old", deadline)

    def old_ready(self, value, *, deadline):
        return self.event("old-ready", deadline)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="host-recovery-ordering-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.state = root / "state"
        self.state.mkdir(mode=0o700)
        self.source = root / "source"
        self.source.mkdir(mode=0o700)
        self.file = self.source / "config.yaml"
        self.file.write_bytes(b"original-baseline-config")
        self.file.chmod(0o600)
        self.tree_fd = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.tree_fd)
        self.tree, self.blobs = inventory.snapshot(self.tree_fd, uid=os.geteuid(), gid=os.getegid())
        self.lock = durable.installation_lock(self.state, intent()["owner"])
        fd, _ = self.lock.__enter__()
        self.addCleanup(self.lock.__exit__, None, None, None)
        self.log = journal.Journal(fd)
        self.time, self.boot = 1000.0, "boot-a"
        self.boundary = Boundary(self)
        self.notices = []
        self.receipt_fault = False
        self.transport_ok = True
        self.engine = coordinator.AttemptCoordinator(self.log, self.boundary, lambda: self.time, lambda: self.boot,
                                                     self.persist_alert, self.transport)

    def persist_alert(self, notice):
        if self.receipt_fault:
            raise OSError(errno.ENOSPC, "injected")

    def transport(self, notice):
        self.notices.append(notice)
        return self.transport_ok

    def admit(self):
        value = intent()
        value["baseline_sha256"] = durable.digest(durable.canonical(self.tree))
        return self.engine.admit(value)

    def test_arm_and_registration_precede_first_stop_and_start(self):
        ack = self.admit()
        self.assertTrue(ack["start_fenced"])
        self.assertEqual(self.boundary.calls, ["preflight"])
        self.assertTrue((self.state / "intent.json").exists())
        self.assertTrue((self.state / "arm.json").exists())
        result = self.engine.forward()
        self.assertEqual(result["outcome"], "candidate_verified")
        self.assertTrue(result["start_fenced"])
        self.assertEqual(self.boundary.calls, ["preflight", "quiesce", "revalidate", "mutate", "create",
                                               "owned", "start-candidate", "postchecks"])
        with self.assertRaises(durable.Rejected):
            self.engine.forward()

    def test_lost_create_reply_reconciles_before_registration_and_start(self):
        self.admit()
        self.boundary.create_reply_lost = True
        self.assertEqual(self.engine.forward()["outcome"], "candidate_verified")
        self.assertEqual(len(self.log.registered), 1)

    def test_non_ambiguous_create_error_cannot_be_overridden_by_green_inspection(self):
        self.admit()
        self.boundary.overrides["create"] = OSError("create rejected")
        self.boundary.overrides["owned"] = [candidate(intent())]
        result = self.engine.forward()
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertNotIn("owned", self.boundary.calls)
        self.assertNotIn("start-candidate", self.boundary.calls)

    def test_multiple_owned_candidates_refuse_candidate_start_and_recover(self):
        self.admit()
        row = candidate(intent())
        self.boundary.overrides["owned"] = [row, {**row, "object_id": "0" * 64}]
        result = self.engine.forward()
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertNotIn("start-candidate", self.boundary.calls)
        self.assertEqual(result["original_cause"], "forward-candidate-start-failed")
        self.assertEqual(self.file.read_bytes(), b"original-baseline-config")

    def test_missing_listener_refuses_admission_without_disk_or_stop(self):
        self.boundary.overrides["preflight"] = False
        with self.assertRaises(durable.Rejected):
            self.admit()
        self.assertEqual(os.listdir(self.state), [])
        self.assertEqual(self.boundary.calls, ["preflight"])

    def test_arm_disk_failure_aborts_unchanged_and_independent_transport_is_attempted(self):
        def fail(point):
            if point == "directory-fsync":
                raise OSError(errno.EIO, "injected")
        self.log.fault = fail
        self.receipt_fault = True
        with self.assertRaises(durable.Rejected):
            self.admit()
        self.assertEqual(self.boundary.calls, ["preflight"])
        self.assertEqual(self.file.read_bytes(), b"original-baseline-config")
        self.assertEqual(len(self.notices), 1)
        self.assertFalse(self.engine.alert["receipt_persisted"])
        self.assertTrue(self.engine.alert["transport_delivered"])

    def test_all_recovery_boundary_failures_keep_start_fenced_and_do_not_claim_restored(self):
        for point in ("fence", "quiesce", "validate-recovery", "restore", "baseline-oracle", "start-old", "old-ready"):
            with self.subTest(point=point):
                self.setUp()
                self.admit()
                self.boundary.overrides["postchecks"] = None
                self.boundary.overrides[point] = OSError("restricted data must not escape")
                # A quiescence failure in the forward path must also fail recovery.
                result = self.engine.forward()
                self.assertEqual(result["outcome"], "recovery_unresolved")
                self.assertTrue(result["start_fenced"])
                self.assertNotIn("restricted data", str(result))
                self.assertEqual(len(self.notices), 1)
                if point in ("fence", "quiesce", "validate-recovery", "restore", "baseline-oracle"):
                    self.assertNotIn("start-old", self.boundary.calls)
                if point in ("fence", "quiesce"):
                    self.assertNotIn("restore", self.boundary.calls)

    def test_incomplete_postchecks_trigger_full_restoration_before_old_start(self):
        self.admit()
        self.boundary.overrides["postchecks"] = {"checks": {"replay": True}}
        result = self.engine.forward()
        self.assertEqual(result["outcome"], "baseline_restored")
        calls = self.boundary.calls
        self.assertLess(calls.index("fence"), calls.index("restore"))
        self.assertLess(calls.index("restore"), calls.index("baseline-oracle"))
        self.assertLess(calls.index("baseline-oracle"), calls.index("start-old"))
        self.assertTrue(result["alert"]["transport_delivered"])
        self.assertTrue((self.state / "intent.json").exists())

    def test_false_green_or_incomplete_baseline_oracle_never_starts_old(self):
        for update in ({"original_replay": 1}, {"new_plugin_absent": False}, {"object_id": "0" * 64},
                       {"all_writers_stopped": False}, {"baseline_sha256": "0" * 64}, {"extra": True}):
            with self.subTest(update=update):
                self.setUp()
                self.admit()
                self.boundary.overrides["postchecks"] = None
                def oracle():
                    value = self.log.intent
                    return {"baseline_sha256": value["baseline_sha256"], "object_id": value["old_object_id"],
                            "original_image": True, "original_replay": True, "new_plugin_absent": True,
                            "complete_write_set": True, "metadata_verified": True, "all_writers_stopped": True, **update}
                self.boundary.overrides["baseline-oracle"] = oracle
                self.assertEqual(self.engine.forward()["outcome"], "recovery_unresolved")
                self.assertNotIn("start-old", self.boundary.calls)

    def test_candidate_terminal_failure_recovers_and_preserves_original_intent(self):
        self.admit()
        original = (self.state / "intent.json").read_bytes()
        def fail_once(point):
            if point == "directory-fsync":
                self.log.fault = None
                raise OSError(errno.ENOSPC, "injected")
        def postchecks():
            self.log.fault = fail_once
            return {"object_id": "a" * 64, "image_id": "f" * 64, "checks": dict.fromkeys(coordinator.CHECKS, True)}
        self.boundary.overrides["postchecks"] = postchecks
        result = self.engine.forward()
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertTrue(result["journal_uncertain"])
        self.assertTrue(result["start_fenced"])
        self.assertEqual(result["original_cause"], "forward-persistence-failed")
        self.assertEqual((self.state / "intent.json").read_bytes(), original)
        self.assertTrue((self.state / "outcome.json").exists())
        self.assertTrue((self.state / "recovery-outcome.json").exists())
        self.assertIsNone(journal.Journal(self.log.fd).terminal)

    def test_recovery_terminal_failure_never_reports_rolled_back(self):
        self.admit()
        self.boundary.overrides["postchecks"] = None
        def ready():
            def fail(point):
                raise OSError(errno.EIO, "injected")
            self.log.fault = fail
            return True
        self.boundary.overrides["old-ready"] = ready
        self.receipt_fault = True
        result = self.engine.forward()
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertEqual(result["recovery_error"], "recovery-persistence-failed")
        self.assertIsNone(self.log.terminal)
        self.assertTrue(result["alert"]["transport_delivered"])
        self.assertFalse(result["alert"]["receipt_persisted"])

    def test_listener_loss_after_arm_is_explicit_not_delivery_success(self):
        self.admit()
        self.boundary.overrides["postchecks"] = None
        self.transport_ok = False
        result = self.engine.forward()
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertEqual(result["recovery_error"], "independent-alert-delivery-failed")
        self.assertFalse(result["alert"]["transport_delivered"])

    def test_boot_change_fences_no_old_start_and_no_budget_reset(self):
        self.admit()
        self.boot, self.time = "boot-b", 1
        result = self.engine.forward()
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertEqual(self.engine.meter.arm["monotonic"], 1000)
        self.assertNotIn("mutate", self.boundary.calls)
        self.assertNotIn("start-old", self.boundary.calls)
        with self.assertRaises(durable.Rejected):
            self.engine.recover()

    def test_late_detector_accounts_from_manager_observed_failure(self):
        self.admit()
        def delayed():
            self.time = 1018
            raise coordinator.ObservedFailure(1002)
        self.boundary.overrides["quiesce"] = delayed
        result = self.engine.forward()
        event = next(e for e in result["timing_events"] if e["phase"] == "recovery-trigger")
        self.assertEqual(event["failure_at"], 1002)
        self.assertEqual(event["detection_seconds"], 16)

    def test_unknown_failure_time_charges_from_forward_boundary_entry(self):
        self.admit()
        def stopped():
            self.boundary.overrides.pop("quiesce")
            self.time = 1002
            return True
        self.boundary.overrides["quiesce"] = stopped
        reached = []
        def delayed():
            reached.append("revalidate")
            self.time = 1005
            raise OSError(errno.EIO, "injected")
        self.boundary.overrides["revalidate"] = delayed
        result = self.engine.forward()
        event = next(e for e in result["timing_events"] if e["phase"] == "recovery-trigger")
        self.assertEqual(reached, ["revalidate"])
        self.assertEqual(event["failure_at"], 1002)
        self.assertEqual(event["detection_seconds"], 3)
        self.assertEqual(event["failure_time_basis"], "forward_boundary_entry_lower_bound")

    def test_delayed_generic_failure_cannot_reset_detection_cap(self):
        self.admit()
        def delayed():
            self.time = 1025
            raise OSError(errno.EIO, "injected")
        self.boundary.overrides["revalidate"] = delayed
        result = self.engine.forward()
        self.assertIn("revalidate", self.boundary.calls)
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertNotIn("restore", self.boundary.calls)
        self.assertNotIn("start-old", self.boundary.calls)
        self.assertEqual(len(self.notices), 1)

    def test_delayed_ambiguous_create_cannot_reset_detection_cap(self):
        self.admit()
        def delayed():
            self.time = 1025
            raise coordinator.AmbiguousCreate()
        self.boundary.overrides["create"] = delayed
        result = self.engine.forward()
        self.assertIn("create", self.boundary.calls)
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertNotIn("owned", self.boundary.calls)
        self.assertNotIn("restore", self.boundary.calls)
        self.assertNotIn("start-old", self.boundary.calls)
        self.assertTrue(result["start_fenced"])

    def test_delayed_terminal_fsync_cannot_reset_detection_cap(self):
        self.admit()
        reached = []
        def delayed(point):
            if point == "directory-fsync":
                reached.append(point)
                self.log.fault = None
                self.time = 1025
                raise OSError(errno.ENOSPC, "injected")
        def postchecks():
            self.log.fault = delayed
            return {"object_id": "a" * 64, "image_id": "f" * 64,
                    "checks": dict.fromkeys(coordinator.CHECKS, True)}
        self.boundary.overrides["postchecks"] = postchecks
        result = self.engine.forward()
        self.assertEqual(reached, ["directory-fsync"])
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertTrue(result["journal_uncertain"])
        self.assertNotIn("restore", self.boundary.calls)
        self.assertNotIn("start-old", self.boundary.calls)
        self.assertTrue(result["alert"]["transport_delivered"])

    def test_explicit_recovery_without_failure_observation_charges_original_arm(self):
        self.admit()
        self.time = 1005
        result = self.engine.recover()
        event = next(e for e in result["timing_events"] if e["phase"] == "recovery-trigger")
        self.assertEqual(event["failure_at"], 1000)
        self.assertEqual(event["detection_seconds"], 5)
        self.assertEqual(event["failure_time_basis"], "original_arm_lower_bound")

    def test_unmetered_quiescence_overrun_cannot_reach_restore(self):
        self.admit()
        self.boundary.overrides["postchecks"] = None
        def overrun():
            self.time = 1030
            return True
        self.boundary.overrides["fence"] = overrun
        result = self.engine.forward()
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertNotIn("restore", self.boundary.calls)
        self.assertNotIn("start-old", self.boundary.calls)
        self.assertEqual(len(self.notices), 1)
