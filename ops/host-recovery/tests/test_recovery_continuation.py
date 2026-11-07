"""Real journal/tree continuation tests; manager/start authority remains scripted."""
import errno
import unittest

from host_recovery import durable
import test_coordinator_resume as resume


class ContinuationTests(unittest.TestCase):
    setUp = resume.ResumeTests.setUp
    persist_alert = resume.ResumeTests.persist_alert
    admit = resume.ResumeTests.admit
    transport = resume.ResumeTests.transport
    reopen = resume.ResumeTests.reopen
    reopened = resume.ResumeTests.reopened

    def prepare(self, *, reboot=True):
        engine = self.reopened()
        self.boot, self.time = ("boot-b", 5.0) if reboot else ("boot-a", 1200.0)
        value = {"schema": "host-recovery-continuation-v1", "continuation_id": "recovery-2",
                 "intent_sha256": durable.digest((self.state / "intent.json").read_bytes()),
                 "arm_sha256": durable.digest(durable.canonical(durable.decode((self.state / "arm.json").read_bytes())["arm"])),
                 "owner": {**self.log.intent["owner"], "boot_id": self.boot, "invocation_id": "recovery-new"},
                 "started_at": self.time, "deadline": self.time + 150}
        self.boundary.authorize_continuation = lambda intent, approved, deadline: self.boundary.event(
            "continuation-authorization", deadline)
        return engine, value

    def run_continuation(self, engine, value):
        return engine.resume(continuation=value, continuation_sha256=durable.digest(durable.canonical(value)))

    def assert_fenced(self, result):
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertTrue(result["start_fenced"])
        self.assertFalse(result["production_acceptance"])
        self.assertIsNone(self.log.terminal)
        self.assertFalse((self.state / "recovery-outcome.json").exists())
        self.assertFalse(self.log.can_start_candidate("a" * 64))
        self.assertNotIn("start-candidate", self.boundary.calls)
        self.assertNotIn("mutate", self.boundary.calls)

    def test_reboot_restores_original_tree_without_renewing_original_target(self):
        engine, value = self.prepare()
        original = {name: (self.state / name).read_bytes() for name in ("intent.json", "arm.json")}
        result = self.run_continuation(engine, value)
        self.assert_fenced(result)
        self.assertTrue(result["continuation_baseline_restored"])
        self.assertFalse(result["original_target_met"])
        self.assertEqual(self.boundary.calls, ["continuation-authorization", "recovery-preflight", "fence",
            "quiesce", "validate-recovery", "restore", "baseline-oracle", "start-old", "old-ready"])
        self.assertEqual(engine.meter.arm, {"boot_id": "boot-a", "monotonic": 1000})
        self.assertEqual(engine.meter.events[0]["original_elapsed_seconds"], None)
        self.assertEqual(engine.meter.deadline("recovery"), value["deadline"])
        for name, raw in original.items():
            self.assertEqual((self.state / name).read_bytes(), raw)
        record = durable.decode((self.state / "continuation-outcome.json").read_bytes())
        self.assertFalse(record["original_target_met"])
        self.assertFalse(record["installation_settled"])
        self.assertEqual(record["continuation_sha256"], durable.digest((self.state / "continuation-request.json").read_bytes()))
        self.assertEqual(self.file.read_bytes(), b"original-baseline-config")
        self.assertTrue(result["alert"]["transport_delivered"])

    def test_expired_same_boot_is_distinct_and_preserves_elapsed_interval(self):
        engine, value = self.prepare(reboot=False)
        result = self.run_continuation(engine, value)
        self.assert_fenced(result)
        self.assertTrue(result["continuation_baseline_restored"])
        self.assertEqual(engine.meter.events[0]["original_elapsed_seconds"], 200)

    def test_digest_match_cannot_replace_independent_authorization(self):
        for reply in (False, 1, None, OSError(errno.EIO, "restricted")):
            with self.subTest(reply=type(reply)):
                self.setUp()
                engine, value = self.prepare()
                self.boundary.overrides["continuation-authorization"] = reply
                self.assert_fenced(self.run_continuation(engine, value))
                self.assertEqual(self.boundary.calls, ["continuation-authorization"])
                self.assertFalse((self.state / "continuation-request.json").exists())
                self.assertEqual(self.file.read_bytes(), b"partial-candidate")

    def test_unknown_unpinned_owner_original_and_reserve_changes_refuse(self):
        changes = ({"schema": "unknown"}, {"extra": 1}, {"continuation_id": "bad/id"},
                   {"intent_sha256": "0" * 64}, {"arm_sha256": "0" * 64},
                   {"started_at": True}, {"started_at": 6}, {"deadline": 5},
                   {"deadline": float("inf")}, {"deadline": 186})
        for change in changes:
            with self.subTest(change=change):
                self.setUp()
                engine, value = self.prepare()
                value.update(change)
                # Nonfinite JSON must fail even before an approval digest exists.
                if change.get("deadline") == float("inf"):
                    with self.assertRaises(ValueError):
                        durable.canonical(value)
                    continue
                self.assert_fenced(self.run_continuation(engine, value))
                self.assertEqual(self.boundary.calls, [])
        for key, replacement in (("boot_id", "other"), ("attempt_id", "other"),
                                 ("installation_id", "other"), ("invocation_id", "inv-a")):
            self.setUp()
            engine, value = self.prepare()
            value["owner"][key] = (self.log.intent["owner"]["invocation_id"]
                                   if key == "invocation_id" else replacement)
            self.assert_fenced(self.run_continuation(engine, value))
            self.assertEqual(self.boundary.calls, [])
        self.setUp()
        engine, value = self.prepare()
        self.assert_fenced(engine.resume(continuation=value, continuation_sha256="0" * 64))
        self.assertEqual(self.boundary.calls, [])

    def test_original_resume_window_cannot_be_replaced(self):
        engine, value = self.prepare(reboot=False)
        self.time = value["started_at"] = 1005
        value["deadline"] = 1155
        self.assert_fenced(self.run_continuation(engine, value))
        self.assertEqual(self.boundary.calls, [])

    def test_publication_faults_never_enter_recovery_and_always_attempt_alert(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point):
                    self.setUp()
                    engine, value = self.prepare()
                    reached = []
                    def fail(stage):
                        if stage == point:
                            reached.append(stage)
                            raise OSError(code, "restricted")
                    self.log.fault = fail
                    self.receipt_fault = True
                    result = self.run_continuation(engine, value)
                    self.assert_fenced(result)
                    self.assertEqual(reached, [point])
                    self.assertEqual(self.boundary.calls, ["continuation-authorization"])
                    self.assertTrue(self.log.uncertain)
                    self.assertFalse(result["alert"]["receipt_persisted"])
                    self.assertTrue(result["alert"]["transport_delivered"])

    def test_consumed_request_cannot_replay_after_reopen(self):
        engine, value = self.prepare()
        self.boundary.overrides["fence"] = False
        self.assert_fenced(self.run_continuation(engine, value))
        raw = (self.state / "continuation-request.json").read_bytes()
        engine = self.reopen()
        self.boot, self.time = "boot-b", 6
        self.assert_fenced(self.run_continuation(engine, value))
        self.assertEqual(self.boundary.calls, [])
        self.assertEqual((self.state / "continuation-request.json").read_bytes(), raw)

    def test_new_boot_clock_regression_and_deadlines_revoke_before_next_effect(self):
        for drift in ("boot", "backward", "deadline", "detection-cap"):
            with self.subTest(drift=drift):
                self.setUp()
                engine, value = self.prepare()
                def change():
                    if drift == "boot":
                        self.boot = "boot-c"
                    else:
                        self.time = {"backward": 4, "deadline": 155, "detection-cap": 25}[drift]
                    return True
                self.boundary.overrides["recovery-preflight"] = change
                self.assert_fenced(self.run_continuation(engine, value))
                self.assertEqual(self.boundary.calls[-1], "recovery-preflight")
                self.assertNotIn("fence", self.boundary.calls)

    def test_original_and_consumed_records_remain_bound_at_every_effect(self):
        for name in ("intent.json", "arm.json", "continuation-request.json"):
            with self.subTest(name=name):
                self.setUp()
                engine, value = self.prepare()
                def change():
                    (self.state / name).write_bytes(b"{}\n")
                    return True
                self.boundary.overrides["quiesce"] = change
                self.assert_fenced(self.run_continuation(engine, value))
                self.assertEqual(self.boundary.calls[-1], "quiesce")
                self.assertNotIn("restore", self.boundary.calls)

    def test_incomplete_baseline_or_failed_readiness_cannot_publish_completion(self):
        for phase, reply in (("baseline-oracle", {}), ("old-ready", False)):
            with self.subTest(phase=phase):
                self.setUp()
                engine, value = self.prepare()
                self.boundary.overrides[phase] = reply
                self.assert_fenced(self.run_continuation(engine, value))
                self.assertFalse((self.state / "continuation-outcome.json").exists())
                if phase == "baseline-oracle":
                    self.assertNotIn("start-old", self.boundary.calls)

    def test_outcome_faults_are_not_late_completion_or_original_terminals(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point):
                    self.setUp()
                    engine, value = self.prepare()
                    reached = []
                    def arm_failure():
                        def fail(stage):
                            if stage == point:
                                reached.append(stage)
                                raise OSError(code, "restricted")
                        self.log.fault = fail
                        return True
                    self.boundary.overrides["old-ready"] = arm_failure
                    result = self.run_continuation(engine, value)
                    self.assert_fenced(result)
                    self.assertEqual(reached, [point])
                    self.assertNotIn("continuation_baseline_restored", result)
                    self.assertTrue(result["alert"]["transport_delivered"])

    def test_forward_and_budget_renewal_are_always_forbidden(self):
        engine, value = self.prepare()
        self.run_continuation(engine, value)
        for operation in (engine.forward, engine.resume, engine.recover,
                          lambda: engine.meter.deadline("forward"),
                          lambda: engine.meter.trigger_recovery(5)):
            with self.assertRaises(durable.Rejected):
                operation()
