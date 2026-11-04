"""Real journal/tree reads and restoration; scripted host boundaries only."""
import copy
import errno
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import unittest

from host_recovery import alert, coordinator, durable, inventory, journal, restore
import test_coordinator as ordering
from test_recovery_state import intent


class ResumeBoundary(ordering.Boundary):
    def recovery_preflight(self, value, *, deadline):
        return self.event("recovery-preflight", deadline)


class ResumeTests(unittest.TestCase):
    setUp = ordering.CoordinatorTests.setUp
    persist_alert = ordering.CoordinatorTests.persist_alert
    admit = ordering.CoordinatorTests.admit

    def transport(self, notice):
        # Exercise the actual fixed-code protocol, not a permissive stub alone.
        alert.validate_notice(notice)
        self.notices.append(copy.deepcopy(notice))
        return self.transport_ok

    def reopened(self):
        self.admit()
        self.file.write_bytes(b"partial-candidate")
        return self.reopen()

    def reopen(self):
        self.log = journal.Journal(self.log.fd)
        self.boundary = ResumeBoundary(self)
        self.time = 1005.0
        self.engine = coordinator.AttemptCoordinator(self.log, self.boundary, lambda: self.time,
            lambda: self.boot, self.persist_alert, self.transport)
        return self.engine

    def assert_unresolved(self, result):
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertTrue(result["start_fenced"])
        self.assertFalse(result["production_acceptance"])
        self.assertNotIn("start-candidate", self.boundary.calls)
        self.assertNotIn("mutate", self.boundary.calls)
        self.assertEqual(len(self.notices), 1)
        self.assertTrue(result["alert"]["transport_delivered"])

    def test_reopened_original_attempt_restores_before_old_start(self):
        engine = self.reopened()
        original = (self.state / "intent.json").read_bytes(), (self.state / "arm.json").read_bytes()
        result = engine.resume()
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertEqual(result["original_cause"], "restart-original-cause-unavailable")
        self.assertTrue(result["start_fenced"])
        self.assertFalse(result["production_acceptance"])
        self.assertEqual(self.boundary.calls, ["recovery-preflight", "fence", "quiesce", "validate-recovery",
            "restore", "baseline-oracle", "start-old", "old-ready"])
        self.assertEqual(inventory.snapshot(self.tree_fd, uid=os.geteuid(), gid=os.getegid()), (self.tree, self.blobs))
        self.assertEqual(original, ((self.state / "intent.json").read_bytes(), (self.state / "arm.json").read_bytes()))
        self.assertEqual(engine.meter.arm["monotonic"], 1000)
        self.assertEqual(engine.meter.deadline("recovery"), 1180)
        self.assertEqual(engine.meter.phase_ends[("recovery", "detection")], 1020)
        self.assertTrue((self.state / "recovery-outcome.json").exists())
        self.assertFalse(self.log.can_start_candidate("a" * 64))
        self.assertIsNone(journal.Journal(self.log.fd).terminal)

    def test_live_admission_cannot_use_restart_path(self):
        self.admit()
        with self.assertRaises(durable.Rejected):
            self.engine.resume()
        self.assertEqual(self.boundary.calls, ["preflight"])

    def test_resume_is_once_only_and_never_allows_forward(self):
        engine = self.reopened()
        engine.resume()
        for action in (engine.resume, engine.forward, engine.recover, lambda: engine.admit(intent())):
            with self.subTest(action=action), self.assertRaises(durable.Rejected):
                action()

    def test_failed_preflight_is_not_retriable_in_same_instance(self):
        engine = self.reopened()
        self.boundary.overrides["recovery-preflight"] = False
        self.assert_unresolved(engine.resume())
        self.assertEqual(self.boundary.calls, ["recovery-preflight"])
        with self.assertRaises(durable.Rejected):
            engine.recover()
        with self.assertRaises(durable.Rejected):
            engine.resume()
        self.assertEqual(self.file.read_bytes(), b"partial-candidate")

    def test_missing_preflight_method_refuses_before_fence_or_restore(self):
        engine = self.reopened()
        self.boundary = ordering.Boundary(self)
        engine.boundary = self.boundary
        self.assert_unresolved(engine.resume())
        self.assertEqual(self.boundary.calls, [])

    def test_cross_boot_does_not_reset_clock_or_touch_boundary(self):
        engine = self.reopened()
        self.boot, self.time = "boot-b", 1
        self.assert_unresolved(engine.resume())
        self.assertEqual(engine.meter.arm, {"boot_id": "boot-a", "monotonic": 1000})
        self.assertEqual(self.boundary.calls, [])

    def test_expiry_regression_and_detection_cap_refuse_before_preflight(self):
        for now in (999, 1020, 1180, float("nan"), float("inf"), True):
            with self.subTest(now=now):
                self.setUp()
                engine = self.reopened()
                self.time = now
                self.assert_unresolved(engine.resume())
                self.assertEqual(self.boundary.calls, [])
                self.assertFalse((self.state / "recovery-outcome.json").exists())

    def test_terminal_looking_files_and_registration_never_skip_recovery(self):
        for name in ("outcome.json", "recovery-outcome.json", "object-" + "a" * 64 + ".json"):
            with self.subTest(name=name):
                self.setUp()
                engine = self.reopened()
                durable.atomic_write(self.log.fd, name, b'{"outcome":"candidate_verified"}\n')
                result = engine.resume()
                self.assertEqual(result["outcome"], "baseline_restored")
                self.assertIn("restore", self.boundary.calls)
                self.assertIn("baseline-oracle", self.boundary.calls)
                self.assertNotIn("start-candidate", self.boundary.calls)

    def test_pending_dispatch_claim_staging_or_unknown_state_needs_reconciliation(self):
        for name in ("reconcile-request.json", "reconcile-enqueued.json", "reconcile-worker.json",
                     ".stage-intent.json", ".stage-outcome.json", ".recovery-stage-unknown", "unknown.json"):
            with self.subTest(name=name):
                self.setUp()
                engine = self.reopened()
                durable.atomic_write(self.log.fd, name, b'{}\n')
                self.assert_unresolved(engine.resume())
                self.assertEqual(self.boundary.calls, [])
                self.assertEqual((self.state / name).read_bytes(), b'{}\n')

    def test_malformed_missing_unbound_or_unsafe_arm_refuses(self):
        variants = (None, b'{', b'{}', durable.canonical({"schema": "host-recovery-arm-v1",
            "intent_sha256": "0" * 64, "arm": {"boot_id": "boot-a", "monotonic": 1000}}))
        for raw in variants:
            with self.subTest(raw=raw):
                self.setUp()
                engine = self.reopened()
                path = self.state / "arm.json"
                if raw is None:
                    path.unlink()
                else:
                    path.write_bytes(raw)
                self.assert_unresolved(engine.resume())
                self.assertEqual(self.boundary.calls, [])
        for update in ({"boot_id": "other"}, {"monotonic": True}, {"monotonic": 0}, {"extra": 1}):
            with self.subTest(update=update):
                self.setUp()
                engine = self.reopened()
                value = durable.decode((self.state / "arm.json").read_bytes())
                value["arm"].update(update)
                (self.state / "arm.json").write_bytes(durable.canonical(value))
                self.assert_unresolved(engine.resume())
                self.assertEqual(self.boundary.calls, [])
        self.setUp()
        engine = self.reopened()
        (self.state / "arm.json").chmod(0o644)
        self.assert_unresolved(engine.resume())
        self.assertEqual(self.boundary.calls, [])

    def test_changed_original_intent_is_not_adopted(self):
        engine = self.reopened()
        value = durable.decode((self.state / "intent.json").read_bytes())
        value["baseline_sha256"] = "0" * 64
        (self.state / "intent.json").write_bytes(durable.canonical(value))
        self.assert_unresolved(engine.resume())
        self.assertEqual(self.boundary.calls, [])

    def test_read_failure_still_attempts_transport_when_receipt_storage_fails(self):
        engine = self.reopened()
        (self.state / "arm.json").unlink()
        self.receipt_fault = True
        result = engine.resume()
        self.assert_unresolved(result)
        self.assertFalse(result["alert"]["receipt_persisted"])

    def test_changed_inputs_at_each_boundary_cannot_reach_next_operation(self):
        phases = ("recovery-preflight", "fence", "quiesce", "validate-recovery", "restore", "baseline-oracle", "start-old", "old-ready")
        for phase in phases:
            with self.subTest(phase=phase):
                self.setUp()
                engine = self.reopened()
                def change():
                    path = self.state / "arm.json"
                    before = path.stat()
                    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1))
                    return True
                self.boundary.overrides[phase] = change
                result = engine.resume()
                self.assert_unresolved(result)
                self.assertEqual(self.boundary.calls[-1], phase)
                self.assertFalse((self.state / "recovery-outcome.json").exists())

    def test_new_pending_request_during_preflight_refuses_fence(self):
        engine = self.reopened()
        def changed():
            durable.atomic_write(self.log.fd, "reconcile-request.json", b'{}\n')
            return True
        self.boundary.overrides["recovery-preflight"] = changed
        self.assert_unresolved(engine.resume())
        self.assertEqual(self.boundary.calls, ["recovery-preflight"])

    def test_in_memory_intent_change_during_preflight_refuses(self):
        engine = self.reopened()
        def changed():
            self.log.intent["baseline_sha256"] = "0" * 64
            return True
        self.boundary.overrides["recovery-preflight"] = changed
        self.assert_unresolved(engine.resume())
        self.assertEqual(self.boundary.calls, ["recovery-preflight"])

    def test_preflight_overrun_cannot_renew_detection_cap(self):
        engine = self.reopened()
        def late():
            self.time = 1020
            return True
        self.boundary.overrides["recovery-preflight"] = late
        self.assert_unresolved(engine.resume())
        self.assertEqual(self.boundary.calls, ["recovery-preflight"])
        self.assertEqual(engine.meter.phase_ends[("recovery", "detection")], 1020)

    def test_strict_baseline_oracle_still_required_on_resume(self):
        engine = self.reopened()
        self.boundary.overrides["baseline-oracle"] = {"complete_write_set": True}
        self.assert_unresolved(engine.resume())
        self.assertNotIn("start-old", self.boundary.calls)
        self.assertEqual(self.file.read_bytes(), b"original-baseline-config")

    def test_all_terminal_write_faults_preserve_latch_and_report_unresolved(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point):
                    self.setUp()
                    engine = self.reopened()
                    original = (self.state / "intent.json").read_bytes()
                    def fail(stage):
                        if stage == point:
                            raise OSError(code, "restricted exception")
                    self.log.fault = fail
                    self.receipt_fault = True
                    result = engine.resume()
                    self.assert_unresolved(result)
                    self.assertEqual(result["recovery_error"], "recovery-persistence-failed")
                    self.assertFalse(result["alert"]["receipt_persisted"])
                    self.assertTrue(self.log.uncertain)
                    self.assertIsNone(self.log.terminal)
                    self.assertEqual((self.state / "intent.json").read_bytes(), original)
                    self.assertNotIn("restricted exception", str(result))

    def test_actual_restore_faults_never_start_old_and_next_resume_revalidates_full_tree(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point):
                    self.setUp()
                    engine = self.reopened()
                    def fail(stage):
                        if stage == point:
                            raise OSError(code, "injected")
                    def broken_restore():
                        restore.restore_tree(self.tree_fd, self.tree, self.blobs, {}, fault=fail,
                            check=lambda: engine.meter.check(engine.meter.phase_ends[("recovery", "restore")]))
                        return True
                    self.boundary.overrides["restore"] = broken_restore
                    self.assert_unresolved(engine.resume())
                    self.assertNotIn("start-old", self.boundary.calls)
                    self.assertFalse((self.state / "recovery-outcome.json").exists())
                    self.notices.clear()
                    next_engine = self.reopen()
                    self.assertEqual(next_engine.resume()["outcome"], "baseline_restored")
                    self.assertEqual(next_engine.meter.arm["monotonic"], 1000)
                    self.assertEqual(next_engine.meter.deadline("recovery"), 1180)
                    self.assertEqual(inventory.snapshot(self.tree_fd, uid=os.geteuid(), gid=os.getegid()),
                                     (self.tree, self.blobs))

    def test_listener_loss_prevents_restored_outcome_claim(self):
        engine = self.reopened()
        self.transport_ok = False
        result = engine.resume()
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertEqual(result["recovery_error"], "independent-alert-delivery-failed")
        self.assertFalse(result["alert"]["transport_delivered"])

    def test_sigkill_mutator_then_reopen_uses_original_arm_and_real_tree_restore(self):
        # Separate disposable installation, not the live parent-held fixture lock.
        with tempfile.TemporaryDirectory(prefix="host-recovery-resume-kill-") as path:
            root = Path(path)
            state, source = root / "state", root / "source"
            state.mkdir(mode=0o700)
            source.mkdir(mode=0o700)
            config = source / "config.yaml"
            config.write_bytes(b"original-baseline-config")
            config.chmod(0o600)
            fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            try:
                tree, blobs = inventory.snapshot(fd, uid=os.geteuid(), gid=os.getegid())
                value = intent()
                value["baseline_sha256"] = durable.digest(durable.canonical(tree))
                program = '''
import os,signal,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from host_recovery import durable,journal
value=durable.decode(sys.argv[4].encode())
with durable.installation_lock(sys.argv[2],value["owner"]) as (fd,_):
    log=journal.Journal(fd)
    log.prepare(value)
    log.arm({"boot_id":"boot-a","monotonic":1000})
    Path(sys.argv[3]).write_bytes(b"partial-candidate")
    print("armed-mutated",flush=True)
    signal.pause()
'''
                child = subprocess.Popen([sys.executable, "-I", "-c", program,
                    str(Path(__file__).resolve().parents[1]), str(state), str(config),
                    durable.canonical(value).decode()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    # Bounded synchronization without a wall-clock polling loop.
                    with selectors.DefaultSelector() as selector:
                        selector.register(child.stdout, selectors.EVENT_READ)
                        self.assertTrue(selector.select(10), "child did not reach mutation boundary")
                        self.assertEqual(child.stdout.readline(), b"armed-mutated\n")
                    with self.assertRaises(BlockingIOError):
                        with durable.installation_lock(state, value["owner"]):
                            pass
                    child.send_signal(signal.SIGKILL)
                    _, stderr = child.communicate(timeout=10)
                    self.assertEqual(child.returncode, -signal.SIGKILL, stderr.decode())
                    self.assertEqual(config.read_bytes(), b"partial-candidate")
                    with durable.installation_lock(state, value["owner"]) as (state_fd, _):
                        self.state, self.file, self.tree_fd = state, config, fd
                        self.tree, self.blobs = tree, blobs
                        self.log = journal.Journal(state_fd)
                        self.boundary = ResumeBoundary(self)
                        self.time, self.boot = 1005, "boot-a"
                        self.engine = coordinator.AttemptCoordinator(self.log, self.boundary, lambda: self.time,
                            lambda: self.boot, self.persist_alert, self.transport)
                        result = self.engine.resume()
                        self.assertEqual(result["outcome"], "baseline_restored")
                        self.assertEqual(self.engine.meter.arm["monotonic"], 1000)
                        self.assertEqual(config.read_bytes(), b"original-baseline-config")
                        with self.assertRaises(BlockingIOError):
                            with durable.installation_lock(state, value["owner"]):
                                pass
                        print(durable.canonical({"schema": "host-recovery-resume-process-test-v1",
                            "case": "sigkill-before-recovery-dispatch", "child_exit": child.returncode,
                            "lock_excluded_before_kill_and_during_resume": True,
                            "baseline_tree_sha256": value["baseline_sha256"],
                            "original_arm": self.engine.meter.arm,
                            "boundary_kind": "scripted-manager-daemon-oracle",
                            "actual_tree_restored": True, "result": result}).decode(), end="", flush=True)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=10)
            finally:
                os.close(fd)
