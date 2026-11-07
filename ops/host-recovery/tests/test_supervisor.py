"""Real locks/files/process death; scripted manager, NOT a systemd/daemon drill."""
import copy
import errno
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from host_recovery import durable, journal, supervisor
from test_recovery_state import candidate, intent


class ScriptedManager:
    def __init__(self):
        self.calls = []
        self.owner_change = False
        self.fenced = True
        self.receipt_change = None
        self.failure = None
        self.on_enqueue = lambda _: None

    def observe_owner(self, owner, *, deadline):
        self.calls.append(("owner", deadline))
        return {**owner, "invocation_id": "2" * 32} if self.owner_change else owner

    def fence(self, value, *, deadline):
        self.calls.append(("fence", deadline))
        return self.fenced

    def enqueue_recovery(self, request, *, deadline):
        self.calls.append(("enqueue", deadline, copy.deepcopy(request)))
        self.on_enqueue(request)
        if self.failure:
            raise self.failure
        return self.receipt_change if self.receipt_change is not None else {
            "request_id": request["request_id"], "accepted": True, "separate_recovery_owner": True}


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="recovery-supervisor-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.value = intent()
        self.now = 1050.0
        self.boot = "boot-a"
        self.owner = {**self.value["owner"], "invocation_id": "1" * 32}
        self.manager = ScriptedManager()
        self.notices = []
        self.fault = None
        self.persist = lambda _: None
        with durable.directory(self.root, private=True) as fd:
            log = journal.Journal(fd)
            log.prepare(self.value)
            log.arm({"boot_id": self.boot, "monotonic": 1000.0})
        self.original = (self.root / "intent.json").read_bytes()

    def open(self):
        return supervisor.recovery_owner(str(self.root), owner=self.owner, manager=self.manager,
                                         clock=lambda: self.now, boot_id=lambda: self.boot,
                                         persist_alert=self.persist,
                                         transport_alert=lambda notice: self.notices.append(notice) or True,
                                         fault=self.fault)

    def enqueues(self):
        return [row for row in self.manager.calls if row[0] == "enqueue"]

    def assert_fenced(self, state):
        for key in ("forward_allowed", "start_permission", "recovery_completed",
                    "installation_start_fence_proven", "production_acceptance"):
            self.assertIs(state[key], False)

    def test_preserves_arm_and_conservatively_charges_unknown_detection(self):
        with self.open() as process:
            self.assertEqual(process.plan["original_arm"]["monotonic"], 1000.0)
            self.assertEqual(process.plan["deadline"], 1180.0)
            self.assertEqual(process.plan["failure_lower_bound"], 1000.0)
            self.assertEqual(process.plan["detection_upper_bound_seconds"], 50.0)
            self.assert_fenced(process.status())

    def test_durable_request_precedes_enqueue_and_receipt_is_not_recovery(self):
        def check(request):
            self.assertEqual(durable.decode((self.root / "reconcile-request.json").read_bytes()), request)
            self.assertFalse((self.root / "reconcile-enqueued.json").exists())
        self.manager.on_enqueue = check
        with self.open() as process:
            state = process.reconcile(deadline=1100)
            self.assertEqual(state["state"], "recovery_enqueued")
            self.assert_fenced(state)
            self.assertEqual([row[0] for row in self.manager.calls], ["owner", "fence", "owner", "owner", "fence", "owner", "enqueue"])
        self.assertEqual((self.root / "intent.json").read_bytes(), self.original)

    def test_caller_deadline_can_only_shorten_original_reserve(self):
        with self.open() as process:
            process.reconcile(deadline=9999)
        self.assertEqual(self.enqueues()[0][1], 1180)
        self.assertEqual(self.enqueues()[0][2]["deadline"], 1180)

    def test_shortened_request_digest_binds_exact_bytes(self):
        with self.open() as process:
            process.reconcile(deadline=1075)
        request = self.enqueues()[0][2]
        request_id = request.pop("request_id")
        self.assertEqual(request_id, durable.digest(durable.canonical(request)))
        self.assertEqual(request["deadline"], 1075)

    def test_repeated_call_cannot_duplicate_enqueue(self):
        with self.open() as process:
            process.reconcile(deadline=1100)
            with self.assertRaises(durable.Rejected):
                process.reconcile(deadline=1150)
        self.assertEqual(len(self.enqueues()), 1)

    def test_reopen_success_receipt_does_not_clear_latch_or_redispatch(self):
        with self.open() as process:
            process.reconcile(deadline=1100)
        self.owner["invocation_id"] = "3" * 32
        with self.open() as process:
            self.assertEqual(process.status()["error"], "supervisor-dispatch-reconciliation-required")
            with self.assertRaises(durable.Rejected):
                process.reconcile(deadline=1150)
        self.assertEqual(len(self.enqueues()), 1)

    def test_lost_enqueue_reply_retains_pending_and_alerts(self):
        self.manager.failure = OSError(errno.EIO, "restricted manager text")
        with self.open() as process:
            state = process.reconcile(deadline=1100)
            self.assertEqual(state["state"], "recovery_unresolved")
            self.assertTrue(state["alert"]["transport_delivered"])
            self.assertNotIn("restricted", str(state))
        self.assertTrue((self.root / "reconcile-request.json").exists())
        self.assertFalse((self.root / "reconcile-enqueued.json").exists())
        with self.open() as process:
            self.assertEqual(process.status()["error"], "supervisor-dispatch-reconciliation-required")
        self.assertEqual(len(self.enqueues()), 1)

    def test_disk_alert_failure_does_not_skip_independent_transport(self):
        self.manager.fenced = False
        def fail(_):
            raise OSError(errno.ENOSPC, "restricted path")
        self.persist = fail
        with self.open() as process:
            state = process.reconcile(deadline=1100)
            self.assertFalse(state["alert"]["receipt_persisted"])
            self.assertTrue(state["alert"]["transport_delivered"])
        self.assertEqual(len(self.notices), 1)
        self.assertEqual(self.enqueues(), [])

    def test_cross_boot_never_resets_budget_or_dispatches(self):
        self.boot = "boot-b"
        self.owner["boot_id"] = self.boot
        with self.open() as process:
            self.assertEqual(process.status()["error"], "supervisor-cross-boot-continuation-required")
            self.assertIsNone(process.plan)
            self.assert_fenced(process.status())
        self.assertEqual(self.enqueues(), [])

    def test_expired_arm_never_gets_fresh_recovery_reserve(self):
        for now in (1180, 1300, 10000):
            self.now = now
            with self.subTest(now=now), self.open() as process:
                self.assertEqual(process.status()["error"], "supervisor-expired-continuation-required")
        self.assertEqual(self.enqueues(), [])

    def test_missing_or_corrupt_arm_remains_unresolved(self):
        arm = self.root / "arm.json"
        arm.unlink()
        with self.open() as process:
            self.assertEqual(process.status()["state"], "recovery_unresolved")
        arm.write_bytes(b'{"torn":')
        arm.chmod(0o600)
        with self.open() as process:
            self.assertEqual(process.status()["state"], "recovery_unresolved")
        self.assertEqual(self.enqueues(), [])

    def test_arm_pin_and_schema_are_required(self):
        arm = self.root / "arm.json"
        original = durable.decode(arm.read_bytes())
        for patch in ({"intent_sha256": "0" * 64}, {"arm": {"boot_id": "boot-a", "monotonic": True}},
                      {"arm": {"boot_id": "wrong", "monotonic": 1000}}, {"extra": True}):
            arm.write_bytes(durable.canonical({**original, **patch}))
            with self.subTest(patch=patch), self.open() as process:
                self.assertEqual(process.status()["state"], "recovery_unresolved")
        self.assertEqual(self.enqueues(), [])

    def test_private_arm_mode_required(self):
        (self.root / "arm.json").chmod(0o644)
        with self.open() as process:
            self.assertEqual(process.status()["state"], "recovery_unresolved")

    def test_terminal_looking_candidate_result_cannot_resume_forward(self):
        with durable.directory(self.root, private=True) as fd:
            durable.atomic_write(fd, "outcome.json", durable.canonical({"outcome": "candidate_verified"}))
        with self.open() as process:
            self.assertEqual(process.status()["state"], "recovery_required")
            self.assertFalse(process.log.can_start_candidate(candidate(self.value)["object_id"]))
            self.assertEqual(process.reconcile(deadline=1100)["state"], "recovery_enqueued")

    def test_changed_manager_owner_or_unconfirmed_fence_forbids_enqueue(self):
        for changed in ("owner", "fence"):
            self.manager.owner_change = changed == "owner"
            self.manager.fenced = changed != "fence"
            with self.subTest(changed=changed), self.open() as process:
                self.assertEqual(process.reconcile(deadline=1100)["state"], "recovery_unresolved")
        self.assertEqual(self.enqueues(), [])
        self.assertFalse((self.root / "reconcile-request.json").exists())

    def test_intent_change_after_open_forbids_enqueue(self):
        with self.open() as process:
            value = copy.deepcopy(self.value)
            value["package_sha256"] = "0" * 64
            (self.root / "intent.json").write_bytes(durable.canonical(value))
            self.assertEqual(process.reconcile(deadline=1100)["state"], "recovery_unresolved")
        self.assertEqual(self.enqueues(), [])

    def test_unexpected_receipt_after_open_forbids_enqueue(self):
        with self.open() as process:
            (self.root / "unknown").write_bytes(b"uncertain")
            self.assertEqual(process.reconcile(deadline=1100)["state"], "recovery_unresolved")
        self.assertEqual(self.enqueues(), [])

    def test_clock_regression_or_boot_change_after_open_forbids_enqueue(self):
        for change in ("clock", "boot"):
            with self.subTest(change=change), self.open() as process:
                if change == "clock":
                    self.now = 1049
                else:
                    self.boot = "boot-b"
                self.assertEqual(process.reconcile(deadline=1100)["state"], "recovery_unresolved")
            self.now, self.boot = 1050, "boot-a"
        self.assertEqual(self.enqueues(), [])

    def test_lock_retained_across_enqueue_and_closed_reference_cannot_dispatch(self):
        def check(_):
            with self.assertRaises(BlockingIOError), self.open():
                self.fail("second owner acquired lock")
        self.manager.on_enqueue = check
        with self.open() as process:
            process.reconcile(deadline=1100)
            with self.assertRaises(BlockingIOError), self.open():
                self.fail("lock released before context exit")
        self.assertTrue(process.status()["owner_closed"])
        with self.assertRaises(durable.Rejected):
            process.reconcile(deadline=1100)

    def test_every_request_write_fault_prevents_enqueue_and_keeps_intent(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point), tempfile.TemporaryDirectory() as path:
                    with durable.directory(path, private=True) as fd:
                        log = journal.Journal(fd)
                        log.prepare(self.value)
                        log.arm({"boot_id": self.boot, "monotonic": 1000})
                    def fail(stage):
                        if stage == point:
                            raise OSError(code, "injected")
                    with supervisor.recovery_owner(path, owner=self.owner, manager=self.manager,
                            clock=lambda: self.now, boot_id=lambda: self.boot, fault=fail,
                            persist_alert=self.persist, transport_alert=lambda _: True) as process:
                        self.assertEqual(process.reconcile(deadline=1100)["state"], "recovery_unresolved")
                    self.assertEqual((Path(path) / "intent.json").read_bytes(), self.original)
        self.assertEqual(self.enqueues(), [])

    def test_slow_request_persistence_cannot_enqueue_after_deadline(self):
        def delay(stage):
            if stage == "readback":
                self.now = 1100
        self.fault = delay
        with self.open() as process:
            self.assertEqual(process.reconcile(deadline=1100)["state"], "recovery_unresolved")
        self.assertEqual(self.enqueues(), [])
        self.assertTrue((self.root / "reconcile-request.json").exists())

    def test_untrusted_enqueue_receipt_cannot_become_completion(self):
        self.manager.receipt_change = {"accepted": True, "request_id": "0" * 64, "separate_recovery_owner": True}
        with self.open() as process:
            state = process.reconcile(deadline=1100)
            self.assertEqual(state["state"], "recovery_unresolved")
            self.assert_fenced(state)
        self.assertFalse((self.root / "reconcile-enqueued.json").exists())

    def test_enqueue_receipt_persistence_fault_does_not_allow_retry(self):
        def enable(_):
            def fail(stage):
                if stage == "directory-fsync":
                    raise OSError(errno.EIO, "injected")
            process.log.fault = fail
        self.manager.on_enqueue = enable
        with self.open() as process:
            state = process.reconcile(deadline=1100)
            self.assertEqual(state["state"], "recovery_unresolved")
            self.assert_fenced(state)
        with self.open() as reopened:
            self.assertEqual(reopened.status()["error"], "supervisor-dispatch-reconciliation-required")
        self.assertEqual(len(self.enqueues()), 1)

    def test_owner_mismatch_is_not_adopted(self):
        self.owner["installation_id"] = "foreign"
        with self.open() as process:
            self.assertEqual(process.status()["error"], "supervisor-intent-owner-mismatch")
        self.assertEqual(self.enqueues(), [])

    def test_invalid_manager_owner_refused_before_open(self):
        self.owner["invocation_id"] = "reused-pid"
        with self.assertRaises(durable.Rejected), self.open():
            self.fail("invalid owner opened")

    def test_directory_read_failure_still_attempts_independent_alert(self):
        with patch.object(supervisor.os, "listdir", side_effect=OSError(errno.EIO, "restricted")):
            with self.open() as process:
                self.assertEqual(process.status()["state"], "recovery_unresolved")
                self.assertTrue(process.status()["alert"]["transport_delivered"])
        self.assertEqual(len(self.notices), 1)
        self.assertEqual(self.enqueues(), [])

    def test_arm_change_after_open_forbids_enqueue(self):
        with self.open() as process:
            path = self.root / "arm.json"
            arm = durable.decode(path.read_bytes())
            arm["arm"]["monotonic"] = 1050
            path.write_bytes(durable.canonical(arm))
            self.assertEqual(process.reconcile(deadline=1100)["state"], "recovery_unresolved")
        self.assertEqual(self.enqueues(), [])

    def test_owner_lost_during_fence_forbids_enqueue(self):
        def fence(value, *, deadline):
            self.manager.owner_change = True
            return True
        self.manager.fence = fence
        with self.open() as process:
            self.assertEqual(process.reconcile(deadline=1100)["state"], "recovery_unresolved")
        self.assertEqual(self.enqueues(), [])

    def test_manager_loss_after_request_is_durable_requires_reconciliation(self):
        def lose(stage):
            if stage == "readback":
                self.manager.owner_change = True
        self.fault = lose
        with self.open() as process:
            self.assertEqual(process.reconcile(deadline=1100)["state"], "recovery_unresolved")
        self.assertTrue((self.root / "reconcile-request.json").exists())
        self.assertEqual(self.enqueues(), [])
        with self.open() as process:
            self.assertEqual(process.status()["error"], "supervisor-dispatch-reconciliation-required")

    def test_no_intent_or_only_staging_never_becomes_clean_admission(self):
        with tempfile.TemporaryDirectory() as path:
            for staged in (False, True):
                if staged:
                    (Path(path) / ".stage-intent.json").write_bytes(b"partial")
                with supervisor.recovery_owner(path, owner=self.owner, manager=self.manager,
                        clock=lambda: self.now, boot_id=lambda: self.boot,
                        persist_alert=self.persist, transport_alert=lambda _: True) as process:
                    self.assertEqual(process.status()["state"], "recovery_unresolved")
                    self.assert_fenced(process.status())
        self.assertEqual(self.enqueues(), [])

    def test_sigkill_retains_durable_request_and_new_process_cannot_redispatch(self):
        package = Path(__file__).resolve().parents[1]
        code = r'''
import json, os, sys
sys.path.insert(0, sys.argv[1])
from host_recovery import supervisor
owner = json.loads(sys.argv[3])
class Manager:
    def observe_owner(self, value, *, deadline): return value
    def fence(self, value, *, deadline): return True
    def enqueue_recovery(self, value, *, deadline):
        print("durable-request-before-lost-reply", flush=True)
        os.read(0, 1)
        raise RuntimeError("unreachable")
with supervisor.recovery_owner(sys.argv[2], owner=owner, manager=Manager(),
        clock=lambda: 1050, boot_id=lambda: "boot-a", persist_alert=lambda _: None,
        transport_alert=lambda _: True) as process:
    process.reconcile(deadline=1100)
'''
        import json
        child = subprocess.Popen([sys.executable, "-I", "-c", code, str(package), str(self.root), json.dumps(self.owner)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(ready.select(10), "child did not reach durable dispatch")
            self.assertEqual(child.stdout.readline(), b"durable-request-before-lost-reply\n")
            with self.assertRaises(BlockingIOError), self.open():
                self.fail("live child lock was not exclusive")
            child.kill()
            _, errors = child.communicate(timeout=10)
            self.assertEqual(child.returncode, -9)
            self.assertEqual(errors, b"")
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
        self.assertTrue((self.root / "reconcile-request.json").exists())
        self.assertFalse((self.root / "reconcile-enqueued.json").exists())
        with self.open() as process:
            self.assertEqual(process.status()["error"], "supervisor-dispatch-reconciliation-required")
            self.assert_fenced(process.status())
        self.assertEqual(self.enqueues(), [])
        self.assertEqual((self.root / "intent.json").read_bytes(), self.original)
