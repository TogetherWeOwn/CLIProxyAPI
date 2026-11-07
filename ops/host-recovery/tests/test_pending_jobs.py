"""Real journal persistence with scripted job observation, never real systemd."""
import copy
import errno
import json
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest

from host_recovery import durable, jobs, journal, supervisor
from test_recovery_state import intent
from test_supervisor import ScriptedManager


class ScriptedObserver:
    def __init__(self):
        self.calls = []
        self.invocation = "b" * 32
        self.state = "running"
        self.job = 0
        self.update = {}
        self.on_observe = lambda: None

    def observe(self, request_id, *, deadline):
        self.calls.append((request_id, deadline))
        self.on_observe()
        return {"schema": "host-recovery-job-observation-v1", "request_id": request_id,
                "unit": jobs.recovery_unit(request_id), "boot_id": "boot-a",
                "invocation_id": self.invocation, "state": self.state, "job_id": self.job, **self.update}


class PendingJobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="recovery-pending-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.value = intent()
        self.owner = {**self.value["owner"], "invocation_id": "1" * 32}
        self.now, self.boot = 1050, "boot-a"
        self.manager = ScriptedManager()
        self.observer = ScriptedObserver()
        self.fault = None
        self.notices = []
        self.persist = lambda _: None
        with durable.directory(self.root, private=True) as fd:
            log = journal.Journal(fd)
            log.prepare(self.value)
            log.arm({"boot_id": self.boot, "monotonic": 1000.0})
        self.original = (self.root / "intent.json").read_bytes()
        # Real durable request; the enqueue boundary is scripted and loses reply.
        self.manager.failure = OSError(errno.EIO, "restricted reply")
        with self.open(existing=False) as process:
            process.reconcile(deadline=1100)
        self.manager.failure = None
        self.manager.calls.clear()
        self.owner["invocation_id"] = "3" * 32
        self.request = durable.decode((self.root / "reconcile-request.json").read_bytes())

    def open(self, *, existing=True):
        return supervisor.recovery_owner(str(self.root), owner=self.owner, manager=self.manager,
            clock=lambda: self.now, boot_id=lambda: self.boot, persist_alert=self.persist,
            transport_alert=lambda notice: self.notices.append(notice) or True, fault=self.fault,
            observe_existing=existing)

    def observe(self):
        with self.open() as process:
            result = process.observe_pending(observer=self.observer, deadline=1150)
        self.assertEqual((self.root / "intent.json").read_bytes(), self.original)
        self.assertFalse(any(row[0] == "enqueue" for row in self.manager.calls))
        for key in ("forward_allowed", "start_permission", "recovery_completed",
                    "installation_start_fence_proven", "production_acceptance"):
            self.assertIs(result[key], False)
        return result

    def rewrite_request(self, change, *, repin=True):
        value = copy.deepcopy(self.request)
        change(value)
        if repin:
            value.pop("request_id")
            value["request_id"] = durable.digest(durable.canonical(value))
        (self.root / "reconcile-request.json").write_bytes(durable.canonical(value))

    def test_lost_reply_can_be_observed_without_redispatch(self):
        result = self.observe()
        self.assertEqual(result["state"], "recovery_job_running")
        self.assertEqual(result["job"]["invocation_id"], "b" * 32)
        self.assertEqual(self.observer.calls, [(self.request["request_id"], 1100)] * 2)
        bound = durable.decode((self.root / "reconcile-observed.json").read_bytes())
        self.assertEqual(bound["request_id"], self.request["request_id"])
        self.assertEqual(bound["invocation_id"], "b" * 32)

    def test_explicit_observation_mode_never_dispatches(self):
        with self.open() as process:
            with self.assertRaises(durable.Rejected):
                process.reconcile(deadline=1100)
        self.assertEqual(self.manager.calls, [])

    def test_default_reopen_still_refuses_automatic_redispatch(self):
        with self.open(existing=False) as process:
            self.assertEqual(process.status()["error"], "supervisor-dispatch-reconciliation-required")
            with self.assertRaises(durable.Rejected):
                process.observe_pending(observer=self.observer, deadline=1100)
        self.assertEqual(self.observer.calls, [])

    def test_absent_job_and_empty_invocation_never_clear_latch(self):
        self.observer.state, self.observer.invocation = "inactive_unverified", ""
        result = self.observe()
        self.assertEqual(result["state"], "recovery_job_inactive_unverified")
        self.assertFalse((self.root / "reconcile-observed.json").exists())
        self.assertTrue((self.root / "reconcile-request.json").exists())

    def test_exited_observed_invocation_never_means_recovery_complete(self):
        self.observe()
        self.observer.state = "inactive_unverified"
        self.assertEqual(self.observe()["state"], "recovery_job_inactive_unverified")

    def test_new_or_lost_invocation_after_restart_is_not_adopted(self):
        self.observe()
        for replacement in ("c" * 32, ""):
            self.observer.invocation = replacement
            if not replacement:
                self.observer.state = "inactive_unverified"
            with self.subTest(replacement=replacement):
                self.assertEqual(self.observe()["state"], "recovery_unresolved")

    def test_supervisor_and_recovery_cannot_share_invocation(self):
        for invocation in (self.owner["invocation_id"], self.request["owner"]["invocation_id"]):
            self.observer.invocation = invocation
            with self.subTest(invocation=invocation):
                self.assertEqual(self.observe()["state"], "recovery_unresolved")
                self.assertFalse((self.root / "reconcile-observed.json").exists())

    def test_pending_job_with_no_invocation_remains_pending_without_binding(self):
        self.observer.state, self.observer.job, self.observer.invocation = "pending", 12, ""
        self.assertEqual(self.observe()["state"], "recovery_job_pending")
        self.assertFalse((self.root / "reconcile-observed.json").exists())

    def test_late_invocation_after_pending_can_be_bound_but_not_promoted(self):
        self.observer.state, self.observer.job, self.observer.invocation = "pending", 12, ""
        self.observe()
        self.observer.state, self.observer.job, self.observer.invocation = "running", 0, "b" * 32
        self.assertEqual(self.observe()["state"], "recovery_job_running")

    def test_changed_observation_during_persistence_is_unresolved(self):
        def change(stage):
            if stage == "readback":
                self.observer.invocation = "c" * 32
        self.fault = change
        self.assertEqual(self.observe()["state"], "recovery_unresolved")
        self.assertEqual(durable.decode((self.root / "reconcile-observed.json").read_bytes())["invocation_id"], "b" * 32)

    def test_observation_write_faults_keep_request_and_independent_alert(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point):
                    self.setUp()
                    def fail(stage):
                        if stage == point:
                            raise OSError(code, "restricted path")
                    self.fault = fail
                    self.persist = lambda _: (_ for _ in ()).throw(OSError(code, "disk full"))
                    result = self.observe()
                    self.assertEqual(result["state"], "recovery_unresolved")
                    self.assertFalse(result["alert"]["receipt_persisted"])
                    self.assertTrue(result["alert"]["transport_delivered"])
                    self.assertNotIn("restricted", str(result))
                    self.assertTrue((self.root / "reconcile-request.json").exists())

    def test_changed_private_request_or_bad_digest_refuses_before_query(self):
        self.rewrite_request(lambda row: row.update(deadline=1090), repin=False)
        with self.open() as process:
            self.assertEqual(process.status()["state"], "recovery_unresolved")
        self.assertEqual(self.observer.calls, [])

    def test_recomputed_digest_cannot_change_attempt_arm_owner_or_budget(self):
        changes = [lambda row: row.update(attempt_id="foreign"), lambda row: row.update(deadline=1181),
                   lambda row: row.update(forward_allowed=0), lambda row: row.update(production_acceptance=0),
                   lambda row: row.update(detection_upper_bound_seconds=True),
                   lambda row: row.update(detection_upper_bound_seconds=-1),
                   lambda row: row["owner"].update(installation_id="foreign"),
                   lambda row: row["owner"].update(unit="other.service"),
                   lambda row: row["original_arm"].update(monotonic=1050),
                   lambda row: row.update(extra=True)]
        for change in changes:
            self.rewrite_request(change)
            with self.subTest(change=change), self.open() as process:
                self.assertEqual(process.status()["state"], "recovery_unresolved")
        self.assertEqual(self.observer.calls, [])

    def test_pending_request_change_after_open_refuses_query(self):
        with self.open() as process:
            self.rewrite_request(lambda row: row.update(deadline=1090))
            result = process.observe_pending(observer=self.observer, deadline=1100)
        self.assertEqual(result["state"], "recovery_unresolved")
        self.assertEqual(self.observer.calls, [])

    def test_staged_or_unknown_dispatch_records_refuse_observation(self):
        for name in (".stage-reconcile-request.json", "reconcile-unknown.json"):
            path = self.root / name
            path.write_bytes(b"uncertain")
            with self.subTest(name=name), self.open() as process:
                self.assertEqual(process.status()["state"], "recovery_unresolved")
            path.unlink()
        self.assertEqual(self.observer.calls, [])

    def test_enqueue_receipt_must_be_exact_and_strict(self):
        path = self.root / "reconcile-enqueued.json"
        path.write_bytes(durable.canonical({"accepted": 1, "request_id": self.request["request_id"],
                                           "separate_recovery_owner": True}))
        path.chmod(0o600)
        with self.open() as process:
            self.assertEqual(process.status()["state"], "recovery_unresolved")
        self.assertEqual(self.observer.calls, [])

    def test_private_observation_record_cannot_be_rebound_or_forged(self):
        self.observe()
        path = self.root / "reconcile-observed.json"
        value = durable.decode(path.read_bytes())
        for change in ({"request_id": "e" * 64}, {"extra": True}, {"invocation_id": "c" * 32}):
            path.write_bytes(durable.canonical({**value, **change}))
            with self.subTest(change=change):
                self.assertEqual(self.observe()["state"], "recovery_unresolved")

    def test_untrusted_or_false_green_observer_replies_never_pass(self):
        for update in ({"request_id": "e" * 64}, {"boot_id": "boot-b"}, {"state": "recovered"},
                       {"job_id": True}, {"unit": "other.service"}, {"extra": "restricted"}):
            self.observer.update = update
            with self.subTest(update=update):
                result = self.observe()
                self.assertEqual(result["state"], "recovery_unresolved")
                self.assertNotIn("restricted", str(result))
        self.assertFalse((self.root / "reconcile-observed.json").exists())

    def test_clock_expiry_and_boot_change_never_get_fresh_window(self):
        for now, boot in ((1100, "boot-a"), (1180, "boot-a"), (1050, "boot-b")):
            self.now, self.boot = now, boot
            with self.subTest(now=now, boot=boot):
                with self.open() as process:
                    if process.status()["state"] == "recovery_dispatch_pending":
                        result = process.observe_pending(observer=self.observer, deadline=9999)
                    else:
                        result = process.status()
                    self.assertEqual(result["state"], "recovery_unresolved")
        self.assertEqual(self.observer.calls, [])

    def test_expiry_during_binding_does_not_reach_second_query(self):
        def expire(stage):
            if stage == "readback":
                self.now = 1100
        self.fault = expire
        self.assertEqual(self.observe()["state"], "recovery_unresolved")
        self.assertEqual(len(self.observer.calls), 1)

    def test_owner_or_fence_loss_after_first_query_is_unresolved(self):
        self.observer.on_observe = lambda: setattr(self.manager, "fenced", False)
        self.assertEqual(self.observe()["state"], "recovery_unresolved")
        self.assertEqual(len(self.observer.calls), 1)

    def test_saved_request_detection_time_bounds_restart_clock(self):
        self.now = 1049
        with self.open() as process:
            self.assertEqual(process.status()["state"], "recovery_unresolved")
        self.assertEqual(self.observer.calls, [])

    def test_observer_cannot_mutate_the_first_snapshot_into_a_green_second(self):
        shared = self.observer.observe(self.request["request_id"], deadline=1100)
        calls = []
        def observe(request_id, *, deadline):
            calls.append(True)
            if len(calls) == 2:
                shared["invocation_id"] = "c" * 32
            return shared
        self.observer.observe = observe
        self.assertEqual(self.observe()["state"], "recovery_unresolved")

    def test_changed_binding_during_second_query_is_unresolved(self):
        def change():
            if len(self.observer.calls) == 2:
                path = self.root / "reconcile-observed.json"
                row = durable.decode(path.read_bytes())
                row["invocation_id"] = "c" * 32
                path.write_bytes(durable.canonical(row))
        self.observer.on_observe = change
        self.assertEqual(self.observe()["state"], "recovery_unresolved")

    def test_unchanged_binding_after_restart_is_read_only(self):
        self.observe()
        original = (self.root / "reconcile-observed.json").read_bytes()
        def forbid(_):
            raise AssertionError("no repeat receipt write")
        self.fault = forbid
        self.assertEqual(self.observe()["state"], "recovery_job_running")
        self.assertEqual((self.root / "reconcile-observed.json").read_bytes(), original)

    def test_exact_enqueue_receipt_is_not_required_for_observation_or_completion(self):
        path = self.root / "reconcile-enqueued.json"
        path.write_bytes(durable.canonical({"accepted": True, "request_id": self.request["request_id"],
                                           "separate_recovery_owner": True}))
        path.chmod(0o600)
        self.assertEqual(self.observe()["state"], "recovery_job_running")

    def test_missing_request_in_observation_mode_never_dispatches(self):
        (self.root / "reconcile-request.json").unlink()
        with self.open() as process:
            self.assertEqual(process.status()["state"], "recovery_unresolved")
            with self.assertRaises(durable.Rejected):
                process.reconcile(deadline=1100)
        self.assertEqual(self.manager.calls, [])

    def test_sigkill_after_observed_binding_retains_identity_and_forbids_replacement(self):
        code = r'''
import json, os, sys
sys.path.insert(0, sys.argv[1])
from host_recovery import jobs, supervisor
owner = json.loads(sys.argv[3])
class Manager:
    def observe_owner(self, value, *, deadline): return value
    def fence(self, value, *, deadline): return True
    def enqueue_recovery(self, value, *, deadline): raise AssertionError("no dispatch")
class Observer:
    calls = 0
    def observe(self, request_id, *, deadline):
        self.calls += 1
        if self.calls == 2:
            print("binding-durable-before-second-observation", flush=True)
            os.read(0, 1)
            raise RuntimeError("unreachable")
        return {"schema": "host-recovery-job-observation-v1", "request_id": request_id,
                "unit": jobs.recovery_unit(request_id), "boot_id": "boot-a", "invocation_id": "b" * 32,
                "state": "running", "job_id": 0}
with supervisor.recovery_owner(sys.argv[2], owner=owner, manager=Manager(), clock=lambda: 1050,
        boot_id=lambda: "boot-a", persist_alert=lambda _: None, transport_alert=lambda _: True,
        observe_existing=True) as process:
    process.observe_pending(observer=Observer(), deadline=1100)
'''
        child = subprocess.Popen([sys.executable, "-I", "-c", code, str(Path(__file__).resolve().parents[1]),
                                  str(self.root), json.dumps(self.owner)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(ready.select(10), "child did not reach durable binding")
            self.assertEqual(child.stdout.readline(), b"binding-durable-before-second-observation\n")
            with self.assertRaises(BlockingIOError), self.open():
                self.fail("child lock not exclusive")
            child.kill()
            _, errors = child.communicate(timeout=10)
            self.assertEqual(child.returncode, -9)
            self.assertEqual(errors, b"")
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
        self.owner["invocation_id"] = "4" * 32
        self.assertEqual(self.observe()["state"], "recovery_job_running")
        self.observer.invocation = "c" * 32
        self.assertEqual(self.observe()["state"], "recovery_unresolved")

    def test_lock_remains_held_and_context_reference_cannot_observe_after_close(self):
        def contender():
            with self.assertRaises(BlockingIOError), self.open():
                self.fail("second owner acquired lock")
        self.observer.on_observe = contender
        with self.open() as process:
            result = process.observe_pending(observer=self.observer, deadline=1100)
            self.assertEqual(result["state"], "recovery_job_running")
            with self.assertRaises(durable.Rejected):
                process.observe_pending(observer=self.observer, deadline=1100)
        with self.assertRaises(durable.Rejected):
            process.observe_pending(observer=self.observer, deadline=1100)
