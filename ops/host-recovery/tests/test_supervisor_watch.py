"""Lock-retaining loop tests; scripted manager/jobs, not systemd recovery."""
import errno
from pathlib import Path
import selectors
import subprocess
import sys
import unittest

from host_recovery import durable
import test_pending_jobs as pending


class SupervisorWatchTests(unittest.TestCase):
    setUp = pending.PendingJobTests.setUp
    open = pending.PendingJobTests.open
    def watch(self, process, *, deadline=1150, interval=10, max_observations=32,
              stop=lambda: False, wait=None):
        if wait is None:
            def wait(seconds):
                self.now += seconds
                return False
        return process.watch_pending(observer=self.observer, deadline=deadline,
                                     interval=interval, max_observations=max_observations,
                                     stop=stop, wait=wait)

    def assert_closed_permissions(self, result):
        for key in ("forward_allowed", "start_permission", "recovery_completed",
                    "installation_start_fence_proven", "production_acceptance"):
            self.assertIs(result[key], False)
        self.assertEqual((self.root / "intent.json").read_bytes(), self.original)
        self.assertFalse(any(row[0] == "enqueue" for row in self.manager.calls))

    def test_watch_tracks_until_saved_deadline_without_reset(self):
        with self.open() as process:
            result = self.watch(process)
        self.assertEqual(result["error"], "supervisor-watch-expired")
        self.assertEqual(result["watch"], {"started_monotonic": 1050, "last_monotonic": 1100,
                         "deadline": 1100, "observations": 5, "max_observations": 32, "sampled_elapsed_seconds": 50})
        self.assertEqual(len(self.observer.calls), 10)
        self.assert_closed_permissions(result)

    def test_watch_shorter_deadline_and_last_wait_are_inclusive(self):
        waits = []
        def wait(seconds):
            waits.append(seconds)
            self.now += seconds
            return False
        with self.open() as process:
            result = self.watch(process, deadline=1071, wait=wait)
        self.assertEqual(waits, [10, 10, 1])
        self.assertEqual(result["watch"]["deadline"], 1071)
        self.assertEqual(result["watch"]["observations"], 3)
        self.assertEqual(result["error"], "supervisor-watch-expired")

    def test_fractional_interval_does_not_false_reject_rounding(self):
        with self.open() as process:
            result = self.watch(process, deadline=1050.3, interval=0.1)
        self.assertEqual(result["error"], "supervisor-watch-expired")
        self.assertGreater(result["watch"]["observations"], 1)

    def test_observation_limit_stops_before_an_extra_wait(self):
        with self.open() as process:
            result = self.watch(process, max_observations=2)
        self.assertEqual(result["error"], "supervisor-watch-observation-limit")
        self.assertEqual(result["watch"]["observations"], 2)
        self.assertEqual(self.now, 1060)
        self.assert_closed_permissions(result)

    def test_observation_limit_rejects_coercions_or_unbounded_values(self):
        for value in (None, True, False, 0, -1, 1.0, "1", 4097):
            with self.subTest(value=value), self.open() as process:
                result = self.watch(process, max_observations=value)
                self.assertEqual(result["state"], "recovery_unresolved")
        self.assertEqual(self.observer.calls, [])

    def test_subprecision_interval_cannot_spin_at_an_unchanged_clock(self):
        with self.open() as process:
            result = self.watch(process, interval=1e-300, wait=lambda _: False)
        self.assertEqual(result["error"], "supervisor-watch-unconfirmed")
        self.assertEqual(len(self.observer.calls), 2)

    def test_watch_holds_lock_during_every_local_wait(self):
        calls = []
        def wait(seconds):
            with self.assertRaises(BlockingIOError), self.open():
                self.fail("contender acquired retained lock")
            calls.append(seconds)
            self.now += seconds
            return len(calls) == 3
        with self.open() as process:
            result = self.watch(process, wait=wait)
            with self.assertRaises(BlockingIOError), self.open():
                self.fail("watch exit released context lock")
        self.assertEqual(result["error"], "supervisor-watch-stopped")
        self.assertEqual(len(calls), 3)
        self.assert_closed_permissions(result)

    def test_stop_before_first_observation_remains_unresolved(self):
        with self.open() as process:
            result = self.watch(process, stop=lambda: True)
        self.assertEqual(result["error"], "supervisor-watch-stopped")
        self.assertEqual(self.observer.calls, [])
        self.assertEqual(len(self.notices), 2)  # Includes setup's lost-enqueue notice.
        self.assert_closed_permissions(result)

    def test_stop_between_ticks_prevents_another_observation(self):
        def wait(seconds):
            self.now += seconds
            return False
        with self.open() as process:
            result = self.watch(process, stop=lambda: self.now > 1050, wait=wait)
        self.assertEqual(result["error"], "supervisor-watch-stopped")
        self.assertEqual(len(self.observer.calls), 2)

    def test_wait_interrupt_is_not_success_even_with_no_clock_advance(self):
        with self.open() as process:
            result = self.watch(process, wait=lambda _: True)
        self.assertEqual(result["error"], "supervisor-watch-stopped")
        self.assert_closed_permissions(result)

    def test_early_wait_return_refuses_busy_spin(self):
        with self.open() as process:
            result = self.watch(process, wait=lambda _: False)
        self.assertEqual(result["error"], "supervisor-watch-unconfirmed")
        self.assertEqual(len(self.observer.calls), 2)

    def test_stop_and_wait_require_strict_boolean_receipts(self):
        for value in (None, 0, 1, "false", [], {}):
            for boundary in ("stop", "wait"):
                with self.subTest(value=value, boundary=boundary), self.open() as process:
                    result = self.watch(process, **{boundary: lambda *_, value=value: value})
                    self.assertEqual(result["error"], "supervisor-watch-unconfirmed")
                    self.assert_closed_permissions(result)

    def test_wait_and_stop_exceptions_are_redacted_and_latched(self):
        def fail(*_):
            raise OSError(errno.EIO, "restricted supervisor details")
        for boundary in ("stop", "wait"):
            with self.subTest(boundary=boundary), self.open() as process:
                result = self.watch(process, **{boundary: fail})
                self.assertNotIn("restricted", str(result))
                with self.assertRaises(durable.Rejected):
                    self.watch(process)

    def test_invalid_budget_cannot_enter_observer_or_wait(self):
        for value in (True, False, 0, -1, float("inf"), float("nan"), "10", None):
            for field in ("deadline", "interval"):
                with self.subTest(value=value, field=field), self.open() as process:
                    result = self.watch(process, **{field: value})
                    self.assertEqual(result["state"], "recovery_unresolved")
        self.assertEqual(self.observer.calls, [])

    def test_expired_caller_deadline_never_observes(self):
        with self.open() as process:
            result = self.watch(process, deadline=1050)
        self.assertEqual(result["error"], "supervisor-watch-expired")
        self.assertEqual(self.observer.calls, [])

    def test_worker_exit_is_unverified_and_not_polled_or_restarted(self):
        def wait(seconds):
            self.now += seconds
            self.observer.state = "inactive_unverified"
            return False
        with self.open() as process:
            result = self.watch(process, wait=wait)
        self.assertEqual(result["error"], "supervisor-worker-outcome-unverified")
        self.assertEqual(result["watch"]["observations"], 2)
        self.assert_closed_permissions(result)

    def test_late_invocation_after_pending_is_bound_under_same_lock(self):
        self.observer.state, self.observer.invocation, self.observer.job = "pending", "", 22
        def wait(seconds):
            self.now += seconds
            self.observer.state, self.observer.invocation, self.observer.job = "running", "b" * 32, 0
            return False
        with self.open() as process:
            result = self.watch(process, deadline=1070, wait=wait)
        self.assertEqual(result["error"], "supervisor-watch-expired")
        record = durable.decode((self.root / "reconcile-observed.json").read_bytes())
        self.assertEqual(record["invocation_id"], "b" * 32)
        self.assert_closed_permissions(result)

    def test_replacement_invocation_after_wait_fails_closed(self):
        def wait(seconds):
            self.now += seconds
            self.observer.invocation = "c" * 32
            return False
        with self.open() as process:
            result = self.watch(process, wait=wait)
        self.assertEqual(result["state"], "recovery_unresolved")
        self.assertEqual(result["watch"]["observations"], 1)
        self.assertEqual(durable.decode((self.root / "reconcile-observed.json").read_bytes())["invocation_id"], "b" * 32)

    def test_owner_or_fence_loss_between_ticks_is_not_retried(self):
        for field in ("owner_change", "fenced"):
            def wait(seconds):
                self.now += seconds
                setattr(self.manager, field, field == "owner_change")
                return False
            self.now = 1050
            self.manager.owner_change, self.manager.fenced = False, True
            with self.subTest(field=field), self.open() as process:
                result = self.watch(process, wait=wait)
                self.assertEqual(result["state"], "recovery_unresolved")
                self.assert_closed_permissions(result)

    def test_clock_regression_or_boot_loss_during_wait_is_not_a_new_budget(self):
        for field in ("clock", "boot"):
            def wait(_):
                if field == "clock":
                    self.now -= 1
                else:
                    self.boot = "boot-b"
                return False
            self.now, self.boot = 1050, "boot-a"
            with self.subTest(field=field), self.open() as process:
                result = self.watch(process, wait=wait)
                self.assertEqual(result["error"], "supervisor-clock-continuation-required")
                self.assert_closed_permissions(result)

    def test_intent_or_request_tampering_during_wait_is_unresolved(self):
        for name in ("arm.json", "reconcile-request.json"):
            path = self.root / name
            original = path.read_bytes()
            def wait(seconds):
                self.now += seconds
                path.write_bytes(b'{}')
                return False
            self.now = 1050
            with self.subTest(name=name), self.open() as process:
                result = self.watch(process, wait=wait)
                self.assertEqual(result["state"], "recovery_unresolved")
            path.write_bytes(original)

    def test_slow_observation_cannot_get_extra_wait(self):
        self.observer.on_observe = lambda: setattr(self, "now", 1100)
        with self.open() as process:
            result = self.watch(process, wait=lambda _: self.fail("late wait"))
        self.assertEqual(result["state"], "recovery_unresolved")
        self.assertEqual(len(self.observer.calls), 1)

    def test_alert_transport_attempt_survives_receipt_failure(self):
        def fail(_):
            raise OSError(errno.ENOSPC, "restricted disk path")
        self.persist = fail
        with self.open() as process:
            result = self.watch(process, stop=lambda: True)
        self.assertFalse(result["alert"]["receipt_persisted"])
        self.assertTrue(result["alert"]["transport_delivered"])

    def test_status_snapshot_cannot_modify_loop_or_job(self):
        with self.open() as process:
            result = self.watch(process, wait=lambda _: True)
            result["watch"]["deadline"] = 9999
            result["job"]["invocation_id"] = "c" * 32
            self.assertEqual(process.status()["watch"]["deadline"], 1100)
            self.assertEqual(process.status()["job"]["invocation_id"], "b" * 32)

    def test_closed_context_or_completed_one_shot_cannot_begin_watch(self):
        with self.open() as process:
            process.observe_pending(observer=self.observer, deadline=1100)
            with self.assertRaises(durable.Rejected):
                self.watch(process)
        with self.assertRaises(durable.Rejected):
            self.watch(process)

    def test_successful_dispatch_can_be_followed_without_releasing_lock(self):
        # New synthetic installation request; no real manager dispatch occurs.
        (self.root / "reconcile-request.json").unlink()
        with self.open(existing=False) as process:
            result = process.reconcile(deadline=1100)
            self.assertEqual(result["state"], "recovery_enqueued")
            self.manager.calls.clear()
            result = self.watch(process, wait=lambda _: True)
            with self.assertRaises(durable.Rejected):
                process.reconcile(deadline=1100)
        self.assertEqual(result["error"], "supervisor-watch-stopped")
        self.assert_closed_permissions(result)

    def test_uncertain_dispatch_cannot_enter_watch(self):
        (self.root / "reconcile-request.json").unlink()
        self.manager.failure = OSError(errno.EIO, "lost reply")
        with self.open(existing=False) as process:
            process.reconcile(deadline=1100)
            with self.assertRaises(durable.Rejected):
                self.watch(process)
        self.assertEqual(self.observer.calls, [])

    def test_real_sigterm_interrupts_event_wait_without_success_or_redispatch(self):
        package = str(Path(__file__).resolve().parent.parent)
        source = r'''
import json, os, signal, sys, threading
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[1] + "/tests")
from host_recovery import supervisor
from test_supervisor import ScriptedManager
from test_pending_jobs import ScriptedObserver
from host_recovery.durable import decode
root = sys.argv[2]
with open(root + "/intent.json", "rb") as f:
    owner = {**decode(f.read())["owner"], "invocation_id": "3" * 32}
stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop.set())
def wait(seconds):
    os.write(1, b"waiting-under-lock\n")
    return stop.wait(seconds)
with supervisor.recovery_owner(root, owner=owner, manager=ScriptedManager(),
        clock=lambda: 1050, boot_id=lambda: "boot-a", persist_alert=lambda _: None,
        transport_alert=lambda _: True, observe_existing=True) as process:
    result = process.watch_pending(observer=ScriptedObserver(), deadline=1100, interval=10,
                          max_observations=32, stop=stop.is_set, wait=wait)
    os.write(1, (json.dumps(result) + "\n").encode())
'''
        child = subprocess.Popen([sys.executable, "-I", "-c", source, package, str(self.root)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(ready.select(10), "child did not reach interruptible wait")
                self.assertEqual(child.stdout.readline(), b"waiting-under-lock\n")
            with self.assertRaises(BlockingIOError), self.open():
                self.fail("contender acquired child lock")
            child.terminate()
            out, err = child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, err.decode())
            result = durable.decode(out)
            self.assertEqual(result["error"], "supervisor-watch-stopped")
            self.assertTrue(result["alert"]["transport_delivered"])
            self.assert_closed_permissions(result)
            with self.open() as process:
                self.assertEqual(process.status()["state"], "recovery_dispatch_pending")
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

    def test_real_sigkill_during_wait_retains_request_binding_and_lock(self):
        package = str(Path(__file__).resolve().parent.parent)
        source = r'''
import os, sys, threading
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[1] + "/tests")
from host_recovery import supervisor
from test_supervisor import ScriptedManager
from test_pending_jobs import ScriptedObserver
from host_recovery.durable import decode
root = sys.argv[2]
with open(root + "/intent.json", "rb") as f:
    owner = {**decode(f.read())["owner"], "invocation_id": "3" * 32}
stop = threading.Event()
def wait(_):
    os.write(1, b"waiting-under-lock\n")
    return stop.wait(60)
with supervisor.recovery_owner(root, owner=owner, manager=ScriptedManager(),
        clock=lambda: 1050, boot_id=lambda: "boot-a", persist_alert=lambda _: None,
        transport_alert=lambda _: True, observe_existing=True) as process:
    process.watch_pending(observer=ScriptedObserver(), deadline=1100, interval=10,
                          max_observations=32, stop=stop.is_set, wait=wait)
'''
        child = subprocess.Popen([sys.executable, "-I", "-c", source, package, str(self.root)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(ready.select(10), "child did not reach interruptible wait")
                self.assertEqual(child.stdout.readline(), b"waiting-under-lock\n")
            with self.assertRaises(BlockingIOError), self.open():
                self.fail("second process acquired lock")
            before = (self.root / "reconcile-observed.json").read_bytes()
            child.kill()
            self.assertEqual(child.wait(timeout=10), -9)
            with self.open() as process:
                result = self.watch(process, wait=lambda _: True)
            self.assertEqual((self.root / "reconcile-observed.json").read_bytes(), before)
            self.assertEqual(result["error"], "supervisor-watch-stopped")
            self.assert_closed_permissions(result)
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
