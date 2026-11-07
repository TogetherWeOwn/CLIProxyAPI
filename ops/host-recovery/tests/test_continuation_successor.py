"""Append-only recovery succession; authorization/manager boundaries are scripted."""
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

from host_recovery import continuation, durable, journal
import test_recovery_continuation as first


class SuccessorTests(unittest.TestCase):
    setUp = first.ContinuationTests.setUp
    persist_alert = first.ContinuationTests.persist_alert
    admit = first.ContinuationTests.admit
    transport = first.ContinuationTests.transport
    reopen = first.ContinuationTests.reopen
    reopened = first.ContinuationTests.reopened
    prepare = first.ContinuationTests.prepare
    run_continuation = first.ContinuationTests.run_continuation
    assert_fenced = first.ContinuationTests.assert_fenced

    def successor(self, previous, *, boot="boot-b", now=6, number=2):
        engine = self.reopen()
        self.boot, self.time = boot, now
        value = {**copy.deepcopy(previous), "schema": "host-recovery-continuation-v2",
                 "previous_sha256": durable.digest(durable.canonical(previous)),
                 "continuation_id": "successor-" + str(number), "started_at": now, "deadline": now + 150,
                 "owner": {**previous["owner"], "boot_id": boot, "invocation_id": "owner-" + str(number)}}
        self.boundary.authorize_continuation = lambda intent, approved, deadline: self.boundary.event(
            "continuation-authorization", deadline)
        self.boundary.reconcile_continuation = lambda intent, history, approved, deadline: self.boundary.event(
            "prior-owners-quiescent", deadline)
        return engine, value

    def consumed(self, *, complete=False):
        engine, value = self.prepare()
        if not complete:
            self.boundary.overrides["fence"] = False
        result = self.run_continuation(engine, value)
        self.assert_fenced(result)
        self.assertTrue((self.state / "continuation-request.json").exists())
        self.assertEqual((self.state / "continuation-outcome.json").exists(), complete)
        return value

    def test_new_approved_successor_preserves_predecessor_and_original_records(self):
        previous = self.consumed()
        before = {name: (self.state / name).read_bytes() for name in
                  ("intent.json", "arm.json", "continuation-request.json")}
        engine, value = self.successor(previous)
        result = self.run_continuation(engine, value)
        self.assert_fenced(result)
        self.assertTrue(result["continuation_baseline_restored"])
        self.assertEqual(self.boundary.calls[:3], ["continuation-authorization", "prior-owners-quiescent",
                                                  "recovery-preflight"])
        self.assertEqual(self.file.read_bytes(), b"original-baseline-config")
        for name, raw in before.items():
            self.assertEqual((self.state / name).read_bytes(), raw)
        outcome = durable.decode((self.state / "continuation-outcome-02.json").read_bytes())
        self.assertEqual(outcome["continuation_sha256"], durable.digest(durable.canonical(value)))
        self.assertFalse(outcome["original_target_met"])
        self.assertFalse(outcome["installation_settled"])
        self.assertEqual(engine.meter.arm["monotonic"], 1000)
        self.assertEqual(engine.meter.deadline("recovery"), 156)

    def test_complete_looking_previous_outcome_never_skips_current_oracles(self):
        previous = self.consumed(complete=True)
        saved = (self.state / "continuation-outcome.json").read_bytes()
        engine, value = self.successor(previous)
        self.boundary.overrides["baseline-oracle"] = {}
        self.assert_fenced(self.run_continuation(engine, value))
        self.assertIn("restore", self.boundary.calls)
        self.assertNotIn("start-old", self.boundary.calls)
        self.assertFalse((self.state / "continuation-outcome-02.json").exists())
        self.assertEqual((self.state / "continuation-outcome.json").read_bytes(), saved)

    def test_missing_false_nonboolean_or_failed_retirement_never_consumes_successor(self):
        for reply in (False, 1, None, OSError(errno.EIO, "restricted"), "missing"):
            with self.subTest(reply=type(reply)):
                self.setUp()
                previous = self.consumed()
                engine, value = self.successor(previous)
                if reply == "missing":
                    del self.boundary.reconcile_continuation
                else:
                    self.boundary.overrides["prior-owners-quiescent"] = reply
                self.assert_fenced(self.run_continuation(engine, value))
                self.assertNotIn("recovery-preflight", self.boundary.calls)
                self.assertFalse((self.state / "continuation-request-02.json").exists())
                self.assertEqual(self.file.read_bytes(), b"partial-candidate")

    def test_old_request_unapproved_successor_and_wrong_tip_never_touch_boundary(self):
        for change in ("replay", "ordinary", "unapproved", "wrong-tip", "same-owner", "same-id"):
            with self.subTest(change=change):
                self.setUp()
                previous = self.consumed()
                engine, value = self.successor(previous)
                if change == "replay":
                    value = previous
                elif change == "ordinary":
                    self.assert_fenced(engine.resume())
                    self.assertEqual(self.boundary.calls, [])
                    continue
                elif change == "unapproved":
                    self.assert_fenced(engine.resume(continuation=value, continuation_sha256="0" * 64))
                    self.assertEqual(self.boundary.calls, [])
                    continue
                elif change == "wrong-tip":
                    value["previous_sha256"] = "0" * 64
                elif change == "same-owner":
                    value["owner"] = previous["owner"]
                else:
                    value["continuation_id"] = previous["continuation_id"]
                self.assert_fenced(self.run_continuation(engine, value))
                self.assertEqual(self.boundary.calls, [])

    def test_gaps_orphans_unknown_stages_and_noncanonical_history_refuse(self):
        for change in ("gap", "orphan", "unknown", "stage", "private", "noncanonical", "outcome"):
            with self.subTest(change=change):
                self.setUp()
                previous = self.consumed()
                engine, value = self.successor(previous)
                path = self.state / "continuation-request.json"
                if change == "gap":
                    path.rename(self.state / "continuation-request-03.json")
                elif change == "orphan":
                    durable.atomic_write(self.log.fd, "continuation-outcome-02.json", b"{}\n")
                elif change in ("unknown", "stage"):
                    durable.atomic_write(self.log.fd, "continuation-unknown.json" if change == "unknown"
                                        else ".stage-continuation-request-02.json", b"{}\n")
                elif change == "private":
                    path.chmod(0o644)
                elif change == "noncanonical":
                    path.write_bytes(path.read_bytes() + b"\n")
                else:
                    durable.atomic_write(self.log.fd, "continuation-outcome.json", b"{}\n")
                self.assert_fenced(self.run_continuation(engine, value))
                self.assertEqual(self.boundary.calls, [])

    def test_retained_history_change_during_reconciliation_refuses_before_consumption(self):
        for name in ("intent.json", "arm.json", "continuation-request.json", "continuation-outcome.json"):
            with self.subTest(name=name):
                self.setUp()
                previous = self.consumed(complete=True)
                engine, value = self.successor(previous)
                def change():
                    (self.state / name).write_bytes(b"{}\n")
                    return True
                self.boundary.overrides["prior-owners-quiescent"] = change
                self.assert_fenced(self.run_continuation(engine, value))
                self.assertEqual(self.boundary.calls[-1], "prior-owners-quiescent")
                self.assertFalse((self.state / "continuation-request-02.json").exists())

    def test_retirement_deadline_and_boot_changes_do_not_renew_detection(self):
        for drift in ("boot", "clock", "detection"):
            with self.subTest(drift=drift):
                self.setUp()
                previous = self.consumed()
                engine, value = self.successor(previous)
                def change():
                    if drift == "boot":
                        self.boot = "boot-c"
                    else:
                        self.time = 5 if drift == "clock" else 26
                    return True
                self.boundary.overrides["prior-owners-quiescent"] = change
                self.assert_fenced(self.run_continuation(engine, value))
                self.assertFalse((self.state / "continuation-request-02.json").exists())
                self.assertNotIn("recovery-preflight", self.boundary.calls)

    def test_successor_publication_faults_preserve_prior_request_and_attempt_alert(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point):
                    self.setUp()
                    previous = self.consumed()
                    original = (self.state / "continuation-request.json").read_bytes()
                    engine, value = self.successor(previous)
                    reached = []
                    def fail(stage):
                        if stage == point:
                            reached.append(stage)
                            raise OSError(code, "restricted")
                    self.log.fault, self.receipt_fault = fail, True
                    result = self.run_continuation(engine, value)
                    self.assert_fenced(result)
                    self.assertEqual(reached, [point])
                    self.assertEqual(self.boundary.calls, ["continuation-authorization", "prior-owners-quiescent"])
                    self.assertEqual((self.state / "continuation-request.json").read_bytes(), original)
                    self.assertTrue(result["alert"]["transport_delivered"])
                    self.assertFalse(result["alert"]["receipt_persisted"])

    def test_successor_requires_new_owner_across_reboot_and_keeps_elapsed_unknown(self):
        previous = self.consumed()
        engine, value = self.successor(previous, boot="boot-c", now=1)
        result = self.run_continuation(engine, value)
        self.assert_fenced(result)
        self.assertTrue(result["continuation_baseline_restored"])
        self.assertIsNone(engine.meter.events[0]["original_elapsed_seconds"])

    def test_entire_chain_is_retired_and_reused_older_owner_is_rejected(self):
        previous = self.consumed()
        owners = [previous["owner"]["invocation_id"]]
        for number in (2, 3):
            engine, value = self.successor(previous, now=5 + number, number=number)
            observed = []
            def retirement(intent, history, approved, deadline):
                observed.extend(old["owner"]["invocation_id"] for old in history)
                return self.boundary.event("prior-owners-quiescent", deadline)
            self.boundary.reconcile_continuation = retirement
            self.boundary.overrides["fence"] = False
            self.assert_fenced(self.run_continuation(engine, value))
            self.assertEqual(observed, owners)
            owners.append(value["owner"]["invocation_id"])
            previous = value
        engine, value = self.successor(previous, now=9, number=4)
        value["owner"]["invocation_id"] = owners[0]
        self.assert_fenced(self.run_continuation(engine, value))
        self.assertEqual(self.boundary.calls, [])

    def test_chain_bound_refuses_before_authorization_without_deleting_history(self):
        previous = self.consumed()
        for number in range(2, continuation.MAX_CONTINUATIONS + 1):
            engine, value = self.successor(previous, now=5 + number, number=number)
            self.boundary.overrides["fence"] = False
            self.assert_fenced(self.run_continuation(engine, value))
            previous = value
        before = set(os.listdir(self.log.fd))
        engine, value = self.successor(previous, now=20, number=9)
        self.assert_fenced(self.run_continuation(engine, value))
        self.assertEqual(self.boundary.calls, [])
        self.assertEqual(set(os.listdir(self.log.fd)), before)

    def test_sigkill_after_request_consumption_requires_new_lock_owner_and_approval(self):
        engine, previous = self.prepare()
        original = {name: (self.state / name).read_bytes() for name in ("intent.json", "arm.json")}
        with tempfile.TemporaryDirectory(prefix="continuation-owner-kill-") as root:
            state = Path(root)
            state.chmod(0o700)
            for name, raw in original.items():
                (state / name).write_bytes(raw)
                (state / name).chmod(0o600)
            program = '''
import os,signal,sys
sys.path.insert(0,sys.argv[1])
from host_recovery import coordinator,durable,journal
approved=durable.decode(sys.argv[3].encode())
class Boundary:
    def authorize_continuation(self,*args,**kwargs): return True
    def recovery_preflight(self,*args,**kwargs):
        print("consumed-before-recovery",flush=True)
        signal.pause()
with durable.installation_lock(sys.argv[2],approved["owner"]) as (fd,_):
    log=journal.Journal(fd)
    engine=coordinator.AttemptCoordinator(log,Boundary(),lambda:5,lambda:"boot-b",lambda n:None,lambda n:True)
    engine.resume(continuation=approved,continuation_sha256=durable.digest(durable.canonical(approved)))
'''
            child = subprocess.Popen([sys.executable, "-I", "-c", program,
                str(Path(__file__).resolve().parents[1]), str(state), durable.canonical(previous).decode()],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(10), "owner did not consume request")
                    self.assertEqual(child.stdout.readline(), b"consumed-before-recovery\n")
                with self.assertRaises(BlockingIOError):
                    with durable.installation_lock(state, previous["owner"]):
                        pass
                child.kill()
                _, stderr = child.communicate(timeout=10)
                self.assertEqual(child.returncode, -signal.SIGKILL, stderr.decode())
                self.assertEqual((state / "continuation-request.json").read_bytes(), durable.canonical(previous))
                with durable.installation_lock(state, previous["owner"]) as (fd, _):
                    self.state, self.log = state, journal.Journal(fd)
                    engine, value = self.successor(previous)
                    result = self.run_continuation(engine, value)
                    self.assert_fenced(result)
                    self.assertTrue(result["continuation_baseline_restored"])
                    self.assertEqual(self.file.read_bytes(), b"original-baseline-config")
                    self.assertEqual(self.boundary.calls[:2], ["continuation-authorization", "prior-owners-quiescent"])
                    for name, raw in original.items():
                        self.assertEqual((state / name).read_bytes(), raw)
            finally:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=10)
