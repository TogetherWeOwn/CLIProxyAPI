"""Historical claim observation; scripted manager, no peer revival or recovery."""
import errno
import os
import unittest
from unittest.mock import patch

from host_recovery import durable, supervisor
import test_worker


class ClaimReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_worker.WorkerClaimTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.case = self.fixture.case
        with self.case.open() as process:
            process.reconcile(deadline=1100)
            self.claim = self.fixture.claim(process)
        self.owner = {**self.case.owner, "invocation_id": "c" * 32}
        self.files = {p.name: p.read_bytes() for p in self.case.root.iterdir()}
        self.enqueues = len(self.case.enqueues())

    def open(self):
        return supervisor.recovery_owner(str(self.case.root), owner=self.owner, manager=self.case.manager,
            clock=lambda: self.case.now, boot_id=lambda: self.case.boot, persist_alert=self.case.persist,
            transport_alert=lambda value: self.case.notices.append(value) or True, observe_existing=True)

    def write(self, name, value):
        (self.case.root / name).write_bytes(durable.canonical(value))

    def restore_fixture(self):
        for name, raw in self.files.items():
            (self.case.root / name).write_bytes(raw)
        self.case.notices.clear()

    def assert_unresolved(self, value):
        self.case.assert_fenced(value)
        self.assertFalse(value["saved_peer_liveness_proven"])
        self.assertEqual(len(self.case.enqueues()), self.enqueues)

    def test_restart_observes_same_invocation_without_reviving_claim_or_writing(self):
        with self.open() as process:
            self.assertIsNone(process.error)
            state = process.observe_pending(observer=self.fixture.observer, deadline=9999)
            self.assertEqual(state["state"], "recovery_job_running")
            self.assertTrue(state["saved_claim_observed"])
            self.assertEqual(process.pending_request["deadline"], 1100)
            with self.assertRaises(durable.Rejected):
                self.fixture.claim(process)
            with self.assertRaises(durable.Rejected):
                process.reconcile(deadline=1100)
            self.assert_unresolved(state)
        self.assertEqual({p.name: p.read_bytes() for p in self.case.root.iterdir()}, self.files)

    def test_claim_observation_retains_lock_and_closed_reference_cannot_observe(self):
        with self.open() as process:
            with self.assertRaises(BlockingIOError), self.case.open():
                self.fail("historical claim inspection released the installation lock")
            value = process.observe_pending(observer=self.fixture.observer, deadline=1100)
            self.assert_unresolved(value)
        with self.assertRaises(durable.Rejected):
            process.observe_pending(observer=self.fixture.observer, deadline=1100)
        with self.assertRaises(durable.Rejected):
            self.fixture.claim(process)

    def test_no_numeric_pid_authentication_or_peer_lookup_on_reopen(self):
        with patch("os.pidfd_open", side_effect=AssertionError("historical PID is not authority")):
            with self.open() as process:
                state = process.observe_pending(observer=self.fixture.observer, deadline=1100)
                self.assertEqual(state["state"], "recovery_job_running")
                self.assert_unresolved(state)
        # Only the original live claim called observe_worker, never this reopen.
        self.assertEqual(self.fixture.claims, 3)

    def test_changed_claim_identity_permission_or_schema_refuses(self):
        changes = ({"request_id": "d" * 64}, {"intent_sha256": "e" * 64}, {"nonce": "bad\nnonce"},
                   {"schema": "other"}, {"restoration_permission": True}, {"start_permission": 0},
                   {"extra": False}, {"supervisor_owner": self.owner})
        for change in changes:
            with self.subTest(change=change):
                self.restore_fixture()
                self.write("reconcile-worker.json", {**self.claim, **change})
                with self.open() as process:
                    self.assertEqual(process.status()["state"], "recovery_unresolved")
                    self.assertTrue(process.status()["alert"]["transport_delivered"])
                    self.assert_unresolved(process.status())

    def test_historical_peer_and_worker_schema_refuse_coercions(self):
        changes = ({"peer": {**self.claim["peer"], "pid": True}},
                   {"peer": {**self.claim["peer"], "uid": 0}},
                   {"peer": {**self.claim["peer"], "gid": -1}},
                   {"worker": {**self.claim["worker"], "pid": self.claim["peer"]["pid"] + 1}},
                   {"worker": {**self.claim["worker"], "state": "inactive_unverified"}},
                   {"worker": {**self.claim["worker"], "invocation_id": self.owner["invocation_id"]}},
                   {"worker": {**self.claim["worker"], "invocation_id": self.case.owner["invocation_id"]}},
                   {"worker": {**self.claim["worker"], "cgroup": "/a/../b"}})
        for change in changes:
            with self.subTest(change=change):
                self.restore_fixture()
                self.write("reconcile-worker.json", {**self.claim, **change})
                with self.open() as process:
                    self.assertIsNotNone(process.error)
                    self.assert_unresolved(process.status())

    def test_missing_or_conflicting_original_invocation_binding_refuses(self):
        path = self.case.root / "reconcile-observed.json"
        for value in (None, {}, {"invocation_id": "d" * 32}):
            with self.subTest(value=value):
                self.restore_fixture()
                if value is None:
                    path.unlink()
                else:
                    self.write(path.name, value)
                with self.open() as process:
                    self.assertIsNotNone(process.error)
                    self.assert_unresolved(process.status())

    def test_private_mode_and_staged_ambiguous_claim_refuse(self):
        path = self.case.root / "reconcile-worker.json"
        os.chmod(path, 0o644)
        with self.open() as process:
            self.assertIsNotNone(process.error)
        os.chmod(path, 0o600)
        self.write(".stage-reconcile-worker-uncertain", {})
        with self.open() as process:
            self.assertIsNotNone(process.error)
            self.assert_unresolved(process.status())

    def test_changed_worker_invocation_never_adopted(self):
        self.fixture.invocation = "d" * 32
        with self.open() as process:
            result = process.observe_pending(observer=self.fixture.observer, deadline=1100)
            self.assertEqual(result["state"], "recovery_unresolved")
            self.assertIsNotNone(result["error"])
            self.assert_unresolved(result)

    def test_saved_claim_change_during_observation_is_sticky_unresolved(self):
        original = self.fixture.observer.observe
        def observe(*args, **kw):
            self.write("reconcile-worker.json", {**self.claim, "nonce": "replacement"})
            return original(*args, **kw)
        self.fixture.observer.observe = observe
        with self.open() as process:
            result = process.observe_pending(observer=self.fixture.observer, deadline=1100)
            self.assertEqual(result["state"], "recovery_unresolved")
            self.assert_unresolved(result)
            with self.assertRaises(durable.Rejected):
                self.fixture.claim(process)
        self.assertEqual((self.case.root / "intent.json").read_bytes(), self.case.original)

    def test_missing_old_peer_or_successful_worker_exit_is_not_completion(self):
        def inactive(request_id, *, deadline):
            value = self.fixture.observe(request_id, deadline=deadline)
            value["state"] = "inactive_unverified"
            return value
        self.fixture.observer.observe = inactive
        with self.open() as process:
            value = process.observe_pending(observer=self.fixture.observer, deadline=1100)
            self.assertEqual(value["state"], "recovery_job_inactive_unverified")
            self.assert_unresolved(value)
            self.assertTrue(process.worker_attempted)

    def test_clock_boot_or_fence_loss_never_renews_request(self):
        for kind in ("expired", "cross-boot", "fence"):
            with self.subTest(kind=kind):
                self.case.now, self.case.boot, self.case.manager.fenced = 1050, "boot-a", True
                if kind == "expired":
                    self.case.now = 1180
                elif kind == "cross-boot":
                    self.case.boot = "boot-b"
                    self.owner["boot_id"] = "boot-b"
                else:
                    self.owner["boot_id"] = "boot-a"
                    self.case.manager.fenced = False
                with self.open() as process:
                    if process.error is None:
                        process.observe_pending(observer=self.fixture.observer, deadline=1100)
                    self.assertIsNotNone(process.error)
                    self.assert_unresolved(process.status())
                self.assertEqual({p.name: p.read_bytes() for p in self.case.root.iterdir()}, self.files)

    def test_claim_read_failure_still_attempts_transport_when_persistence_fails(self):
        original = supervisor.private_record
        for code in (errno.EIO, errno.ENOSPC):
            with self.subTest(code=code):
                self.case.notices.clear()
                def read(fd, name):
                    if name == "reconcile-worker.json":
                        raise OSError(code, "restricted synthetic path")
                    return original(fd, name)
                def fail(_):
                    raise OSError(code, "receipt unavailable")
                self.case.persist = fail
                with patch.object(supervisor, "private_record", side_effect=read), self.open() as process:
                    result = process.status()
                    self.assertFalse(result["alert"]["receipt_persisted"])
                    self.assertTrue(result["alert"]["transport_delivered"])
                    self.assertEqual(len(self.case.notices), 1)
                    self.assert_unresolved(result)

    def test_new_supervisor_cannot_claim_unclaimed_old_request(self):
        # Even without a prior claim, a replacement cannot impersonate its owner.
        (self.case.root / "reconcile-worker.json").unlink()
        with self.open() as process:
            self.assertIsNone(process.error)
            with self.assertRaises(durable.Rejected):
                self.fixture.claim(process)
            self.assertFalse((self.case.root / "reconcile-worker.json").exists())
            self.assert_unresolved(process.status())
