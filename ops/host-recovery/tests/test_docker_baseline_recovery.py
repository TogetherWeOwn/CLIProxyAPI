"""Real synthetic root restoration; task/daemon boundary is scripted here."""
from contextlib import contextmanager
import errno
import select
import signal
import time
import unittest
from unittest.mock import patch

import docker_baseline_fixture as fixture
from host_recovery import durable
from test_installation import approve
import test_write_set as write_set_tests


class DockerBaselineRecoveryTests(unittest.TestCase):
    setUp = write_set_tests.WriteSetTests.setUp
    put = staticmethod(write_set_tests.WriteSetTests.put)
    mutate = write_set_tests.WriteSetTests.mutate
    assert_baseline = write_set_tests.WriteSetTests.assert_baseline

    def inputs(self):
        return {"root": self.root, "backup": approve(self.backup), "roots": self.approvals,
                "paths": self.paths, "pin": self.pin}

    def restore(self, **kwargs):
        return fixture.restore_stopped(self.inputs(), object_id="a" * 64,
            check=lambda **_: self.fenced, deadline=time.monotonic() + 60, **kwargs)

    def prepared_resume(self, *, continued=False):
        now = [1000.0]
        clock_patch = patch.object(fixture.time, "monotonic", side_effect=lambda: now[0])
        clock_patch.start()
        self.addCleanup(clock_patch.stop)
        value = fixture.intent(self.pin, "a" * 64)
        with durable.installation_lock(str(self.root), value["owner"]):
            fixture.prepare_resume(self.inputs(), object_id="a" * 64)
        now[0] += 30 if continued else 1
        self.mutate()
        calls = []
        def verified(value, *, deadline):
            self.assert_baseline()
            calls.append("verified")
            return {"baseline_sha256": self.pin, "object_id": "a" * 64,
                    "original_image": True, "original_replay": True, "new_plugin_absent": True,
                    "complete_write_set": True, "metadata_verified": True, "all_writers_stopped": True}
        def start(value, receipt, *, deadline):
            self.assert_baseline()
            self.assertEqual(calls, ["verified"])
            calls.append("start")
            return True
        def ready(value, *, deadline):
            self.assertEqual(calls, ["verified", "start"])
            calls.append("ready")
            return True
        return calls, dict(object_id="a" * 64, check=lambda **_: self.fenced,
                           verify_stopped=verified, start_old=start, old_ready=ready, deadline=1100)

    def resume(self, arguments):
        value = fixture.intent(self.pin, "a" * 64)
        with durable.installation_lock(str(self.root), value["owner"]):
            return fixture.resume_stopped(self.inputs(), **arguments)

    def test_coordinator_reopens_original_journal_and_restores_before_start(self):
        calls, arguments = self.prepared_resume()
        originals = [(self.root / "journal" / name).read_bytes() for name in ("intent.json", "arm.json")]
        result = self.resume(arguments)
        self.assertEqual(calls, ["verified", "start", "ready"])
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertIs(result["start_fenced"], True)
        self.assertIs(result["production_acceptance"], False)
        self.assertEqual(originals, [(self.root / "journal" / name).read_bytes() for name in ("intent.json", "arm.json")])
        with self.assertRaisesRegex(durable.Rejected, "fresh-original-journal"):
            self.resume(arguments)
        self.assertEqual(calls.count("start"), 1)

    def test_late_coordinator_consumes_continuation_without_renewing_original_target(self):
        calls, arguments = self.prepared_resume(continued=True)
        result = self.resume(arguments)
        self.assertEqual(calls, ["verified", "start", "ready"])
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertIs(result["continuation_baseline_restored"], True)
        self.assertIs(result["original_target_met"], False)
        saved = durable.decode((self.root / "journal/continuation-outcome.json").read_bytes())
        self.assertIs(saved["installation_settled"], False)
        with self.assertRaises(durable.Rejected):
            self.resume(arguments)
        self.assertEqual(calls.count("start"), 1)

    def test_coordinator_never_starts_after_incomplete_stopped_oracle(self):
        calls, arguments = self.prepared_resume()
        arguments["verify_stopped"] = lambda *_, **__: {"filesystem_verified": True}
        with self.assertRaisesRegex(durable.Rejected, "coordinator-recovery-unconfirmed"):
            self.resume(arguments)
        self.assertEqual(calls, [])

    def test_coordinator_never_starts_after_verifier_callback_changes_restored_bytes(self):
        calls, arguments = self.prepared_resume()
        original = arguments["verify_stopped"]
        def mutate(value, **kwargs):
            receipt = original(value, **kwargs)
            self.put(self.paths["config"] / "config.yaml", b"changed after verification")
            return receipt
        arguments["verify_stopped"] = mutate
        with self.assertRaisesRegex(durable.Rejected, "coordinator-recovery-unconfirmed"):
            self.resume(arguments)
        self.assertEqual(calls, ["verified"])

    def test_coordinator_lost_stopped_boundary_never_restores_or_starts(self):
        calls, arguments = self.prepared_resume()
        before = (self.paths["config"] / "config.yaml").read_bytes()
        self.fenced = False
        with self.assertRaisesRegex(durable.Rejected, "coordinator-recovery-unconfirmed"):
            self.resume(arguments)
        self.assertEqual(calls, [])
        self.assertEqual((self.paths["config"] / "config.yaml").read_bytes(), before)

    def test_coordinator_refuses_original_object_mismatch_before_effects(self):
        calls, arguments = self.prepared_resume()
        arguments["object_id"] = "b" * 64
        with self.assertRaisesRegex(durable.Rejected, "fresh-original-journal"):
            self.resume(arguments)
        self.assertEqual(calls, [])

    def test_coordinator_readiness_failure_never_publishes_success(self):
        calls, arguments = self.prepared_resume(continued=True)
        arguments["old_ready"] = lambda *_, **__: False
        with self.assertRaisesRegex(durable.Rejected, "coordinator-recovery-unconfirmed"):
            self.resume(arguments)
        self.assertEqual(calls, ["verified", "start"])
        self.assertFalse((self.root / "journal/continuation-outcome.json").exists())
        self.assertTrue((self.root / "journal/intent.json").exists())
        self.assertTrue((self.root / "journal/continuation-request.json").exists())

    def test_coordinator_continuation_publication_failure_prevents_effects(self):
        calls, arguments = self.prepared_resume(continued=True)
        original = fixture.journal.Journal._write
        reached = []
        def fail(log, name, value):
            if name != "continuation-request.json":
                return original(log, name, value)
            def fault(stage):
                if stage == "rename":
                    reached.append(stage)
                    raise OSError(errno.ENOSPC, "synthetic consumption failure")
            log.fault = fault
            return original(log, name, value)
        with patch.object(fixture.journal.Journal, "_write", new=fail):
            with self.assertRaisesRegex(durable.Rejected, "coordinator-recovery-unconfirmed"):
                self.resume(arguments)
        self.assertEqual(reached, ["rename"])
        self.assertEqual(calls, [])
        self.assertEqual((self.paths["config"] / "config.yaml").read_bytes(), b"partial-candidate-config")

    def worker_death(self):
        value = fixture.intent(self.pin, "a" * 64)
        with durable.installation_lock(str(self.root), value["owner"]):
            return fixture.rehearse_worker_death(self.inputs(), object_id="a" * 64,
                check=lambda **_: self.fenced, deadline=time.monotonic() + 60)

    def test_recovery_helper_sigkill_leaves_rejected_partial_state_until_fresh_retry(self):
        row = self.worker_death()
        self.assertEqual(row, {"hook": "directory-fsync", "sigkill_observed": True, "worker_reaped": True,
            "partial_rename_observed": True, "partial_baseline_rejected": True,
            "start_allowed": False, "supervisor_death_tested": False})
        self.assertEqual((self.paths["auth"] / "nested/unrelated.bin").read_bytes(), b"unrelated-provider\0bytes")
        self.assertEqual((self.paths["config"] / "config.yaml").read_bytes(), b"synthetic-worker-partial-config")
        with self.restore():
            self.assert_baseline()

    def test_reopened_coordinator_restores_after_real_recovery_helper_death(self):
        calls, arguments = self.prepared_resume(continued=True)
        originals = {path.name: path.read_bytes() for path in (self.root / "journal").iterdir()}
        with self.restore():
            pass
        self.worker_death()
        self.assertEqual({path.name: path.read_bytes() for path in (self.root / "journal").iterdir()}, originals)
        self.assertEqual(calls, [])
        result = self.resume(arguments)
        self.assertEqual(calls, ["verified", "start", "ready"])
        for name, raw in originals.items():
            self.assertEqual((self.root / "journal" / name).read_bytes(), raw)
        self.assertIs(result["continuation_baseline_restored"], True)
        self.assertIs(result["original_target_met"], False)
        self.assertIs(result["start_fenced"], True)
        self.assert_baseline()

    def test_recovery_helper_death_refuses_before_mutation_without_stopped_boundary(self):
        before = (self.paths["config"] / "config.yaml").read_bytes()
        self.fenced = False
        with patch.object(fixture.os, "fork") as fork:
            with self.assertRaisesRegex(durable.Rejected, "stopped-boundary-required"):
                self.worker_death()
        fork.assert_not_called()
        self.assertEqual((self.paths["config"] / "config.yaml").read_bytes(), before)

    def test_recovery_helper_normal_exit_is_not_counted_as_reached_sigkill(self):
        @contextmanager
        def no_hook(*args, **kwargs):
            yield {}
        with patch.object(fixture, "restore_stopped", side_effect=no_hook):
            with self.assertRaisesRegex(durable.Rejected, "death-hook-unconfirmed"):
                self.worker_death()

    def test_recovery_helper_death_requires_fresh_partial_baseline_rejection(self):
        original = fixture.write_set.WriteSetVerifier.verify_files
        calls = []
        def accept_partial(reader, value, *, deadline):
            calls.append(True)
            if len(calls) == 1:
                return original(reader, value, deadline=deadline)
            return {"filesystem_verified": True}
        with patch.object(fixture.write_set.WriteSetVerifier, "verify_files", new=accept_partial):
            with self.assertRaisesRegex(durable.Rejected, "partial-baseline-accepted"):
                self.worker_death()
        self.assertEqual(len(calls), 2)

    def test_dead_original_owner_releases_only_same_directory_lock_for_fresh_restoration(self):
        deadline = time.monotonic() + 60
        with fixture.original_lock_owner(self.inputs(), deadline=deadline) as owner:
            owner.prepare("a" * 64, deadline=deadline)
            original = dict(owner.originals)
            self.mutate()
            owner.retire(deadline=deadline)
            with owner.recovery_lock(deadline=deadline) as receipt:
                self.assertTrue(all(receipt[key] is True for key in (
                    "original_owner_sigkill_observed", "original_owner_reaped",
                    "live_owner_excluded_contender", "same_directory_lock_reacquired",
                    "original_intent_arm_unchanged")))
                self.assertIs(receipt["boot_changed"], False)
                self.assertIs(receipt["operational_supervisor_recovery"], False)
                with self.assertRaises(BlockingIOError):
                    with durable.installation_lock(str(self.root), owner.owner):
                        self.fail("second recovery owner overlapped")
                with self.restore():
                    self.assert_baseline()
                self.assertEqual(original, {name: (self.root / "journal" / name).read_bytes() for name in original})
            with self.assertRaisesRegex(durable.Rejected, "owner-retirement-required"):
                with owner.recovery_lock(deadline=deadline):
                    self.fail("recovery lock reused")
        with durable.installation_lock(str(self.root), owner.owner):
            pass

    def test_owner_transfer_rejects_replacement_installation_directory(self):
        deadline = time.monotonic() + 60
        with fixture.original_lock_owner(self.inputs(), deadline=deadline) as owner:
            owner.prepare("a" * 64, deadline=deadline)
            owner.retire(deadline=deadline)
            saved = self.root.with_name(self.root.name + ".saved")
            self.root.rename(saved)
            try:
                self.root.mkdir(mode=0o700)
                with self.assertRaisesRegex(durable.Rejected, "lock-directory-changed"):
                    with owner.recovery_lock(deadline=deadline):
                        self.fail("replacement directory yielded recovery")
            finally:
                self.root.rmdir()
                saved.rename(self.root)

    def test_live_original_owner_never_grants_a_recovery_lock(self):
        deadline = time.monotonic() + 60
        with fixture.original_lock_owner(self.inputs(), deadline=deadline) as owner:
            owner.prepare("a" * 64, deadline=deadline)
            with self.assertRaisesRegex(durable.Rejected, "owner-retirement-required"):
                with owner.recovery_lock(deadline=deadline):
                    self.fail("live original owner yielded recovery")
            owner.excluded()

    def test_original_owner_normal_signal_exit_is_not_a_sigkill_transfer(self):
        deadline = time.monotonic() + 60
        with fixture.original_lock_owner(self.inputs(), deadline=deadline) as owner:
            owner.prepare("a" * 64, deadline=deadline)
            signal.pidfd_send_signal(owner.pidfd, signal.SIGTERM)
            poller = select.poll()
            poller.register(owner.pidfd, select.POLLIN)
            self.assertTrue(poller.poll(1000))
            with self.assertRaisesRegex(durable.Rejected, "lock-owner-lost"):
                owner.retire(deadline=deadline)
            with self.assertRaisesRegex(durable.Rejected, "owner-retirement-required"):
                with owner.recovery_lock(deadline=deadline):
                    self.fail("unconfirmed original owner death yielded recovery")

    def test_owner_transfer_rejects_changed_original_journal_before_restoration(self):
        deadline = time.monotonic() + 60
        with fixture.original_lock_owner(self.inputs(), deadline=deadline) as owner:
            owner.prepare("a" * 64, deadline=deadline)
            owner.retire(deadline=deadline)
            self.put(self.root / "journal/arm.json", b"changed original arm")
            with self.assertRaisesRegex(durable.Rejected, "owner-journal-changed"):
                with owner.recovery_lock(deadline=deadline):
                    self.fail("changed original arm yielded recovery")

    def test_expired_owner_transfer_refuses_before_kill_and_keeps_exclusion(self):
        deadline = time.monotonic() + 60
        with fixture.original_lock_owner(self.inputs(), deadline=deadline) as owner:
            owner.prepare("a" * 64, deadline=deadline)
            with self.assertRaisesRegex(durable.Rejected, "original-arm-required"):
                owner.retire(deadline=time.monotonic() - 1)
            owner.check()
            owner.excluded()
            self.assertFalse(owner.retired)

    def test_original_owner_cannot_rearm_journal_or_reuse_retirement(self):
        deadline = time.monotonic() + 60
        with fixture.original_lock_owner(self.inputs(), deadline=deadline) as owner:
            owner.prepare("a" * 64, deadline=deadline)
            with self.assertRaisesRegex(durable.Rejected, "arm-once-only"):
                owner.prepare("b" * 64, deadline=deadline)
            owner.retire(deadline=deadline)
            with self.assertRaisesRegex(durable.Rejected, "lock-owner-lost"):
                owner.retire(deadline=deadline)

    def test_actual_restore_and_fresh_observer_cover_all_roots_without_start_grant(self):
        self.mutate()
        with self.restore() as receipt:
            self.assert_baseline()
            self.assertEqual(receipt["schema"], "host-recovery-write-set-observed-v1")
            self.assertEqual((receipt["roots"], receipt["selected"], receipt["disabled"], receipt["enabled"]),
                             (3, 9, 7, 2))
            self.assertIs(receipt["filesystem_verified"], True)
            for flag in ("start_permission", "semantic_start_oracle_proven", "production_acceptance"):
                self.assertIs(receipt[flag], False)
        self.assert_baseline()

    def test_every_reached_storage_failure_prevents_yield_and_fresh_retry_restores(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point):
                    self.mutate()
                    reached, yielded = [], False
                    def fault(stage):
                        if stage == point:
                            reached.append(stage)
                            raise OSError(code, "synthetic storage failure")
                    with self.assertRaises(OSError):
                        with self.restore(fault=fault):
                            yielded = True
                    self.assertEqual(reached, [point])
                    self.assertFalse(yielded)
                    with self.restore():
                        self.assert_baseline()

    def rehearse(self, **kwargs):
        return fixture.rehearse_restore_faults(self.inputs(), object_id="a" * 64,
            check=lambda **_: self.fenced, deadline=time.monotonic() + 60, **kwargs)

    def test_rehearsal_requires_all_twelve_exact_hooks_and_fresh_complete_retries(self):
        self.mutate()
        rows = self.rehearse()
        self.assertEqual([(row["errno"], row["hook"]) for row in rows], [
            (code, point) for code in (errno.EIO, errno.ENOSPC)
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback")])
        for row in rows:
            self.assertIs(row["reached"], True)
            self.assertIs(row["failed_restore_yielded"], False)
            self.assertIs(row["fresh_retry_verified"], True)
        self.assert_baseline()

    def test_rehearsal_refuses_missing_stopped_boundary_before_fault_mutation(self):
        before = (self.paths["auth"] / "nested/unrelated.bin").read_bytes()
        self.fenced = False
        with self.assertRaisesRegex(durable.Rejected, "stopped-boundary-required"):
            self.rehearse()
        self.assertEqual((self.paths["auth"] / "nested/unrelated.bin").read_bytes(), before)

    def test_rehearsal_does_not_count_an_early_same_errno_failure_as_hook_coverage(self):
        with patch.object(fixture, "restore_stopped", side_effect=OSError(errno.EIO, "before hook")):
            with self.assertRaisesRegex(AssertionError, "exact storage hook"):
                self.rehearse()

    def test_rehearsal_rejects_a_yield_when_the_fault_hook_was_not_reached(self):
        @contextmanager
        def skipped(*args, **kwargs):
            yield {"filesystem_verified": True}
        with patch.object(fixture, "restore_stopped", side_effect=skipped):
            with self.assertRaisesRegex(AssertionError, "yielded a usable receipt"):
                self.rehearse()

    def test_rehearsal_cannot_retry_after_stopped_boundary_is_lost(self):
        @contextmanager
        def lost(*args, **kwargs):
            try:
                kwargs["fault"]("create")
                yield
            finally:
                self.fenced = False
        with patch.object(fixture, "restore_stopped", side_effect=lost) as restore:
            with self.assertRaisesRegex(durable.Rejected, "stopped-boundary-required"):
                self.rehearse()
            self.assertEqual(restore.call_count, 1)

    def test_stopped_boundary_loss_refuses_before_restore(self):
        self.mutate()
        original = (self.paths["config"] / "config.yaml").read_bytes()
        self.fenced = False
        with self.assertRaises(durable.Rejected):
            with self.restore():
                self.fail("lost stopped boundary yielded a restored receipt")
        self.assertEqual((self.paths["config"] / "config.yaml").read_bytes(), original)

    def test_post_yield_mutation_is_not_hidden_by_restorer_progress(self):
        self.mutate()
        with self.assertRaises(durable.Rejected):
            with self.restore():
                self.put(self.paths["config"] / "config.yaml", b"changed after fresh observation")
