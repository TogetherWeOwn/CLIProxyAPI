"""Real temporary filesystem tests; NOT systemd/daemon or timing acceptance."""
import copy
import errno
import os
from pathlib import Path
import tempfile
import unittest

from host_recovery import budget, durable, inventory, journal, restore


def intent():
    attempt = "60e14471-66ce-4d2a-9a16-aa57b1658bc5"
    policy = {"schema": "host-recovery-budget-v1", "work_seconds": 120,
              "recovery_seconds": 180, "total_seconds": 300, "measurement_sha256": "a" * 64,
              "forward": {"caps": dict.fromkeys(budget.FORWARD_PHASES, 10), "safety_margin": 5},
              "recovery": {"caps": dict.fromkeys(budget.RECOVERY_PHASES, 20), "safety_margin": 5}}
    return {"schema": "host-recovery-intent-v1", "attempt_id": attempt, "installation_id": "fixture",
            "package_sha256": "b" * 64, "manifest_sha256": "c" * 64, "baseline_sha256": "d" * 64,
            "policy_sha256": durable.digest(durable.canonical(policy)), "budget": policy,
            "old_object_id": "e" * 64, "candidate_image_id": "f" * 64, "candidate_ownership_id": attempt,
            "owner": {"installation_id": "fixture", "attempt_id": attempt, "unit": "supervisor.service",
                      "invocation_id": "invocation", "boot_id": "boot-a"}}


def candidate(value):
    return {"object_id": "a" * 64, "image_id": value["candidate_image_id"],
            "ownership_id": value["attempt_id"], "running": False, "restart_policy": "no"}


class PrivateRootTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="host-recovery-state-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def write(self, path, raw):
        file = self.root / path
        file.write_bytes(raw)
        file.chmod(0o600)
        return file


class JournalTests(PrivateRootTests):
    def arm(self):
        value = intent()
        log = journal.Journal(self.fd)
        log.prepare(value)
        log.arm({"boot_id": "boot-a", "monotonic": 1000.0})
        return log, value

    def test_intent_remains_after_registration_and_terminal(self):
        log, value = self.arm()
        raw = (self.root / "intent.json").read_bytes()
        record = candidate(value)
        log.register(record)
        self.assertTrue(log.can_start_candidate(record["object_id"]))
        log.finish("candidate_verified", {"component_only": True})
        self.assertFalse(log.can_start_candidate(record["object_id"]))
        self.assertEqual(raw, (self.root / "intent.json").read_bytes())
        with self.assertRaises(durable.Rejected):
            log.prepare(value)

    def test_recovery_revokes_registered_candidate_and_terminal_permission(self):
        log, value = self.arm()
        record = candidate(value)
        log.register(record)
        log.revoke_forward()
        self.assertFalse(log.can_start_candidate(record["object_id"]))
        with self.assertRaises(durable.Rejected):
            log.register(record)
        with self.assertRaises(durable.Rejected):
            log.finish("candidate_verified", {})

    def test_unregistered_candidate_cannot_commit_terminal(self):
        log, _ = self.arm()
        with self.assertRaises(durable.Rejected):
            log.finish("candidate_verified", {})

    def test_register_before_arm_is_refused(self):
        value = intent()
        log = journal.Journal(self.fd)
        log.prepare(value)
        with self.assertRaises(durable.Rejected):
            log.register(candidate(value))
        self.assertFalse(log.can_start_candidate("a" * 64))

    def test_reopen_never_grants_forward_or_trusts_terminal(self):
        log, value = self.arm()
        log.register(candidate(value))
        log.finish("candidate_verified", {"component_only": True})
        reopened = journal.Journal(self.fd)
        self.assertTrue(reopened.reopened)
        self.assertEqual(reopened.intent, value)
        self.assertFalse(reopened.can_start_candidate("a" * 64))
        self.assertIsNone(reopened.terminal)
        for action in (lambda: reopened.arm({"boot_id": "boot-a", "monotonic": 1001}),
                       lambda: reopened.prepare(value), lambda: reopened.register(candidate(value))):
            with self.assertRaises(durable.Rejected):
                action()

    def test_every_arm_fault_refuses_stop_permission_and_keeps_intent(self):
        value = intent()
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point), tempfile.TemporaryDirectory() as path:
                    with durable.directory(path, private=True) as fd:
                        log = journal.Journal(fd)
                        log.prepare(value)
                        def fail(stage):
                            if stage == point:
                                raise OSError(code, "injected")
                        log.fault = fail
                        with self.assertRaises(OSError):
                            log.arm({"boot_id": "boot-a", "monotonic": 1000})
                        self.assertIsNone(log.armed)
                        self.assertTrue(log.uncertain)
                        self.assertEqual(journal.Journal(fd).intent, value)
                        self.assertFalse(log.can_start_candidate("a" * 64))

    def test_registration_uncertainty_even_after_rename_never_grants_start(self):
        log, value = self.arm()
        def fail(stage):
            if stage == "directory-fsync":
                raise OSError(errno.EIO, "injected")
        log.fault = fail
        with self.assertRaises(OSError):
            log.register(candidate(value))
        self.assertEqual(log.registered, {})
        self.assertFalse(log.can_start_candidate("a" * 64))
        self.assertTrue((self.root / ("object-" + "a" * 64 + ".json")).exists())
        self.assertFalse(journal.Journal(self.fd).can_start_candidate("a" * 64))

    def test_terminal_uncertainty_never_sets_terminal_or_overwrites_intent(self):
        log, value = self.arm()
        log.register(candidate(value))
        original = (self.root / "intent.json").read_bytes()
        def fail(stage):
            if stage == "readback":
                raise OSError(errno.ENOSPC, "injected")
        log.fault = fail
        with self.assertRaises(OSError):
            log.finish("candidate_verified", {})
        self.assertIsNone(log.terminal)
        self.assertTrue(log.uncertain)
        self.assertEqual((self.root / "intent.json").read_bytes(), original)
        self.assertIsNone(journal.Journal(self.fd).terminal)

    def test_candidate_must_be_stopped_no_restart_and_exactly_owned(self):
        log, value = self.arm()
        record = candidate(value)
        for updates in ({"object_id": "short"}, {"object_id": value["old_object_id"]},
                        {"image_id": "0" * 64}, {"ownership_id": "another"},
                        {"running": True}, {"running": 0}, {"restart_policy": "always"}, {"extra": True}):
            with self.subTest(updates=updates), self.assertRaises(durable.Rejected):
                log.register({**record, **updates})
        log.register(record)
        log.register(record)
        with self.assertRaises(durable.Rejected):
            log.register({**record, "object_id": "1" * 64})

    def test_ambiguous_or_malformed_existing_state_refuses_admission(self):
        for raw in (b'{"torn":', b'{}', b'{"schema":"host-recovery-intent-v1"}'):
            with self.subTest(raw=raw):
                self.write("intent.json", raw)
                with self.assertRaises(durable.Rejected):
                    journal.Journal(self.fd)
        (self.root / "intent.json").unlink()
        self.write(".stage-intent.json", b"partial")
        with self.assertRaises(FileNotFoundError):
            journal.Journal(self.fd)

    def test_policy_and_owner_pins_are_checked_before_intent(self):
        for mutate in (lambda v: v.update(attempt_id="not-uuid"),
                       lambda v: v.update(policy_sha256="1" * 64),
                       lambda v: v["owner"].update(attempt_id="other"),
                       lambda v: v.update(candidate_ownership_id="other"),
                       lambda v: v.update(old_object_id="short")):
            value = intent()
            mutate(value)
            with self.assertRaises(durable.Rejected):
                journal.Journal(self.fd).prepare(value)
            self.assertEqual(os.listdir(self.fd), [])

    def test_intent_and_registration_inputs_are_frozen(self):
        log, value = self.arm()
        record = candidate(value)
        log.register(record)
        value["budget"]["forward"]["caps"]["stop"] = 999
        record["image_id"] = "0" * 64
        self.assertEqual(log.intent["budget"]["forward"]["caps"]["stop"], 10)
        self.assertEqual(log.registered["a" * 64]["image_id"], "f" * 64)


class RestoreTests(PrivateRootTests):
    def baseline(self):
        (self.root / "auths").mkdir(mode=0o700)
        for i in range(9):
            self.write(f"auths/selected-{i}.json", durable.canonical({"type": "meta", "disabled": i < 7}))
        self.write("auths/unrelated.json", b'{"type":"other","opaque":"fixture"}\n')
        self.write("config.yaml", b"replay: original\n")
        self.write("compose.yaml", b"image: original\n")
        return inventory.snapshot(self.fd, uid=os.geteuid(), gid=os.getegid())

    def test_complete_restore_preserves_unrelated_entries_and_original_metadata(self):
        tree, blobs = self.baseline()
        self.write("auths/selected-0.json", b'{"torn":')
        self.write("config.yaml", b"plugin: candidate\n")
        (self.root / "compose.yaml").unlink()
        self.write("new-plugin", b"candidate")
        result = restore.restore_tree(self.fd, tree, blobs, {"new-plugin": "file"})
        self.assertEqual(result["baseline_sha256"], durable.digest(durable.canonical(tree)))
        self.assertFalse((self.root / "new-plugin").exists())
        self.assertEqual(inventory.snapshot(self.fd, uid=os.geteuid(), gid=os.getegid()), (tree, blobs))
        self.assertEqual(restore.restore_tree(self.fd, tree, blobs, {"new-plugin": "file"}), result)

    def test_unknown_entry_refused_before_any_restore_or_deletion(self):
        tree, blobs = self.baseline()
        self.write("config.yaml", b"candidate")
        self.write("unknown-provider", b"preserve")
        with self.assertRaises(durable.Rejected):
            restore.restore_tree(self.fd, tree, blobs, {})
        self.assertEqual((self.root / "config.yaml").read_bytes(), b"candidate")
        self.assertEqual((self.root / "unknown-provider").read_bytes(), b"preserve")

    def test_each_restore_write_fault_can_be_reconciled_without_a_start_receipt(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point), tempfile.TemporaryDirectory() as path:
                    with durable.directory(path, private=True) as fd:
                        file = Path(path) / "config.yaml"
                        file.write_bytes(b"original")
                        file.chmod(0o600)
                        tree, blobs = inventory.snapshot(fd, uid=os.geteuid(), gid=os.getegid())
                        file.write_bytes(b"partial")
                        def fail(stage):
                            if stage == point:
                                raise OSError(code, "injected")
                        with self.assertRaises(OSError):
                            restore.restore_tree(fd, tree, blobs, {}, fault=fail)
                        restored = restore.restore_tree(fd, tree, blobs, {})
                        self.assertEqual(restored["entries"], 2)
                        self.assertEqual(os.listdir(fd), ["config.yaml"])
                        self.assertEqual(file.read_bytes(), b"original")

    def test_candidate_directories_removed_and_missing_baseline_directories_recreated(self):
        tree, blobs = self.baseline()
        for path in (self.root / "auths").iterdir():
            path.unlink()
        (self.root / "auths").rmdir()
        (self.root / "candidate").mkdir(mode=0o700)
        self.write("candidate/plugin", b"new")
        restore.restore_tree(self.fd, tree, blobs, {"candidate": "directory", "candidate/plugin": "file"})
        self.assertEqual(inventory.snapshot(self.fd, uid=os.geteuid(), gid=os.getegid()), (tree, blobs))

    def test_bad_baseline_or_unsafe_current_state_refuses_mutation(self):
        tree, blobs = self.baseline()
        self.write("config.yaml", b"candidate")
        bad = copy.deepcopy(blobs)
        bad[next(iter(bad))] = b"tampered"
        with self.assertRaises(durable.Rejected):
            restore.restore_tree(self.fd, tree, bad, {})
        (self.root / "compose.yaml").unlink()
        (self.root / "compose.yaml").symlink_to(self.root / "config.yaml")
        with self.assertRaises((OSError, durable.Rejected)):
            restore.restore_tree(self.fd, tree, blobs, {})
        self.assertEqual((self.root / "config.yaml").read_bytes(), b"candidate")

    def test_staging_collision_kind_changes_and_missing_approved_parent_refused(self):
        tree, blobs = self.baseline()
        stage = next(iter(restore.stages(tree).values()))
        for additions in ({stage: "file"}, {"auths": "directory"}, {"../escape": "file"},
                          {"absent/plugin": "file"}, {"new": "symlink"}):
            with self.subTest(additions=additions), self.assertRaises(durable.Rejected):
                restore.restore_tree(self.fd, tree, blobs, additions)
        (self.root / "config.yaml").unlink()
        (self.root / "config.yaml").mkdir(mode=0o700)
        with self.assertRaises(durable.Rejected):
            restore.restore_tree(self.fd, tree, blobs, {})

    def test_unsupported_directory_access_is_rejected_not_relaxed(self):
        tree, blobs = self.baseline()
        tree["entries"]["auths"]["mode"] = 0o500
        with self.assertRaises(durable.Rejected):
            restore.restore_tree(self.fd, tree, blobs, {})
        self.assertEqual((self.root / "auths").stat().st_mode & 0o777, 0o700)

    def test_reserved_stage_cannot_overwrite_the_destination(self):
        self.write("config.yaml", b"original")
        with self.assertRaises(durable.Rejected):
            durable.atomic_write(self.fd, "config.yaml", b"replacement", stage_name="config.yaml")
        self.assertEqual((self.root / "config.yaml").read_bytes(), b"original")

    def test_deadline_check_failure_never_returns_a_restore_receipt(self):
        tree, blobs = self.baseline()
        self.write("config.yaml", b"candidate")
        def expired():
            raise durable.Rejected("budget-deadline-missed")
        with self.assertRaises(durable.Rejected):
            restore.restore_tree(self.fd, tree, blobs, {}, check=expired)
        self.assertEqual((self.root / "config.yaml").read_bytes(), b"candidate")
