"""Fresh actual-file observations; quiescence/identity remain scripted boundaries."""
import copy
import errno
import unittest
from unittest.mock import patch

from host_recovery import durable, inventory, write_set
import test_write_set
from test_installation import approve


class WriteSetVerifierTests(unittest.TestCase):
    def setUp(self):
        self.fx = test_write_set.WriteSetTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.roles = {"config": ("config", "config.yaml"), "compose": ("config", "compose.yaml")}

    def open(self, **overrides):
        args = dict(baseline=approve(self.fx.backup), roots=self.fx.approvals, baseline_sha256=self.fx.pin,
                    check=self.fx.check, clock=lambda: self.fx.time)
        args.update(overrides)
        return write_set.open_write_set_verifier(**args)

    def test_fresh_observer_never_calls_restore_or_persistence(self):
        with patch.object(write_set, "restore_tree", side_effect=AssertionError("restoration attempted")), patch.object(
                durable, "atomic_write", side_effect=AssertionError("persistence attempted")), self.open() as observer:
            receipt = observer.verify_files(self.fx.value, deadline=1100)
            self.assertEqual(receipt["schema"], "host-recovery-write-set-observed-v1")
            self.assertEqual((receipt["roots"], receipt["selected"], receipt["disabled"], receipt["enabled"]), (3, 9, 7, 2))
            self.assertIs(receipt["filesystem_verified"], True)
            for flag in ("start_permission", "semantic_start_oracle_proven", "production_acceptance"):
                self.assertIs(receipt[flag], False)
            self.assertFalse(observer._reader.restored)
            self.assertFalse(hasattr(observer, "restore_complete"))
            self.assertNotIn(str(self.fx.root), str(receipt))
            self.assertNotIn("synthetic-0", str(receipt))
        self.fx.assert_baseline()

    def test_observation_reads_current_bytes_without_restorer_flag(self):
        with self.open() as observer:
            files = observer.capture_files(self.fx.value, self.roles, deadline=1100)
            self.assertEqual(files, {role: (self.fx.paths[root] / name).read_bytes()
                                     for role, (root, name) in self.roles.items()})
            self.assertFalse(observer._reader.restored)
        # The mutation API still requires its own successful restoration.
        with self.fx.open() as recovery, self.assertRaises(durable.Rejected):
            recovery.capture_files(self.fx.value, self.roles, deadline=1100)

    def test_separate_fresh_context_verifies_after_restorer_has_closed(self):
        self.fx.mutate()
        with self.fx.open() as recovery:
            recovery.restore_complete(self.fx.value, deadline=1100)
        with self.open() as observer:
            self.assertTrue(observer.verify_files(self.fx.value, deadline=1100)["filesystem_verified"])
            self.assertFalse(observer._reader.restored)

    def test_partial_candidate_and_unrelated_bytes_are_not_repaired(self):
        for root, name in (("auth", "synthetic-0.json"), ("auth", "unrelated.json"),
                           ("auth", "nested/unrelated.bin"), ("config", "config.yaml"), ("plugin", "candidate.so")):
            with self.subTest(root=root, name=name):
                self.setUp()
                path = self.fx.paths[root] / name
                self.fx.put(path, b"changed-or-candidate")
                with self.open() as observer, self.assertRaises(durable.Rejected):
                    observer.verify_files(self.fx.value, deadline=1100)
                self.assertEqual(path.read_bytes(), b"changed-or-candidate")

    def test_metadata_drift_and_link_are_not_repaired(self):
        for change in ("mode", "link"):
            with self.subTest(change=change):
                self.setUp()
                path = self.fx.paths["config"] / "config.yaml"
                if change == "mode":
                    path.chmod(0o640)
                else:
                    path.unlink()
                    path.symlink_to(self.fx.paths["auth"] / "unrelated.json")
                expected = OSError if change == "link" else durable.Rejected
                with self.open() as observer, self.assertRaises(expected) as failure:
                    observer.capture_files(self.fx.value, self.roles, deadline=1100)
                if change == "link":
                    self.assertEqual(failure.exception.errno, errno.ELOOP)
                if change == "mode":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o640)
                else:
                    self.assertTrue(path.is_symlink())

    def test_wrong_original_intent_and_baseline_tamper_refuse(self):
        with self.open() as observer, self.assertRaises(durable.Rejected):
            observer.verify_files({**self.fx.value, "baseline_sha256": "0" * 64}, deadline=1100)
        self.fx.put(self.fx.backup / "manifest.json", b"changed")
        with self.open() as observer, self.assertRaises(durable.Rejected):
            observer.verify_files(self.fx.value, deadline=1100)

    def test_bound_intent_cannot_change_between_observations(self):
        with self.open() as observer:
            observer.verify_files(self.fx.value, deadline=1100)
            value = copy.deepcopy(self.fx.value)
            value["package_sha256"] = "0" * 64
            with self.assertRaises(durable.Rejected):
                observer.verify_files(value, deadline=1100)

    def test_late_callback_intent_drift_refuses_and_poisons(self):
        with self.open() as observer:
            scanned = []
            verify = observer._reader._verify_all
            def capture(deadline):
                result = verify(deadline)
                scanned.append("files-read")
                return result
            def check(*, deadline):
                if scanned:
                    self.fx.value["package_sha256"] = "0" * 64
                    scanned.append("late-intent-change")
                return True
            observer._reader.check = check
            with patch.object(observer._reader, "_verify_all", side_effect=capture), self.assertRaises(durable.Rejected):
                observer.verify_files(self.fx.value, deadline=1100)
            self.assertIn("late-intent-change", scanned)
            with self.assertRaises(durable.Rejected):
                observer.verify_files(self.fx.value, deadline=1100)

    def test_reached_read_fault_refuses_without_repair(self):
        for code in (errno.EIO, errno.ENOSPC):
            with self.subTest(code=code), self.open() as observer:
                reached = []
                def fault(*args, **kwargs):
                    reached.append(code)
                    raise OSError(code, "synthetic-read-fault")
                with patch.object(inventory, "read_file", side_effect=fault), self.assertRaises(OSError):
                    observer.verify_files(self.fx.value, deadline=1100)
                self.assertEqual(reached, [code])
                with self.assertRaises(durable.Rejected):
                    observer.verify_files(self.fx.value, deadline=1100)
        self.fx.assert_baseline()

    def test_closed_context_lost_fence_and_expiry_refuse(self):
        with self.open() as closed:
            pass
        with self.assertRaises(durable.Rejected):
            closed.verify_files(self.fx.value, deadline=1100)
        self.fx.fenced = False
        with self.open() as observer, self.assertRaises(durable.Rejected):
            observer.verify_files(self.fx.value, deadline=1100)
        self.fx.fenced = True
        with self.open() as observer, self.assertRaises(durable.Rejected):
            observer.verify_files(self.fx.value, deadline=self.fx.time)

    def test_root_replacement_and_role_aliases_refuse(self):
        with self.assertRaisesRegex(durable.Rejected, "^installation-directory-changed$"):
            with self.open() as observer:
                self.fx.paths["config"].rename(self.fx.root / "detached")
                self.fx.paths["config"].mkdir(mode=0o700)
                with self.assertRaises(durable.Rejected):
                    observer.verify_files(self.fx.value, deadline=1100)
        self.setUp()
        with self.open() as observer, self.assertRaises(durable.Rejected):
            observer.capture_files(self.fx.value, {"config": self.roles["config"], "alias": self.roles["config"]}, deadline=1100)

    def test_trailing_callback_cannot_replace_observer_boundaries(self):
        for field in ("check", "clock", "pin", "backup", "roots"):
            with self.subTest(field=field), self.open() as observer:
                reader = observer._reader
                scanned, changed = [], []
                verify = reader._verify_all
                def capture(deadline):
                    result = verify(deadline)
                    scanned.append("complete-scan")
                    return result
                def check(*, deadline):
                    if len(scanned) == 2 and not changed:
                        changed.append(field)
                        if field == "check":
                            reader.check = lambda **kwargs: False
                        elif field == "clock":
                            reader.clock = lambda: 1
                        elif field == "pin":
                            reader.pin = "0" * 64
                        elif field == "backup":
                            reader.backup = copy.copy(reader.backup)
                        else:
                            reader.roots = dict(reader.roots)
                    return True
                reader.check = check
                with patch.object(reader, "_verify_all", side_effect=capture), self.assertRaises(durable.Rejected):
                    observer.verify_files(self.fx.value, deadline=1100)
                self.assertEqual(scanned, ["complete-scan", "complete-scan"])
                self.assertEqual(changed, [field])
                with self.assertRaises(durable.Rejected):
                    observer.verify_files(self.fx.value, deadline=1100)

    def test_original_configuration_is_retained_between_observations(self):
        for field in ("check", "clock", "pin", "backup", "roots"):
            with self.subTest(field=field), self.open() as observer:
                observer.verify_files(self.fx.value, deadline=1100)
                reader = observer._reader
                original = getattr(reader, field)
                replacements = {"check": lambda **kwargs: True, "clock": lambda: self.fx.time,
                                "pin": "0" * 64, "backup": copy.copy(reader.backup), "roots": dict(reader.roots)}
                setattr(reader, field, replacements[field])
                with patch.object(reader, "_verify_all", side_effect=AssertionError("rebound observer read")), self.assertRaises(
                        durable.Rejected):
                    observer.verify_files(self.fx.value, deadline=1100)
                setattr(reader, field, original)
                with self.assertRaises(durable.Rejected):
                    observer.verify_files(self.fx.value, deadline=1100)

    def test_role_and_bind_views_retain_the_same_configuration(self):
        for view in ("roles", "binds"):
            with self.subTest(view=view), self.open() as observer:
                observer.verify_files(self.fx.value, deadline=1100)
                observer._reader.clock = lambda: self.fx.time
                mounts = [{"Type": "bind", "Source": self.fx.approvals["config"].path,
                           "Destination": "/synthetic-config", "Mode": "ro", "RW": False, "Propagation": "rprivate"}]
                with self.assertRaises(durable.Rejected):
                    if view == "roles":
                        observer.capture_files(self.fx.value, self.roles, deadline=1100)
                    else:
                        observer.verify_bind_sources(self.fx.value, mounts, deadline=1100)

    def test_caught_reentrant_observation_poisoning_is_sticky(self):
        with self.open() as observer:
            reached = []
            def check(*, deadline):
                if not reached:
                    reached.append("reentrant-call")
                    with self.assertRaises(durable.Rejected):
                        observer.capture_files(self.fx.value, self.roles, deadline=deadline)
                return True
            reader = observer._reader
            reader.check = check
            with self.assertRaises(durable.Rejected):
                observer.verify_files(self.fx.value, deadline=1100)
            self.assertEqual(reached, ["reentrant-call"])
            self.assertTrue(reader.failed)
            with self.assertRaises(durable.Rejected):
                observer.verify_files(self.fx.value, deadline=1100)

    def test_reader_replacement_poisons_the_original_without_dereferencing_replacement(self):
        for view in ("files", "roles", "binds"):
            with self.subTest(view=view), self.open() as observer:
                reader = observer._reader
                observer._reader = object()
                with self.assertRaises(durable.Rejected):
                    if view == "files":
                        observer.verify_files(self.fx.value, deadline=1100)
                    elif view == "roles":
                        observer.capture_files(self.fx.value, self.roles, deadline=1100)
                    else:
                        observer.verify_bind_sources(self.fx.value, [], deadline=1100)
                self.assertTrue(reader.failed)
                observer._reader = reader
                with self.assertRaises(durable.Rejected):
                    observer.verify_files(self.fx.value, deadline=1100)

    def test_changed_root_handle_in_original_mapping_refuses(self):
        with self.open() as observer:
            observer.verify_files(self.fx.value, deadline=1100)
            reader = observer._reader
            original = reader.roots["config"]
            reader.roots["config"] = copy.copy(original)
            with self.assertRaises(durable.Rejected):
                observer.capture_files(self.fx.value, self.roles, deadline=1100)
            reader.roots["config"] = original
            with self.assertRaises(durable.Rejected):
                observer.verify_files(self.fx.value, deadline=1100)

    def test_observer_cannot_be_reused_after_reader_restoration(self):
        with self.open() as observer:
            observer.verify_files(self.fx.value, deadline=1100)
            observer._reader.restore_complete(self.fx.value, deadline=1100)
            with self.assertRaises(durable.Rejected):
                observer.verify_files(self.fx.value, deadline=1100)
        self.fx.assert_baseline()

    def test_mutating_returned_capture_or_receipt_cannot_change_next_observation(self):
        with self.open() as observer:
            files = observer.capture_files(self.fx.value, self.roles, deadline=1100)
            files["config"] = b"forged"
            receipt = observer.verify_files(self.fx.value, deadline=1100)
            receipt["start_permission"] = True
            self.assertIs(observer.verify_files(self.fx.value, deadline=1100)["start_permission"], False)
            self.assertNotEqual(observer.capture_files(self.fx.value, self.roles, deadline=1100)["config"], b"forged")
