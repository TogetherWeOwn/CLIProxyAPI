"""Actual synthetic multi-root files; scripted quiescence/semantic boundaries."""
from dataclasses import replace
import copy
import errno
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from fixture_home import fixture_home

from host_recovery import coordinator, durable, installation, inventory, journal, restore, write_set
from test_installation import approve
from test_recovery_state import intent

PACKAGE = Path(__file__).resolve().parent.parent


class WriteSetTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".recovery-write-set-", dir=fixture_home())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.backup = self.root / "backup"
        self.backup.mkdir(mode=0o700)
        self.paths = {key: self.root / key for key in ("auth", "config", "plugin")}
        for path in self.paths.values():
            path.mkdir(mode=0o700)
        self.selected = {}
        for index in range(9):
            name = f"synthetic-{index}.json"
            self.selected[name] = index < 7
            self.put(self.paths["auth"] / name, durable.canonical({"type": "meta", "disabled": index < 7}))
        self.put(self.paths["auth"] / "unrelated.json", b'{"type":"other","disabled":false}\n')
        (self.paths["auth"] / "nested").mkdir(mode=0o700)
        self.put(self.paths["auth"] / "nested" / "unrelated.bin", b"unrelated-provider\0bytes", 0o640)
        self.put(self.paths["config"] / "config.yaml", b"replay: true\nplugins: {}\n")
        self.put(self.paths["config"] / "compose.yaml", b"services:\n  old:\n    image: synthetic-old\n")
        self.trees = {}
        manifest = {"schema": "host-recovery-write-set-v1", "roots": {}, "auth": {
            "root": "auth", "selected": self.selected, "expected_type": "meta"}}
        with durable.directory(str(self.backup), private=True) as parent:
            for name, path in self.paths.items():
                with durable.directory(str(path)) as fd:
                    tree, blobs = inventory.snapshot(fd, uid=os.geteuid(), gid=os.getegid())
                self.trees[name] = tree, blobs
                pin = inventory.save_baseline(parent, name, tree, blobs)
                manifest["roots"][name] = {"baseline_sha256": pin, "additions": {}}
            manifest["roots"]["plugin"]["additions"] = {"candidate.so": "file"}
            self.pin = durable.atomic_write(parent, "manifest.json", durable.canonical(manifest))
        self.manifest = manifest
        self.approvals = {name: approve(path) for name, path in self.paths.items()}
        self.value = intent()
        self.value["baseline_sha256"] = self.pin
        self.time = 1005.0
        self.fenced = True
        self.checks = 0

    @staticmethod
    def put(path, raw, mode=0o600):
        path.write_bytes(raw)
        path.chmod(mode)

    def check(self, *, deadline):
        self.checks += 1
        self.assertGreater(deadline, self.time)
        return self.fenced

    def open(self, **overrides):
        args = dict(baseline=approve(self.backup), roots=self.approvals, baseline_sha256=self.pin,
                    check=self.check, clock=lambda: self.time)
        args.update(overrides)
        return write_set.open_write_set(**args)

    def mutate(self):
        self.put(self.paths["auth"] / "synthetic-0.json", b'{"type":"meta","disabled":false}\n')
        self.put(self.paths["auth"] / "unrelated.json", b"candidate-touched-unrelated")
        self.put(self.paths["auth"] / "nested" / "unrelated.bin", b"changed")
        self.put(self.paths["config"] / "config.yaml", b"partial-candidate-config")
        self.put(self.paths["config"] / "compose.yaml", b"partial-candidate-compose")
        self.put(self.paths["plugin"] / "candidate.so", b"synthetic-plugin-not-executable")

    def assert_baseline(self):
        for name, path in self.paths.items():
            with durable.directory(str(path)) as fd:
                self.assertEqual(inventory.snapshot(fd, uid=os.geteuid(), gid=os.getegid()), self.trees[name])

    def publish_manifest(self, value):
        with durable.directory(str(self.backup), private=True) as fd:
            self.pin = durable.atomic_write(fd, "manifest.json", durable.canonical(value))
        self.value["baseline_sha256"] = self.pin

    def test_all_roots_restore_selected_unrelated_config_compose_and_plugin(self):
        self.mutate()
        with self.open() as recovery:
            self.assertTrue(recovery.validate_recovery(self.value, deadline=1100))
            self.assertTrue(recovery.restore_complete(self.value, deadline=1100))
            result = recovery.verify_files(self.value, deadline=1100)
            self.assertEqual((result["roots"], result["selected"], result["disabled"], result["enabled"]), (3, 9, 7, 2))
            self.assertTrue(result["filesystem_verified"])
            for flag in ("semantic_start_oracle_proven", "start_permission", "production_acceptance"):
                self.assertIs(result[flag], False)
            self.assertNotIn("synthetic-0", json.dumps(result))
            self.assertNotIn(str(self.root), json.dumps(result))
        self.assert_baseline()
        self.assertGreater(self.checks, 30)

    def test_missing_extra_or_mixed_root_bindings_refuse_before_mutation(self):
        for roots in ({k: v for k, v in self.approvals.items() if k != "config"},
                      {**self.approvals, "extra": approve(self.backup)}):
            self.mutate()
            with self.assertRaises(durable.Rejected), self.open(roots=roots) as recovery:
                recovery.restore_complete(self.value, deadline=1100)
            self.assertEqual((self.paths["config"] / "config.yaml").read_bytes(), b"partial-candidate-config")

    def test_aggregate_pin_not_adjacent_manifest_self_consistency(self):
        self.mutate()
        bad = copy.deepcopy(self.manifest)
        bad["auth"]["expected_type"] = "meta-muse"
        self.put(self.backup / "manifest.json", durable.canonical(bad))
        with self.assertRaises(durable.Rejected), self.open() as recovery:
            recovery.restore_complete(self.value, deadline=1100)
        self.assertEqual((self.paths["config"] / "config.yaml").read_bytes(), b"partial-candidate-config")

    def test_original_intent_pin_must_match_approved_aggregate(self):
        with self.open() as recovery, self.assertRaises(durable.Rejected):
            recovery.validate_recovery({**self.value, "baseline_sha256": "0" * 64}, deadline=1100)

    def test_late_root_unknown_entry_refuses_before_earlier_root_restore(self):
        self.mutate()
        self.put(self.paths["plugin"] / "unapproved.so", b"unexpected")
        with self.open() as recovery, self.assertRaisesRegex(durable.Rejected, "unexpected-entry"):
            recovery.restore_complete(self.value, deadline=1100)
        self.assertEqual((self.paths["auth"] / "unrelated.json").read_bytes(), b"candidate-touched-unrelated")
        self.assertEqual((self.paths["config"] / "config.yaml").read_bytes(), b"partial-candidate-config")

    def test_late_root_tampered_blob_refuses_before_any_mutation(self):
        self.mutate()
        name = next(iter(self.trees["config"][1]))
        self.put(self.backup / "config" / name, b"tampered")
        with self.open() as recovery, self.assertRaises(durable.Rejected):
            recovery.restore_complete(self.value, deadline=1100)
        self.assertEqual((self.paths["auth"] / "unrelated.json").read_bytes(), b"candidate-touched-unrelated")

    def test_auth_selection_is_exact_nine_seven_disabled_and_baseline_type(self):
        variants = []
        missing = copy.deepcopy(self.manifest)
        missing["auth"]["selected"].pop("synthetic-0.json")
        variants.append(missing)
        wrong = copy.deepcopy(self.manifest)
        wrong["auth"]["selected"]["synthetic-0.json"] = False
        variants.append(wrong)
        mismatch = copy.deepcopy(self.manifest)
        mismatch["auth"]["expected_type"] = "meta-muse"
        variants.append(mismatch)
        for value in variants:
            with self.subTest(value=value):
                self.publish_manifest(value)
                with self.assertRaises(durable.Rejected), self.open() as recovery:
                    recovery.validate_recovery(self.value, deadline=1100)

    def test_duplicate_nested_or_backup_roots_refuse_at_open(self):
        for roots in ({**self.approvals, "config": self.approvals["auth"]},
                      {**self.approvals, "config": approve(self.paths["auth"] / "nested")},
                      {**self.approvals, "config": approve(self.backup / "config")}):
            with self.subTest(roots=roots), self.assertRaises(durable.Rejected), self.open(roots=roots):
                self.fail("overlapping roots accepted")

    def test_replaced_root_identity_revokes_before_mutation(self):
        self.mutate()
        with self.assertRaises(durable.Rejected), self.open() as recovery:
            self.paths["config"].rename(self.root / "detached-config")
            self.paths["config"].mkdir(mode=0o700)
            recovery.restore_complete(self.value, deadline=1100)
        self.assertEqual((self.paths["auth"] / "unrelated.json").read_bytes(), b"candidate-touched-unrelated")
        self.assertEqual(list(self.paths["config"].iterdir()), [])

    def test_unknown_schema_fields_or_backup_entries_refuse(self):
        for change in (lambda v: v.update(extra=True), lambda v: v["roots"]["config"].update(extra=True),
                       lambda v: v["auth"].update(extra=True)):
            with self.subTest(change=change):
                self.setUp()
                value = copy.deepcopy(self.manifest)
                change(value)
                self.publish_manifest(value)
                with self.assertRaises(durable.Rejected), self.open() as recovery:
                    recovery.validate_recovery(self.value, deadline=1100)
        self.setUp()
        self.put(self.backup / "unexpected", b"extra")
        with self.assertRaises(durable.Rejected), self.open() as recovery:
            recovery.validate_recovery(self.value, deadline=1100)

    def test_symlink_special_file_or_type_change_refuses_before_mutation(self):
        for kind in ("symlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                self.setUp()
                self.mutate()
                path = self.paths["config"] / "config.yaml"
                path.unlink()
                if kind == "symlink":
                    path.symlink_to(self.paths["auth"] / "unrelated.json")
                elif kind == "fifo":
                    os.mkfifo(path, 0o600)
                else:
                    path.mkdir(mode=0o700)
                with self.assertRaises((OSError, durable.Rejected)), self.open() as recovery:
                    recovery.restore_complete(self.value, deadline=1100)
                self.assertEqual((self.paths["auth"] / "unrelated.json").read_bytes(), b"candidate-touched-unrelated")

    def test_no_permission_relaxation_for_unsafe_baseline_or_root(self):
        for target in (self.backup / "manifest.json", self.backup / "config"):
            with self.subTest(target=target):
                old = target.stat().st_mode & 0o777
                target.chmod(0o644 if target.is_file() else 0o755)
                with self.assertRaises(durable.Rejected), self.open() as recovery:
                    recovery.validate_recovery(self.value, deadline=1100)
                self.assertEqual(target.stat().st_mode & 0o777, 0o644 if target.is_file() else 0o755)
                target.chmod(old)
        self.paths["config"].chmod(0o777)
        with self.assertRaises(durable.Rejected), self.open():
            self.fail("unsafe root accepted")
        self.assertEqual(self.paths["config"].stat().st_mode & 0o777, 0o777)

    def test_caller_mutation_of_approval_map_is_not_adopted(self):
        with self.open() as recovery:
            self.approvals.pop("config")
            recovery.restore_complete(self.value, deadline=1100)
            self.assertEqual(recovery.verify_files(self.value, deadline=1100)["roots"], 3)

    def test_closed_context_cannot_restore_or_verify(self):
        with self.open() as recovery:
            handles = [recovery.backup, *recovery.roots.values()]
            fds = [handle.fd for handle in handles]
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)
        for operation in (recovery.validate_recovery, recovery.restore_complete, recovery.verify_files):
            with self.assertRaises(durable.Rejected):
                operation(self.value, deadline=1100)
        for handle in handles:
            with self.assertRaises(durable.Rejected):
                handle.validate()

    def test_failed_context_cannot_retry_even_if_quiescence_returns(self):
        with self.open() as recovery:
            self.fenced = False
            with self.assertRaises(durable.Rejected):
                recovery.restore_complete(self.value, deadline=1100)
            self.fenced = True
            with self.assertRaises(durable.Rejected):
                recovery.restore_complete(self.value, deadline=1100)

    def test_quiescence_must_be_strict_true_not_truthy(self):
        for result in (1, {}, None, False):
            with self.subTest(result=result), self.open(check=lambda **_: result) as recovery:
                with self.assertRaises(durable.Rejected):
                    recovery.restore_complete(self.value, deadline=1100)

    def test_missing_or_expired_original_phase_deadline_never_mutates(self):
        self.mutate()
        for deadline in (1005, 1004, float("nan"), float("inf"), None, True):
            with self.subTest(deadline=deadline), self.open() as recovery, self.assertRaises(durable.Rejected):
                recovery.restore_complete(self.value, deadline=deadline)
        self.assertEqual((self.paths["auth"] / "unrelated.json").read_bytes(), b"candidate-touched-unrelated")

    def test_phase_overrun_during_restore_cannot_return_success(self):
        self.mutate()
        def fault(point):
            if point == "directory-fsync":
                self.time = 1100
        with self.open() as recovery, self.assertRaises(durable.Rejected):
            recovery.restore_complete(self.value, deadline=1100, fault=fault)
        self.assertFalse(recovery.restored)
        self.assertTrue((self.paths["plugin"] / "candidate.so").exists())

    def test_all_write_faults_reopen_idempotently_across_partial_roots(self):
        for number in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(errno=number, point=point):
                    self.setUp()
                    self.mutate()
                    count = 0
                    def fault(actual):
                        nonlocal count
                        # Fail on the first config root write, after the auth root.
                        if actual == point:
                            count += 1
                            if count == 12:
                                raise OSError(number, "synthetic storage fault")
                    with self.open() as recovery, self.assertRaises(OSError):
                        recovery.restore_complete(self.value, deadline=1100, fault=fault)
                    self.assertFalse(recovery.restored)
                    self.assertTrue((self.paths["plugin"] / "candidate.so").exists())
                    with self.open() as again:
                        self.assertTrue(again.restore_complete(self.value, deadline=1100))
                        self.assertTrue(again.verify_files(self.value, deadline=1100)["filesystem_verified"])
                    self.assert_baseline()

    def test_final_all_root_scan_catches_change_in_an_earlier_root(self):
        self.mutate()
        real = write_set.restore_tree
        def restore_and_change(fd, *args, **kwargs):
            result = real(fd, *args, **kwargs)
            if os.fstat(fd).st_ino == self.approvals["plugin"].inode:
                self.put(self.paths["auth"] / "unrelated.json", b"late-writer")
            return result
        with patch.object(write_set, "restore_tree", side_effect=restore_and_change), self.open() as recovery:
            with self.assertRaisesRegex(durable.Rejected, "final-inventory"):
                recovery.restore_complete(self.value, deadline=1100)
            self.assertFalse(recovery.restored)

    def test_fresh_file_verification_catches_change_after_restore(self):
        self.mutate()
        with self.open() as recovery:
            recovery.restore_complete(self.value, deadline=1100)
            self.put(self.paths["config"] / "compose.yaml", b"late-change")
            with self.assertRaises(durable.Rejected):
                recovery.verify_files(self.value, deadline=1100)

    def test_verification_before_restoration_and_repeat_restore_refuse(self):
        with self.open() as recovery, self.assertRaises(durable.Rejected):
            recovery.verify_files(self.value, deadline=1100)
        with self.open() as recovery:
            recovery.restore_complete(self.value, deadline=1100)
            with self.assertRaises(durable.Rejected):
                recovery.restore_complete(self.value, deadline=1100)

    def test_aggregate_entry_and_byte_limits_not_per_root_only(self):
        for constant, limit in (("MAX_ENTRIES", 10), ("MAX_TREE_BYTES", 10)):
            with self.subTest(constant=constant), patch.object(write_set, constant, limit), self.open() as recovery:
                with self.assertRaisesRegex(durable.Rejected, "aggregate-limit"):
                    recovery.validate_recovery(self.value, deadline=1100)

    def test_baseline_parent_cannot_be_symlinked_or_nested_into_write_root(self):
        link = self.root / "backup-link"
        link.symlink_to(self.backup, target_is_directory=True)
        approval = replace(approve(self.backup), path=str(link))
        with self.assertRaises(OSError), self.open(baseline=approval):
            self.fail("baseline symlink accepted")
        nested = self.paths["config"] / "backup"
        nested.mkdir(mode=0o700)
        with self.assertRaises(durable.Rejected), self.open(baseline=approve(nested)):
            self.fail("nested baseline accepted")

    def test_separate_process_sigkill_partial_restore_reopens_all_roots(self):
        self.mutate()
        source = '''
import json, os, sys
from dataclasses import asdict
sys.path.insert(0, sys.argv[1])
from host_recovery import durable, installation, write_set
args=json.loads(sys.argv[2])
roots={name:installation.DirectoryApproval(**row) for name,row in args['roots'].items()}
backup=installation.DirectoryApproval(**args['backup'])
owner=args['intent']['owner']
with durable.installation_lock(sys.argv[3], owner):
 with write_set.open_write_set(baseline=backup, roots=roots, baseline_sha256=args['pin'], check=lambda **_:True, clock=lambda:1005) as recovery:
  count=0
  def fault(point):
   global count
   if point=='directory-fsync':
    count+=1
    if count==12:
     print('partial-ready',flush=True)
     sys.stdin.buffer.read(1)
  recovery.restore_complete(args['intent'],deadline=1100,fault=fault)
'''
        from dataclasses import asdict
        state = self.root / "state"
        state.mkdir(mode=0o700)
        args = {"roots": {name: asdict(value) for name, value in self.approvals.items()},
                "backup": asdict(approve(self.backup)), "pin": self.pin, "intent": self.value}
        proc = subprocess.Popen([sys.executable, "-I", "-c", source, str(PACKAGE), json.dumps(args), str(state)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(10), "child failed to reach deterministic barrier")
            self.assertEqual(proc.stdout.readline(), b"partial-ready\n")
            with self.assertRaises(BlockingIOError), durable.installation_lock(state, self.value["owner"]):
                self.fail("lock overlap")
            proc.send_signal(signal.SIGKILL)
            _, errors = proc.communicate(timeout=10)
            self.assertEqual(proc.returncode, -signal.SIGKILL, errors.decode())
            with durable.installation_lock(state, self.value["owner"]), self.open() as recovery:
                recovery.restore_complete(self.value, deadline=1100)
                receipt = recovery.verify_files(self.value, deadline=1100)
            self.assert_baseline()
            raw = {"schema": "synthetic-write-set-process-case-v1", "child_exit": proc.returncode,
                   "boundary": "scripted-manager-daemon-quiescence", "receipt": receipt,
                   "production_acceptance": False}
            if os.environ.get("HOST_RECOVERY_WRITE_SET_RECEIPT"):
                Path(os.environ["HOST_RECOVERY_WRITE_SET_RECEIPT"]).write_bytes(durable.canonical(raw))
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=10)

    def coordinator_case(self, *, fault=None, corrupt=False, semantic_ok=True, receipt_fault=False):
        case = self
        class Boundary:
            calls = []
            def event(self, name):
                self.calls.append(name)
                return True
            def recovery_preflight(self, value, *, deadline):
                return self.event("preflight")
            def fence(self, value, *, deadline):
                return self.event("fence")
            def quiesce(self, value, *, deadline):
                return self.event("quiesce")
            def validate_recovery(self, value, *, deadline):
                self.event("validate")
                return recovery.validate_recovery(value, deadline=deadline)
            def restore_complete(self, value, *, deadline):
                self.event("restore")
                return recovery.restore_complete(value, deadline=deadline, fault=fault)
            def verify_baseline_stopped(self, value, *, deadline):
                self.event("oracle")
                receipt = recovery.verify_files(value, deadline=deadline)
                case.assertFalse(receipt["semantic_start_oracle_proven"])
                if not semantic_ok:
                    return receipt
                # Host/config/replay/image semantics remain an explicitly scripted
                # independent boundary, not facts inferred by the file restorer.
                return {"baseline_sha256": value["baseline_sha256"], "object_id": value["old_object_id"],
                        "original_image": True, "original_replay": True, "new_plugin_absent": True,
                        "complete_write_set": True, "metadata_verified": True, "all_writers_stopped": True}
            def start_old(self, value, receipt, *, deadline):
                case.assert_baseline()
                return self.event("start-old-scripted")
            def old_ready(self, value, *, deadline):
                return self.event("old-ready-scripted")
        state = self.root / "state"
        state.mkdir(mode=0o700)
        notices = []
        def persist(_):
            if receipt_fault:
                raise OSError(errno.ENOSPC, "synthetic receipt fault")
        with durable.installation_lock(state, self.value["owner"]) as (fd, _):
            log = journal.Journal(fd)
            log.prepare(self.value)
            log.arm({"boot_id": "boot-a", "monotonic": 1000})
            self.mutate()
            if corrupt:
                self.put(self.paths["plugin"] / "unknown.so", b"unknown")
            with self.open() as recovery:
                boundary = Boundary()
                engine = coordinator.AttemptCoordinator(journal.Journal(fd), boundary, lambda: self.time,
                    lambda: "boot-a", persist, lambda n: notices.append(n) or True)
                result = engine.resume()
            self.assertTrue(result["start_fenced"])
            self.assertFalse(result["production_acceptance"])
            self.assertEqual(engine.meter.arm["monotonic"], 1000)
            self.assertEqual(engine.meter.deadline("recovery"), 1180)
            self.assertEqual(len(notices), 1)
            self.assertTrue(result["alert"]["transport_delivered"])
            self.assertEqual(result["alert"]["receipt_persisted"], not receipt_fault)
            if fault or corrupt or not semantic_ok:
                self.assertEqual(result["outcome"], "recovery_unresolved")
                self.assertNotIn("start-old-scripted", boundary.calls)
                self.assertFalse((state / "recovery-outcome.json").exists())
            else:
                self.assertEqual(result["outcome"], "baseline_restored")
                self.assertEqual(boundary.calls, ["preflight", "fence", "quiesce", "validate", "restore", "oracle",
                                                 "start-old-scripted", "old-ready-scripted"])
                self.assertTrue((state / "recovery-outcome.json").exists())
            return boundary.calls

    def test_original_arm_coordinator_uses_all_roots_but_separate_semantic_oracle(self):
        self.coordinator_case()

    def test_filesystem_only_receipt_cannot_satisfy_coordinator_start_oracle(self):
        self.assertIn("oracle", self.coordinator_case(semantic_ok=False))
        self.assert_baseline()

    def test_all_root_precheck_failure_prevents_coordinator_restore_and_start(self):
        calls = self.coordinator_case(corrupt=True, receipt_fault=True)
        self.assertNotIn("restore", calls)
        self.assertEqual((self.paths["auth"] / "unrelated.json").read_bytes(), b"candidate-touched-unrelated")

    def test_coordinator_restoration_fault_never_starts_and_alert_survives_disk_failure(self):
        for number in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(errno=number, point=point):
                    self.setUp()
                    def fault(actual):
                        if actual == point:
                            raise OSError(number, "synthetic restore fault")
                    self.assertNotIn("oracle", self.coordinator_case(fault=fault, receipt_fault=True))

    def test_original_intent_cannot_change_between_validation_and_restoration(self):
        with self.open() as recovery:
            recovery.validate_recovery(self.value, deadline=1100)
            changed = {**self.value, "candidate_image_id": "3" * 64}
            with self.assertRaisesRegex(durable.Rejected, "original-intent-pin"):
                recovery.restore_complete(changed, deadline=1100)

    def test_clock_regression_between_calls_refuses_without_reset(self):
        with self.open() as recovery:
            recovery.validate_recovery(self.value, deadline=1100)
            self.time = 1004
            with self.assertRaisesRegex(durable.Rejected, "clock-discontinuity"):
                recovery.restore_complete(self.value, deadline=1100)
