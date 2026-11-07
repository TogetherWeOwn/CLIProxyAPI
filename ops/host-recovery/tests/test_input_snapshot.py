"""Real protected synthetic file capture; manager/fence/schema are scripted."""
import base64
import copy
from dataclasses import replace
import errno
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from fixture_home import fixture_home

from host_recovery import durable, input_gate, input_snapshot, protected_file
import test_input_gate
from test_installation import approve
from test_recovery_state import intent


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".recovery-input-snapshot-", dir=fixture_home())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.sources, self.policies = self.root / "sources", self.root / "policies"
        self.sources.mkdir(mode=0o700)
        self.policies.mkdir(mode=0o700)
        self.value, self.time, self.boundary_ok = intent(), 1000.0, True
        self.spec, self.paths = test_input_gate.request(), {}
        self.policy = {"schema": "host-recovery-input-policy-v1"}
        for role in input_snapshot.ROLES:
            self.policy[role] = copy.deepcopy(self.spec[role]["changes"])
            for side in ("before", "after"):
                key = role + "-" + side
                self.paths[key] = self.sources / key
                self.paths[key].write_bytes(base64.b64decode(self.spec[role][side]))
                self.paths[key].chmod(0o600)
        self.paths["policy"] = self.policies / "policy.json"
        self.paths["policy"].write_bytes(durable.canonical(self.policy))
        self.paths["policy"].chmod(0o600)
        self.configure()

    def configure(self):
        def file(key):
            path = self.paths[key]
            return input_snapshot.InputFileApproval(approve(path.parent), path.name, durable.digest(path.read_bytes()))
        pairs = {role: input_snapshot.InputPairApproval(file(role + "-before"), file(role + "-after"))
                 for role in input_snapshot.ROLES}
        self.approval = input_snapshot.SnapshotApproval(durable.digest(durable.canonical(self.value)), file("policy"), **pairs)
        self.snapshot = input_snapshot.ProtectedInputSnapshot(approval=self.approval,
                         check=lambda: self.boundary_ok, clock=lambda: self.time)

    def capture(self):
        return self.snapshot(self.value, deadline=self.time + 10)

    def refused(self):
        with self.assertRaisesRegex(durable.Rejected, "^input-snapshot-unconfirmed$"):
            self.capture()

    def test_exact_seven_file_capture_matches_existing_helper_request_without_writes(self):
        before = {key: (durable.signature(path.stat()), path.read_bytes()) for key, path in self.paths.items()}
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("capture-does-not-execute")):
            self.assertEqual(self.capture(), durable.canonical(self.spec))
        self.assertEqual(before, {key: (durable.signature(path.stat()), path.read_bytes()) for key, path in self.paths.items()})
        self.assertEqual(len(list(self.root.rglob("*"))), 9)

    def test_independent_document_and_policy_pins_are_all_checked_fresh(self):
        self.assertEqual(self.capture(), durable.canonical(self.spec))
        for key, path in self.paths.items():
            with self.subTest(role=key):
                before = path.read_bytes()
                path.write_bytes(before + b"\n")
                self.refused()
                path.write_bytes(before)

    def test_intent_identity_cannot_be_substituted(self):
        self.value["attempt_id"] = "other-attempt"
        with mock.patch.object(input_snapshot, "open_approved_directory") as opened:
            self.refused()
            opened.assert_not_called()

    def test_private_readonly_files_and_directories_are_supported(self):
        for path in self.paths.values():
            path.chmod(0o400)
        self.sources.chmod(0o500)
        self.policies.chmod(0o500)
        self.addCleanup(self.sources.chmod, 0o700)
        self.addCleanup(self.policies.chmod, 0o700)
        self.configure()
        self.assertEqual(self.capture(), durable.canonical(self.spec))

    def test_private_file_modes_and_regular_single_link_files_are_required(self):
        path = self.paths["config-after"]
        saved = path.with_name("saved")
        path.rename(saved)
        self.refused()
        path.symlink_to(saved)
        self.refused()
        path.unlink()
        os.link(saved, path)
        self.refused()
        path.unlink()
        os.mkfifo(path, 0o600)
        self.refused()
        path.unlink()
        path.mkdir(mode=0o700)
        self.refused()
        path.rmdir()
        saved.rename(path)
        for mode in (0o644, 0o700, 0o666, 0o4600):
            with self.subTest(mode=mode):
                path.chmod(mode)
                self.refused()
        path.chmod(0o600)
        self.assertEqual(self.capture(), durable.canonical(self.spec))

    def test_wrong_numeric_owner_and_unsupported_metadata_refuse(self):
        original = os.fstat
        def wrong_owner(fd):
            result = original(fd)
            if stat.S_ISREG(result.st_mode):
                values = list(result)
                values[4] += 1
                return os.stat_result(values)
            return result
        with mock.patch.object(os, "fstat", side_effect=wrong_owner):
            self.refused()
        with mock.patch.object(os, "listxattr", return_value=["user.secret"]):
            self.refused()

    def test_missing_swapped_and_unprotected_root_refuse(self):
        root = self.approval.config.before.root
        for field in ("device", "inode", "uid", "gid"):
            with self.subTest(field=field):
                changed = replace(self.approval.config.before, root=replace(root, **{field: getattr(root, field) + 1}))
                self.snapshot.approval = replace(self.approval, config=replace(self.approval.config, before=changed))
                self.refused()
        self.snapshot.approval = self.approval
        self.sources.chmod(0o777)
        self.refused()
        self.sources.chmod(0o700)
        retained = self.sources.with_name("retained")
        self.sources.rename(retained)
        self.sources.symlink_to(retained, target_is_directory=True)
        self.refused()

    def test_same_file_cannot_supply_two_roles_even_with_identical_pins(self):
        self.snapshot.approval = replace(self.approval, config=input_snapshot.InputPairApproval(
                                        self.approval.config.before, self.approval.config.before))
        self.refused()

    def test_retained_descriptor_and_root_replacement_are_refused(self):
        original = input_snapshot.canonical
        for target in ("file", "root"):
            with self.subTest(target=target):
                reached = []
                def encode(value):
                    raw = original(value)
                    if value.get("schema") == "host-recovery-input-request-v1":
                        if target == "file":
                            path = self.paths["config-before"]
                            replacement = path.with_name("replacement")
                            replacement.write_bytes(path.read_bytes())
                            replacement.chmod(0o600)
                            os.replace(replacement, path)
                        else:
                            self.sources.rename(self.root / "retained")
                            self.sources.mkdir(mode=0o700)
                        reached.append(target)
                    return raw
                with mock.patch.object(input_snapshot, "canonical", side_effect=encode):
                    self.refused()
                self.assertEqual(reached, [target])
                if target == "file":
                    self.configure()

    def test_same_inode_same_size_mutation_is_rehashed_even_if_metadata_appears_unchanged(self):
        original, reached = input_snapshot.canonical, []
        def encode(value):
            raw = original(value)
            if value.get("schema") == "host-recovery-input-request-v1":
                path = self.paths["config-before"]
                old = path.stat().st_ino
                content = path.read_bytes()
                path.write_bytes(content.replace(b"old", b"bad"))
                self.assertEqual(path.stat().st_ino, old)
                reached.append("bytes-mutated")
            return raw
        # Neutralize signature checks only. The second retained-descriptor byte
        # hash must reject; this is not an actual coarse-timestamp filesystem drill.
        with mock.patch.object(input_snapshot, "canonical", side_effect=encode), mock.patch.object(
                protected_file, "signature", return_value="same-metadata"):
            self.refused()
        self.assertEqual(reached, ["bytes-mutated"])

    def test_policy_duplicates_unknown_and_missing_roles_are_not_ignored(self):
        cases = (b'{"schema":"host-recovery-input-policy-v1","schema":"other"}',
                 durable.canonical({**self.policy, "unknown": []}),
                 durable.canonical({key: value for key, value in self.policy.items() if key != "config"}),
                 durable.canonical({**self.policy, "config": None}),
                 durable.canonical({**self.policy, "config": [{}] * 257}))
        for raw in cases:
            with self.subTest(size=len(raw)):
                self.paths["policy"].write_bytes(raw)
                self.configure()  # Correct bytes still need the exact policy envelope.
                self.refused()

    def test_document_policy_and_serialized_request_bounds_are_enforced(self):
        for constant in ("MAX_DOCUMENT", "MAX_POLICY", "MAX_REQUEST"):
            with self.subTest(bound=constant), mock.patch.object(input_snapshot, constant, 1):
                self.refused()
        path = self.paths["config-before"]
        before = path.read_bytes()
        path.write_bytes(b"")
        self.refused()
        path.write_bytes(before)

    def test_eio_enospc_and_short_reads_close_all_descriptors(self):
        count = lambda: len(os.listdir("/proc/self/fd"))
        before = count()
        self.capture()
        self.assertEqual(count(), before)
        for error in (errno.EIO, errno.ENOSPC):
            with self.subTest(error=error), mock.patch.object(os, "pread", side_effect=OSError(error, "secret-path")) as read:
                self.refused()
                self.assertEqual(read.call_count, 1)
            self.assertEqual(count(), before)
        with mock.patch.object(os, "pread", return_value=b"") as read:
            self.refused()
            self.assertEqual(read.call_count, 1)
        self.assertEqual(count(), before)

    def test_second_read_storage_fault_is_reached_and_refused(self):
        reached = []
        def checksum(source):
            reached.append(source.name)
            raise OSError(errno.EIO, "secret-path")
        with mock.patch.object(protected_file.ProtectedFile, "checksum", checksum):
            self.refused()
        self.assertEqual(reached, ["policy.json"])

    def test_boundary_strict_true_deadline_and_clock_checks_fail_closed(self):
        for result in (False, None, 1, "true"):
            self.boundary_ok = result
            self.refused()
        self.boundary_ok = True
        with self.assertRaisesRegex(durable.Rejected, "^input-snapshot-unconfirmed$"):
            self.snapshot(self.value, deadline=self.time)
        ticks = iter((1000.0, 999.0))
        self.snapshot.clock = lambda: next(ticks)
        self.refused()

    def test_boundary_loss_after_capture_and_serialization_expiry_are_refused(self):
        original, reached = input_snapshot.canonical, []
        def encode(value):
            raw = original(value)
            if value.get("schema") == "host-recovery-input-request-v1":
                self.boundary_ok = False
                reached.append("revoked")
            return raw
        with mock.patch.object(input_snapshot, "canonical", side_effect=encode):
            self.refused()
        self.assertEqual(reached, ["revoked"])
        self.boundary_ok = True
        def expired(value):
            raw = original(value)
            if value.get("schema") == "host-recovery-input-request-v1":
                self.time += 10
                reached.append("expired")
            return raw
        with mock.patch.object(input_snapshot, "canonical", side_effect=expired):
            self.refused()
        self.assertEqual(reached, ["revoked", "expired"])

    def test_approval_shapes_and_explicit_boundary_are_required(self):
        for field, value in (("name", "../escape"), ("name", "."), ("sha256", "x"), ("root", None),
                             ("root", replace(self.approval.policy.root, mode=0o755))):
            with self.subTest(field=field), self.assertRaises(durable.Rejected):
                replace(self.approval.policy, **{field: value})
        with self.assertRaises(durable.Rejected):
            input_snapshot.InputPairApproval(None, self.approval.config.after)
        with self.assertRaises(durable.Rejected):
            replace(self.approval, compose_source=None)
        with self.assertRaises(durable.Rejected):
            input_snapshot.ProtectedInputSnapshot(approval=self.approval, check=None, clock=lambda: self.time)


class SnapshotBarrierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="snapshot-guard-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / "inputguard"
        result = subprocess.run(("go", "build", "-o", str(cls.binary), "./ops/host-recovery/inputguard/cmd"),
                                cwd=test_input_gate.ROOT, capture_output=True, timeout=180)
        if result.returncode:
            raise RuntimeError("repository guard build failed: " + result.stderr.decode(errors="replace"))

    def setUp(self):
        self.fx = test_input_gate.InputGateTests()
        self.fx.binary = self.binary
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.source = SnapshotTests()
        self.source.setUp()
        self.addCleanup(self.source.doCleanups)
        self.source.value = self.fx.value
        self.source.configure()
        self.source.snapshot.clock = lambda: self.fx.fx.time
        self.fx.gate.snapshot = self.source.snapshot
        self.engine, self.host = self.fx.fx.engine, self.fx.fx.boundary

    def test_built_helper_uses_protected_capture_at_both_barriers(self):
        self.engine.admit(self.fx.value)
        self.assertEqual(self.host.calls, ["preflight"])
        self.assertEqual(self.engine.forward()["outcome"], "candidate_verified")
        self.assertIn("mutate", self.host.calls)
        self.assertIn("start-candidate", self.host.calls)

    def test_source_or_policy_drift_before_admission_creates_no_intent_or_stop(self):
        for key in ("compose_source-after", "policy"):
            path = self.source.paths[key]
            before = path.read_bytes()
            path.write_bytes(before + b"\n")
            with self.assertRaises(durable.Rejected):
                self.engine.admit(self.fx.value)
            self.assertEqual(os.listdir(self.fx.fx.state), [])
            self.assertNotIn("quiesce", self.host.calls)
            path.write_bytes(before)

    def test_stopped_source_drift_and_alert_write_fault_skip_forward_mutation(self):
        self.engine.admit(self.fx.value)
        self.source.paths["frozen_rendered_compose-after"].write_bytes(b"unapproved: true\n")
        self.fx.fx.receipt_fault = True
        result = self.engine.forward()
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertEqual(result["original_cause"], "forward-revalidate-failed")
        self.assertNotIn("mutate", self.host.calls)
        self.assertNotIn("start-candidate", self.host.calls)
        self.assertFalse(result["alert"]["receipt_persisted"])
        self.assertTrue(result["alert"]["transport_delivered"])
        self.assertTrue(result["start_fenced"])

    def test_changed_policy_cannot_approve_itself_even_with_a_new_policy_file_pin(self):
        self.source.policy["config"] = []
        self.source.paths["policy"].write_bytes(durable.canonical(self.source.policy))
        self.source.configure()
        self.fx.gate.snapshot = self.source.snapshot
        # InputApproval still binds the independently approved whole request.
        with self.assertRaises(durable.Rejected):
            self.engine.admit(self.fx.value)
        self.assertEqual(os.listdir(self.fx.fx.state), [])

    def test_snapshot_byte_pins_do_not_replace_semantic_guard_validation(self):
        path = self.source.paths["config-after"]
        path.write_bytes(b"selected: new\nunrelated: unapproved\n")
        self.source.configure()
        self.fx.gate.snapshot = self.source.snapshot
        raw = self.source.capture()
        self.fx.gate.approval = replace(self.fx.approval, request_sha256=durable.digest(raw))
        with self.assertRaises(durable.Rejected):
            self.engine.admit(self.fx.value)
        self.assertEqual(os.listdir(self.fx.fx.state), [])

    def test_post_helper_recapture_refuses_replaced_source(self):
        original, reached = self.fx.gate._run, []
        def run(raw, remaining):
            original(raw, remaining)
            path = self.source.paths["config-before"]
            path.write_bytes(b"secret: changed\n")
            reached.append("helper-replied-then-source-changed")
        self.fx.gate._run = run
        with self.assertRaises(durable.Rejected):
            self.engine.admit(self.fx.value)
        self.assertEqual(reached, ["helper-replied-then-source-changed"])
        self.assertEqual(os.listdir(self.fx.fx.state), [])
