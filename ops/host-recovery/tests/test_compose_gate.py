"""Actual compose-go helper and protected files; scripted manager/fence/oracle."""
from dataclasses import replace
import errno
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from host_recovery import compose_snapshot, durable, input_gate, input_snapshot, protected_file
import test_application_gate
import test_input_gate
from test_installation import approve

SOURCE = b"services: {proxy: {image: '${IMAGE:?required}'}}\n"
FROZEN = {"name": "recovery-test", "networks": {"default": {"name": "recovery-test_default"}},
          "services": {"proxy": {"image": "synthetic:old", "networks": {"default": None}}}}


class ComposeGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="compose-guard-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / "composeguard"
        result = subprocess.run(("go", "build", "-o", str(cls.binary), "./ops/host-recovery/inputguard/composecmd"),
                                cwd=test_input_gate.ROOT, capture_output=True, timeout=180)
        if result.returncode:
            raise RuntimeError("repository guard build failed: " + result.stderr.decode(errors="replace"))

    def setUp(self):
        self.app = test_application_gate.ApplicationGateTests()
        self.app.binary = self.binary
        self.app.setUp()
        self.addCleanup(self.app.doCleanups)
        self.fx, self.source = self.app.fx, self.app.source
        self.engine, self.host = self.app.engine, self.app.host
        self.env_paths = {}
        for side in ("before", "after"):
            path = self.source.sources / ("environment-" + side)
            path.write_bytes(durable.canonical({"IMAGE": "synthetic:old"}))
            path.chmod(0o600)
            self.env_paths[side] = path
            self.source.paths["compose_source-" + side].write_bytes(SOURCE)
            self.source.paths["frozen_rendered_compose-" + side].write_bytes(durable.canonical(FROZEN))
        self.source.policy["compose_source"] = []
        self.source.policy["frozen_rendered_compose"] = []
        self.source.paths["policy"].write_bytes(durable.canonical(self.source.policy))
        self.configure()

    def configure(self):
        self.source.configure()
        clock = lambda: self.fx.fx.time
        check = lambda: self.fx.check() and self.source.boundary_ok
        self.source.snapshot.clock, self.source.snapshot.check = clock, check
        def file(side):
            path = self.env_paths[side]
            return input_snapshot.InputFileApproval(approve(path.parent), path.name, durable.digest(path.read_bytes()))
        self.environments = input_snapshot.InputPairApproval(file("before"), file("after"))
        self.snapshot = compose_snapshot.ProtectedComposeSnapshot(snapshot=self.source.snapshot,
                        environment=self.environments, project_name="recovery-test", check=check, clock=clock)
        raw = self.snapshot(self.fx.value, deadline=self.fx.fx.time + 10)
        self.gate = input_gate.ComposeInputGate(helper_fd=self.fx.helper_fd,
                    approval=replace(self.fx.approval, request_sha256=durable.digest(raw)),
                    snapshot=self.snapshot, check=self.fx.check, clock=clock)
        self.engine.boundary = input_gate.GuardedBoundary(self.host, self.gate, preflight_deadline=self.fx.fx.time + 20)

    def refused(self, call):
        with self.assertRaisesRegex(durable.Rejected, "^input-gate-unconfirmed$"):
            call()

    def test_actual_renderer_runs_at_both_barriers_with_no_ambient_env(self):
        runs, original = [], self.gate._run
        def run(raw, remaining):
            original(raw, remaining)
            runs.append("real-compose-helper-confirmed")
        self.gate._run = run
        with mock.patch.dict(os.environ, {"IMAGE": "ambient-must-not-apply", "COMPOSE_FILE": "/never-read"}):
            self.engine.admit(self.fx.value)
            result = self.engine.forward()
        self.assertEqual(runs, ["real-compose-helper-confirmed"] * 2)
        self.assertEqual(result["outcome"], "candidate_verified")
        self.assertTrue(result["start_fenced"])
        self.assertFalse(result["production_acceptance"])

    def test_frozen_pin_without_correspondence_refuses_before_stop(self):
        for side in ("before", "after"):
            self.source.paths["frozen_rendered_compose-" + side].write_bytes(SOURCE)
        self.configure()  # Synthetic fixture approval, not operational repinning.
        reached, original = [], self.gate._run
        def run(raw, remaining):
            reached.append("renderer-dispatched")
            original(raw, remaining)
        self.gate._run = run
        self.refused(lambda: self.engine.admit(self.fx.value))
        self.assertEqual(reached, ["renderer-dispatched"])
        self.assertEqual(os.listdir(self.fx.fx.state), [])
        self.assertNotIn("quiesce", self.host.calls)

    def test_stopped_actual_render_mismatch_uses_separate_recovery_and_alert(self):
        self.engine.admit(self.fx.value)
        # Test-only injection updates synthetic byte approvals to reach the real
        # renderer after stop. Never repin an armed operational attempt like this.
        for path in self.env_paths.values():
            path.write_bytes(durable.canonical({"IMAGE": "synthetic:wrong"}))
        self.configure()
        self.fx.fx.receipt_fault = True
        reached, original = [], self.gate._run
        def run(raw, remaining):
            reached.append("stopped-renderer-dispatched")
            original(raw, remaining)
        self.gate._run = run
        result = self.engine.forward()
        self.assertEqual(reached, ["stopped-renderer-dispatched"])
        self.assertEqual(result["original_cause"], "forward-revalidate-failed")
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertNotIn("mutate", self.host.calls)
        self.assertNotIn("start-candidate", self.host.calls)
        self.assertFalse(result["alert"]["receipt_persisted"])
        self.assertTrue(result["alert"]["transport_delivered"])
        self.assertTrue(result["start_fenced"])

    def test_environment_byte_drift_or_replacement_is_refused(self):
        for path in self.env_paths.values():
            original = path.read_bytes()
            path.write_bytes(durable.canonical({"IMAGE": "unapproved"}))
            self.refused(lambda: self.engine.admit(self.fx.value))
            path.write_bytes(original)
        path = self.env_paths["after"]
        original = path.read_bytes()
        path.unlink()
        path.symlink_to(self.env_paths["before"])
        self.refused(lambda: self.engine.admit(self.fx.value))
        path.unlink()
        path.write_bytes(original)
        path.chmod(0o600)

    def test_after_helper_environment_rehash_is_required(self):
        reached, original = [], self.gate._run
        def run(raw, remaining):
            original(raw, remaining)
            self.env_paths["after"].write_bytes(durable.canonical({"IMAGE": "unapproved"}))
            reached.append("environment-changed-after-real-pass")
        self.gate._run = run
        self.refused(lambda: self.engine.admit(self.fx.value))
        self.assertEqual(reached, ["environment-changed-after-real-pass"])
        self.assertEqual(os.listdir(self.fx.fx.state), [])

    def test_retained_environment_rehash_after_serialization(self):
        original, reached = compose_snapshot.canonical, []
        def serialize(value):
            raw = original(value)
            if value.get("schema") == "host-recovery-compose-request-v1":
                self.env_paths["after"].write_bytes(original({"IMAGE": "synthetic:new"}))
                reached.append("serialized-then-mutated-same-inode")
            return raw
        # Deliberately suppress metadata change detection to isolate byte rehash.
        with mock.patch.object(compose_snapshot, "canonical", side_effect=serialize), mock.patch.object(
                protected_file, "signature", return_value="synthetic-coarse-metadata"):
            self.refused(lambda: self.engine.admit(self.fx.value))
        self.assertEqual(reached, ["serialized-then-mutated-same-inode"])

    def test_final_base_recapture_cannot_hide_same_inode_environment_change(self):
        original, reached, calls = self.source.snapshot.__class__.__call__, [], []
        def capture(snapshot, value, *, deadline):
            raw = original(snapshot, value, deadline=deadline)
            calls.append("base-capture")
            if len(calls) == 2:
                self.env_paths["after"].write_bytes(durable.canonical({"IMAGE": "synthetic:new"}))
                reached.append("changed-during-final-base-recapture")
            return raw
        with mock.patch.object(self.source.snapshot.__class__, "__call__", capture), mock.patch.object(
                protected_file, "signature", return_value="synthetic-coarse-metadata"):
            self.refused(lambda: self.engine.admit(self.fx.value))
        self.assertEqual(reached, ["changed-during-final-base-recapture"])
        self.assertEqual(len(calls), 2)

    def test_environment_schema_and_role_aliases_are_refused(self):
        path = self.env_paths["after"]
        for raw in (b'{"IMAGE":"one","IMAGE":"two"}', b'{"IMAGE":null}', b'{"IMAGE":1}', b'{"bad-key":"one"}'):
            path.write_bytes(raw)
            with self.assertRaisesRegex(durable.Rejected, "^compose-snapshot-unconfirmed$"):
                self.configure()
        for environment in (input_snapshot.InputPairApproval(self.environments.before, self.environments.before),
                            input_snapshot.InputPairApproval(self.source.approval.config.before, self.environments.after)):
            with self.assertRaisesRegex(durable.Rejected, "^compose-snapshot-distinct-files-required$"):
                compose_snapshot.ProtectedComposeSnapshot(snapshot=self.source.snapshot, environment=environment,
                    project_name="recovery-test", check=self.fx.check, clock=lambda: self.fx.fx.time)

    def test_environment_storage_faults_are_reached_and_secret_free(self):
        for code in (errno.EIO, errno.ENOSPC):
            reached = []
            original = protected_file.ProtectedFile.checksum
            def checksum(source):
                if source.name.startswith("environment-"):
                    reached.append(source.name)
                    raise OSError(code, "synthetic-secret-diagnostic")
                return original(source)
            with mock.patch.object(protected_file.ProtectedFile, "checksum", checksum):
                self.refused(lambda: self.engine.admit(self.fx.value))
            self.assertEqual(reached, ["environment-before"])
            self.assertEqual(os.listdir(self.fx.fx.state), [])

    def test_capture_is_readonly_and_deadline_and_boundary_are_required(self):
        before = {side: (durable.signature(path.stat()), path.read_bytes()) for side, path in self.env_paths.items()}
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("capture-must-not-execute")):
            raw = self.snapshot(self.fx.value, deadline=self.fx.fx.time + 10)
        self.assertEqual(durable.decode(raw)["renderer"], compose_snapshot.RENDERER)
        self.assertEqual(before, {side: (durable.signature(path.stat()), path.read_bytes()) for side, path in self.env_paths.items()})
        for check, deadline in ((lambda: 1, self.fx.fx.time + 10), (self.fx.check, self.fx.fx.time)):
            self.snapshot.check = check
            with self.assertRaisesRegex(durable.Rejected, "^compose-snapshot-unconfirmed$"):
                self.snapshot(self.fx.value, deadline=deadline)

    def test_base_capture_is_rechecked_and_changed_source_refuses(self):
        original, reached = compose_snapshot.canonical, []
        def serialize(value):
            raw = original(value)
            if value.get("schema") == "host-recovery-compose-request-v1":
                self.source.paths["compose_source-before"].write_bytes(b"services: {}\n")
                reached.append("serialized-then-base-mutated")
            return raw
        with mock.patch.object(compose_snapshot, "canonical", side_effect=serialize):
            self.refused(lambda: self.engine.admit(self.fx.value))
        self.assertEqual(reached, ["serialized-then-base-mutated"])

    def test_helper_refusals_emit_no_paths_environment_or_diagnostics(self):
        raw = self.snapshot(self.fx.value, deadline=self.fx.fx.time + 10)
        for value in (b'{"secret-diagnostic":', raw.replace(compose_snapshot.RENDERER.encode(), b"not-the-renderer"), raw + raw):
            result = subprocess.run((str(self.binary), "/never-read-this"), input=value, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(result.stdout, input_gate.ComposeInputGate.receipt.replace(
                b'"matched":true,"application_validated":true,"compose_validated":true',
                b'"matched":false,"application_validated":false,"compose_validated":false'))
