"""Actual source-profile helper/files; scripted manager, fence, oracle and alerts."""
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from host_recovery import compose_snapshot, durable, input_gate, protected_file
import test_compose_gate
import test_input_gate

META = b"plugins: {enabled: true, configs: {meta: {enabled: true, reasoning-replay: {enabled: true, models: ['muse-spark-*']}}}}\n"


class MetaGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="meta-input-guard-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / "metaguard"
        cls.compose_binary = Path(cls.build.name) / "composeguard"
        for binary, command in ((cls.binary, "metacmd"), (cls.compose_binary, "composecmd")):
            result = subprocess.run(("go", "build", "-o", str(binary),
                                     "./ops/host-recovery/inputguard/" + command),
                                    cwd=test_input_gate.ROOT, capture_output=True, timeout=180)
            if result.returncode:
                raise RuntimeError("repository helper build failed: " + result.stderr.decode(errors="replace"))

    def setUp(self):
        self.comp = test_compose_gate.ComposeGateTests()
        self.comp.binary = self.binary
        self.comp.setUp()
        self.addCleanup(self.comp.doCleanups)
        self.fx, self.source = self.comp.fx, self.comp.source
        self.engine, self.host = self.comp.engine, self.comp.host
        for side in ("before", "after"):
            path = self.source.paths["config-" + side]
            path.write_bytes(path.read_bytes() + META)
        self.configure()

    def configure(self):
        self.comp.configure()
        base = self.comp.snapshot
        self.snapshot = compose_snapshot.ProtectedMetaSnapshot(snapshot=base.snapshot,
                        environment=base.environment, project_name=base.project_name,
                        check=base.check, clock=base.clock)
        raw = self.snapshot(self.fx.value, deadline=self.fx.fx.time + 10)
        self.gate = input_gate.MetaInputGate(helper_fd=self.fx.helper_fd,
                    approval=replace(self.fx.approval, request_sha256=durable.digest(raw)),
                    snapshot=self.snapshot, check=self.fx.check, clock=lambda: self.fx.fx.time)
        self.engine.boundary = input_gate.GuardedBoundary(self.host, self.gate,
                              preflight_deadline=self.fx.fx.time + 20)

    def refused(self, call):
        with self.assertRaisesRegex(durable.Rejected, "^input-gate-unconfirmed$"):
            call()

    def test_real_source_profile_helper_at_both_barriers(self):
        reached, original = [], self.gate._run
        def run(raw, remaining):
            original(raw, remaining)
            reached.append("real-meta-profile-confirmed")
        self.gate._run = run
        self.engine.admit(self.fx.value)
        result = self.engine.forward()
        self.assertEqual(reached, ["real-meta-profile-confirmed"] * 2)
        self.assertEqual(result["outcome"], "candidate_verified")
        self.assertTrue(result["start_fenced"])
        self.assertFalse(result["production_acceptance"])

    def malformed(self):
        for side in ("before", "after"):
            path = self.source.paths["config-" + side]
            path.write_bytes(path.read_bytes().replace(b"models: [", b"models: [1, "))
        self.configure()  # Test-only byte approvals, not operational provisioning.

    def test_opaque_compose_success_does_not_validate_meta_options(self):
        self.malformed()
        raw = self.snapshot(self.fx.value, deadline=self.fx.fx.time + 10)
        inputs = durable.canonical(durable.decode(raw)["inputs"])
        compared = subprocess.run((str(self.compose_binary),), input=inputs, capture_output=True, timeout=10)
        self.assertEqual(compared.returncode, 0)
        self.assertEqual(compared.stdout, input_gate.ComposeInputGate.receipt)
        reached, original = [], self.gate._run
        def run(raw, remaining):
            reached.append("meta-profile-dispatched")
            original(raw, remaining)
        self.gate._run = run
        self.refused(lambda: self.engine.admit(self.fx.value))
        self.assertEqual(reached, ["meta-profile-dispatched"])
        self.assertEqual(os.listdir(self.fx.fx.state), [])
        self.assertNotIn("quiesce", self.host.calls)

    def test_stopped_meta_schema_failure_uses_separate_recovery(self):
        self.engine.admit(self.fx.value)
        self.malformed()  # Inject matching synthetic approvals to reach schema.
        self.fx.fx.receipt_fault = True
        reached, original = [], self.gate._run
        def run(raw, remaining):
            reached.append("stopped-meta-profile-dispatched")
            original(raw, remaining)
        self.gate._run = run
        result = self.engine.forward()
        self.assertEqual(reached, ["stopped-meta-profile-dispatched"])
        self.assertEqual(result["original_cause"], "forward-revalidate-failed")
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertNotIn("mutate", self.host.calls)
        self.assertNotIn("start-candidate", self.host.calls)
        self.assertFalse(result["alert"]["receipt_persisted"])
        self.assertTrue(result["alert"]["transport_delivered"])
        self.assertTrue(result["start_fenced"])

    def test_compose_only_helper_cannot_downgrade_profile(self):
        helper = self.source.root / "compose-only-helper"
        helper.write_bytes(self.compose_binary.read_bytes())
        helper.chmod(0o700)
        fd = os.open(helper, os.O_RDONLY | os.O_NOFOLLOW)
        self.addCleanup(os.close, fd)
        # Give the comparison helper its own valid envelope so it really emits a
        # successful older receipt; it is not refused just on malformed input.
        base = self.comp.snapshot
        raw = base(self.fx.value, deadline=self.fx.fx.time + 10)
        gate = input_gate.MetaInputGate(helper_fd=fd, approval=replace(self.gate.approval,
                    helper_sha256=durable.digest(helper.read_bytes()), request_sha256=durable.digest(raw)),
                    snapshot=base, check=self.fx.check, clock=lambda: self.fx.fx.time)
        self.refused(lambda: gate.verify(self.fx.value, deadline=self.fx.fx.time + 10))

    def test_profile_envelope_is_inside_retained_descriptor_rehash(self):
        reached, original = [], compose_snapshot.canonical
        def serialize(value):
            raw = original(value)
            if value.get("schema") == "host-recovery-meta-input-request-v1":
                self.comp.env_paths["after"].write_bytes(durable.canonical({"IMAGE": "unapproved"}))
                reached.append("meta-serialized-then-environment-mutated")
            return raw
        with mock.patch.object(compose_snapshot, "canonical", side_effect=serialize), mock.patch.object(
                protected_file, "signature", return_value="synthetic-coarse-metadata"):
            self.refused(lambda: self.engine.admit(self.fx.value))
        self.assertEqual(reached, ["meta-serialized-then-environment-mutated"])
        self.assertEqual(os.listdir(self.fx.fx.state), [])

    def test_post_helper_source_drift_still_refuses(self):
        reached, original = [], self.gate._run
        def run(raw, remaining):
            original(raw, remaining)
            path = self.source.paths["config-after"]
            path.write_bytes(path.read_bytes().replace(b"models: [", b"models: [1, "))
            reached.append("source-mutated-after-real-pass")
        self.gate._run = run
        self.refused(lambda: self.engine.admit(self.fx.value))
        self.assertEqual(reached, ["source-mutated-after-real-pass"])
        self.assertEqual(os.listdir(self.fx.fx.state), [])

    def test_helper_profile_and_protocol_refusals_are_secret_free(self):
        raw = self.snapshot(self.fx.value, deadline=self.fx.fx.time + 10)
        for bad in (b'{"secret":', raw + raw, raw.replace(compose_snapshot.META_PROFILE.encode(), b"unknown-source")):
            result = subprocess.run((str(self.binary), "/never-read"), input=bad, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(result.stdout, input_gate.MetaInputGate.receipt.replace(b":true", b":false"))
