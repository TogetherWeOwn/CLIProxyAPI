"""Built application helper + protected inputs; scripted host/fence/oracle only."""
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from host_recovery import durable, input_gate
import test_input_gate
import test_input_snapshot


class ApplicationGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="application-guard-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / "applicationguard"
        cls.comparison_binary = Path(cls.build.name) / "comparison"
        for binary, command in ((cls.binary, "applicationcmd"), (cls.comparison_binary, "cmd")):
            result = subprocess.run(("go", "build", "-o", str(binary),
                                     "./ops/host-recovery/inputguard/" + command),
                                    cwd=test_input_gate.ROOT, capture_output=True, timeout=180)
            if result.returncode:
                raise RuntimeError("repository guard build failed: " + result.stderr.decode(errors="replace"))

    def setUp(self):
        self.fx = test_input_gate.InputGateTests()
        self.fx.binary = self.binary
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.source = test_input_snapshot.SnapshotTests()
        self.source.setUp()
        self.addCleanup(self.source.doCleanups)
        self.source.value = self.fx.value
        self.source.policy["config"][0]["path"] = ["host"]
        self.configure(b"host: old\nport: 8317\n", b"host: new\nport: 8317\n")
        self.engine, self.host = self.fx.fx.engine, self.fx.fx.boundary

    def configure(self, before, after):
        for side, raw in (("before", before), ("after", after)):
            self.source.paths["config-" + side].write_bytes(raw)
        self.source.paths["policy"].write_bytes(durable.canonical(self.source.policy))
        self.source.configure()
        self.source.snapshot.clock = lambda: self.fx.fx.time
        self.source.snapshot.check = lambda: self.fx.check() and self.source.boundary_ok
        raw = self.source.snapshot(self.fx.value, deadline=self.fx.fx.time + 10)
        approval = replace(self.fx.approval, request_sha256=durable.digest(raw))
        self.gate = input_gate.ApplicationInputGate(helper_fd=self.fx.helper_fd, approval=approval,
                     snapshot=self.source.snapshot, check=self.fx.check, clock=lambda: self.fx.fx.time)
        self.fx.fx.engine.boundary = input_gate.GuardedBoundary(self.fx.fx.boundary, self.gate,
                                                               preflight_deadline=self.fx.fx.time + 20)

    def refused(self, call):
        with self.assertRaisesRegex(durable.Rejected, "^input-gate-unconfirmed$"):
            call()

    def test_application_helper_and_protected_inputs_run_at_both_barriers(self):
        runs = []
        original = self.gate._run
        def run(raw, remaining):
            original(raw, remaining)
            runs.append("actual-application-helper-confirmed")
        self.gate._run = run
        self.engine.admit(self.fx.value)
        result = self.engine.forward()
        self.assertEqual(runs, ["actual-application-helper-confirmed"] * 2)
        self.assertEqual(result["outcome"], "candidate_verified")
        self.assertIn("start-candidate", self.host.calls)
        self.assertTrue(result["start_fenced"])
        self.assertFalse(result["production_acceptance"])

    def test_pinned_invalid_host_type_refuses_before_arm(self):
        self.configure(b"host: old\nport: '8317'\n", b"host: new\nport: '8317'\n")
        # Port is deliberately unchanged, so exact-delta comparison succeeds.
        # The actual host type validator, not a mismatching byte pin, must refuse.
        raw = self.source.snapshot(self.fx.value, deadline=self.fx.fx.time + 10)
        compared = subprocess.run((str(self.comparison_binary),), input=raw, capture_output=True, timeout=10)
        self.assertEqual(compared.returncode, 0)
        self.assertEqual(compared.stdout, input_gate.RECEIPT)
        reached = []
        original = self.gate._run
        def run(raw, remaining):
            reached.append("helper-dispatched")
            original(raw, remaining)
        self.gate._run = run
        self.refused(lambda: self.engine.admit(self.fx.value))
        self.assertEqual(reached, ["helper-dispatched"])
        self.assertEqual(os.listdir(self.fx.fx.state), [])
        self.assertNotIn("quiesce", self.host.calls)

    def test_stopped_schema_refusal_with_all_matching_pins_uses_recovery(self):
        self.engine.admit(self.fx.value)
        # Test-only fault: replace independently approved byte pins as well as
        # inputs, bypassing early pin refusal to reach actual schema validation.
        # Real provisioning must never repin an armed attempt this way.
        self.configure(b"host: old\nport: '8317'\n", b"host: new\nport: '8317'\n")
        self.fx.fx.receipt_fault = True
        reached = []
        original = self.gate._run
        def run(raw, remaining):
            reached.append("stopped-helper-dispatched")
            original(raw, remaining)
        self.gate._run = run
        result = self.engine.forward()
        self.assertEqual(reached, ["stopped-helper-dispatched"])
        self.assertEqual(result["original_cause"], "forward-revalidate-failed")
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertNotIn("mutate", self.host.calls)
        self.assertNotIn("start-candidate", self.host.calls)
        self.assertFalse(result["alert"]["receipt_persisted"])
        self.assertTrue(result["alert"]["transport_delivered"])
        self.assertTrue(result["start_fenced"])

    def test_comparison_receipt_cannot_downgrade_application_validation(self):
        helper = self.source.root / "comparison-helper"
        helper.write_bytes(self.comparison_binary.read_bytes())
        helper.chmod(0o700)
        fd = os.open(helper, os.O_RDONLY | os.O_NOFOLLOW)
        self.addCleanup(os.close, fd)
        gate = input_gate.ApplicationInputGate(helper_fd=fd, approval=replace(self.gate.approval,
                   helper_sha256=durable.digest(helper.read_bytes())), snapshot=self.source.snapshot,
                   check=self.fx.check, clock=lambda: self.fx.fx.time)
        self.refused(lambda: gate.verify(self.fx.value, deadline=self.fx.fx.time + 10))
        self.assertEqual(os.listdir(self.fx.fx.state), [])
        self.engine.admit(self.fx.value)

    def test_post_helper_recapture_still_rejects_actual_source_drift(self):
        original, reached = self.gate._run, []
        def run(raw, remaining):
            original(raw, remaining)
            self.source.paths["config-after"].write_bytes(b"host: unapproved\nport: 8317\n")
            reached.append("changed-after-real-schema-pass")
        self.gate._run = run
        self.refused(lambda: self.engine.admit(self.fx.value))
        self.assertEqual(reached, ["changed-after-real-schema-pass"])
        self.assertEqual(os.listdir(self.fx.fx.state), [])

    def test_helper_cli_arguments_and_malformed_input_cannot_load_paths(self):
        for args, raw in ((("not-an-input-path",), b"{}"), ((), b"{\"secret-value\":")):
            result = subprocess.run((str(self.binary), *args), input=raw, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(result.stdout, input_gate.ApplicationInputGate.receipt.replace(
                b'"matched":true,"application_validated":true', b'"matched":false,"application_validated":false'))

    def test_opaque_plugin_options_are_not_misreported_as_plugin_schema_coverage(self):
        plugin = b"plugins: {enabled: true, configs: {meta: {enabled: true, unvalidated-plugin-option: 1}}}\n"
        self.configure(b"host: old\n" + plugin, b"host: new\n" + plugin)
        self.engine.admit(self.fx.value)
        self.assertEqual(self.host.calls, ["preflight"])
        self.assertEqual(self.gate.pending, [])
