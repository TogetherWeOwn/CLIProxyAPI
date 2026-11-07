"""Real built guard/descriptor/pipe tests; scripted manager/fence/schema boundaries."""
import base64
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from host_recovery import durable, input_gate, loading
import test_coordinator
from test_recovery_state import intent

ROLES = ("config", "compose_source", "frozen_rendered_compose")
ROOT = Path(__file__).resolve().parents[3]


def semantic_string(value):
    # Go's typed scalar wire representation, not a second YAML parser.
    raw = json.dumps({"kind": "!!str", "scalar": value}, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def request():
    before, after = b"selected: old\nunrelated: keep\n", b"selected: new\nunrelated: keep\n"
    pair = {"before": base64.b64encode(before).decode(), "after": base64.b64encode(after).decode(),
            "before_sha256": durable.digest(before), "after_sha256": durable.digest(after),
            "changes": [{"path": ["selected"], "before": semantic_string("old"),
                         "after": semantic_string("new")}]}
    return {"schema": "host-recovery-input-request-v1", **{role: copy.deepcopy(pair) for role in ROLES}}


class InputGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="host-recovery-guard-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / "inputguard"
        result = subprocess.run(("go", "build", "-o", str(cls.binary), "./ops/host-recovery/inputguard/cmd"),
                                cwd=ROOT, capture_output=True, timeout=180)
        if result.returncode != 0:
            raise RuntimeError("repository guard build failed: " + result.stderr.decode(errors="replace"))

    def setUp(self):
        self.fx = test_coordinator.CoordinatorTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.value = intent()
        self.value["baseline_sha256"] = durable.digest(durable.canonical(self.fx.tree))
        self.helper = Path(self.fx.temp.name) / "inputguard"
        shutil.copyfile(self.binary, self.helper)
        self.helper.chmod(0o700)
        self.helper_fd = os.open(self.helper, os.O_RDONLY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.helper_fd)
        self.sources = Path(self.fx.temp.name) / "inputs"
        self.sources.mkdir(mode=0o700)
        self.source_fd = os.open(self.sources, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.source_fd)
        self.captures, self.checks = [], 0
        self.boundary_ok = True
        self.spec = request()
        self.configure()

    def configure(self):
        for role in ROLES:
            for side in ("before", "after"):
                path = self.sources / (role + "-" + side)
                path.write_bytes(base64.b64decode(self.spec[role][side]))
                path.chmod(0o600)
        self.source_identity = durable.signature(os.fstat(self.source_fd))
        self.helper_identity = (os.fstat(self.helper_fd).st_dev, os.fstat(self.helper_fd).st_ino)
        self.approval = input_gate.InputApproval(
            durable.digest(durable.canonical(self.value)), durable.digest(durable.canonical(self.spec)),
            durable.digest(self.helper.read_bytes()), os.geteuid(), os.getegid())
        self.gate = input_gate.ExactInputGate(helper_fd=self.helper_fd, approval=self.approval,
                     snapshot=self.capture, check=self.check, clock=lambda: self.fx.time)
        self.fx.engine.boundary = input_gate.GuardedBoundary(self.fx.boundary, self.gate,
                                                            preflight_deadline=self.fx.time + 20)

    def check(self):
        self.checks += 1
        st = self.helper.stat(follow_symlinks=False)
        return (self.boundary_ok and durable.signature(os.fstat(self.source_fd)) == self.source_identity
                and (st.st_dev, st.st_ino) == self.helper_identity)

    def capture(self, value, *, deadline):
        self.assertEqual(value, self.value)
        self.assertGreater(deadline, self.fx.time)
        self.captures.append(deadline)
        spec = copy.deepcopy(self.spec)
        for role in ROLES:
            for side in ("before", "after"):
                raw, st = loading.read_file(self.source_fd, role + "-" + side, limit=4 * 1024 * 1024)
                self.assertEqual((st.st_uid, st.st_gid, st.st_mode & 0o777), (os.geteuid(), os.getegid(), 0o600))
                spec[role][side] = base64.b64encode(raw).decode()
        return durable.canonical(spec)

    def verify(self, *, gate=None, deadline=None):
        return (gate or self.gate).verify(self.value, deadline=deadline or self.fx.time + 10)

    def assert_refused(self, call=None):
        with self.assertRaisesRegex(durable.Rejected, "^input-gate-unconfirmed$"):
            (call or self.verify)()

    def test_real_helper_runs_at_admission_and_again_after_stop(self):
        self.fx.engine.admit(self.value)
        self.assertEqual(len(self.captures), 2)
        self.assertEqual(self.fx.boundary.calls, ["preflight"])
        result = self.fx.engine.forward()
        self.assertEqual(result["outcome"], "candidate_verified")
        self.assertTrue(result["start_fenced"])
        self.assertFalse(result["production_acceptance"])
        self.assertEqual(len(self.captures), 4)
        revalidate = [event for event in result["timing_events"] if event.get("phase") == "revalidate"]
        self.assertTrue(revalidate)
        self.assertIn("mutate", self.fx.boundary.calls)
        self.assertEqual(self.gate.pending, [])

    def test_semantic_mismatch_before_arm_never_stops_or_writes_intent(self):
        raw = b"selected: new\nunrelated: secret-unapproved-value\n"
        self.spec["config"]["after"] = base64.b64encode(raw).decode()
        self.spec["config"]["after_sha256"] = durable.digest(raw)
        self.configure()  # Raw bytes are pinned but semantic approval still excludes the change.
        self.assert_refused(lambda: self.fx.engine.admit(self.value))
        self.assertEqual(self.fx.boundary.calls, ["preflight"])
        self.assertEqual(os.listdir(self.fx.state), [])
        self.assertEqual(self.fx.file.read_bytes(), b"original-baseline-config")

    def test_render_drift_after_arm_prevents_mutation_and_uses_recovery(self):
        self.fx.engine.admit(self.value)
        (self.sources / "frozen_rendered_compose-after").write_bytes(b"secret-invalid-yaml: [")
        self.fx.receipt_fault = True
        result = self.fx.engine.forward()
        self.assertEqual(result["original_cause"], "forward-revalidate-failed")
        self.assertNotIn("mutate", self.fx.boundary.calls)
        self.assertNotIn("start-candidate", self.fx.boundary.calls)
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertTrue(result["start_fenced"])
        self.assertFalse(result["alert"]["receipt_persisted"])
        self.assertTrue(result["alert"]["transport_delivered"])
        self.assertEqual(len(self.fx.notices), 1)
        self.assertEqual(self.fx.file.read_bytes(), b"original-baseline-config")

    def test_no_saved_green_receipt_can_skip_fresh_capture(self):
        self.assertTrue(self.verify())
        for role in ROLES:
            for side in ("before", "after"):
                with self.subTest(role=role, side=side):
                    path = self.sources / (role + "-" + side)
                    old = path.read_bytes()
                    path.write_bytes(old + b"# changed\n")
                    self.assert_refused()
                    path.write_bytes(old)

    def test_helper_read_storage_faults_refuse_without_intent_or_stop(self):
        for error in (errno.EIO, errno.ENOSPC):
            with self.subTest(error=error):
                with mock.patch.object(input_gate.os, "pread", side_effect=OSError(error, "secret-device")) as read:
                    self.assert_refused(lambda: self.fx.engine.admit(self.value))
                    self.assertEqual(read.call_count, 1)
                self.assertEqual(os.listdir(self.fx.state), [])
                self.assertNotIn("quiesce", self.fx.boundary.calls)

    def test_stopped_helper_failure_and_alert_receipt_fault_still_attempt_transport(self):
        self.fx.engine.admit(self.value)
        self.fx.receipt_fault = True
        with mock.patch.object(input_gate.os, "pread", side_effect=OSError(errno.EIO, "secret-device")) as read:
            result = self.fx.engine.forward()
            self.assertEqual(read.call_count, 1)
        self.assertNotIn("mutate", self.fx.boundary.calls)
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertFalse(result["alert"]["receipt_persisted"])
        self.assertTrue(result["alert"]["transport_delivered"])
        self.assertEqual(len(self.fx.notices), 1)

    def test_source_change_during_helper_is_refused(self):
        original = self.gate._run
        def run(raw, remaining):
            original(raw, remaining)
            (self.sources / "compose_source-after").write_bytes(b"changed: true\n")
        self.gate._run = run
        self.assert_refused()

    def test_helper_change_during_check_is_refused(self):
        original = self.gate._run
        def run(raw, remaining):
            original(raw, remaining)
            self.helper.chmod(0o600)
        self.gate._run = run
        self.assert_refused()

    def test_helper_path_replacement_cannot_reopen_uninspected_binary(self):
        replacement = self.helper.with_name("replacement")
        shutil.copyfile(self.binary, replacement)
        replacement.chmod(0o700)
        os.replace(replacement, self.helper)
        self.assert_refused()

    def test_helper_pin_mode_links_and_metadata_are_required(self):
        self.helper.chmod(0o777)
        self.assert_refused()
        self.helper.chmod(0o700)
        link = self.helper.with_name("hardlink")
        os.link(self.helper, link)
        self.assert_refused()
        link.unlink()
        with self.helper.open("r+b") as stream:
            stream.seek(-1, os.SEEK_END)
            stream.write(b"x")
        self.assert_refused()

    def test_intent_approval_cannot_be_reused_for_another_attempt(self):
        self.value["attempt_id"] = "other-attempt"
        self.assert_refused()
        self.assertEqual(self.captures, [])

    def test_existing_listener_and_stopped_checks_are_not_replaced(self):
        self.fx.boundary.overrides["preflight"] = False
        with self.assertRaises(durable.Rejected):
            self.fx.engine.admit(self.value)
        self.assertEqual(self.captures, [])
        self.fx.boundary.overrides.clear()
        self.fx.engine.admit(self.value)
        count = len(self.captures)
        self.fx.boundary.overrides["revalidate"] = False
        self.assertEqual(self.fx.engine.forward()["outcome"], "baseline_restored")
        self.assertEqual(len(self.captures), count)
        self.assertNotIn("mutate", self.fx.boundary.calls)

    def test_boundary_revocation_and_capture_error_are_secret_free(self):
        self.boundary_ok = False
        self.assert_refused()
        self.boundary_ok = True
        def fail(value, *, deadline):
            raise OSError("secret-filename-and-parser-text")
        self.gate.snapshot = fail
        self.assert_refused()

    def test_inclusive_deadline_and_clock_discontinuity_refuse(self):
        self.assert_refused(lambda: self.verify(deadline=self.fx.time))
        def capture(value, *, deadline):
            raw = self.capture(value, deadline=deadline)
            self.fx.time = deadline
            return raw
        self.gate.snapshot = capture
        self.assert_refused()
        self.gate.snapshot = self.capture
        ticks = iter((1000.0, 999.0))
        self.gate.clock = lambda: next(ticks)
        self.assert_refused()

    def script_gate(self, code):
        path = Path(self.fx.temp.name) / "script-helper"
        path.write_text("#!/usr/bin/python3 -I\n" + code)
        path.chmod(0o700)
        fd = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        approval = input_gate.InputApproval(self.approval.intent_sha256, self.approval.request_sha256,
                                           durable.digest(path.read_bytes()), os.geteuid(), os.getegid())
        return input_gate.ExactInputGate(helper_fd=fd, approval=approval, snapshot=self.capture,
                                        check=lambda: True, clock=time.monotonic)

    def run_script(self, code, *, seconds=3):
        gate = self.script_gate(code)
        try:
            self.assert_refused(lambda: gate.verify(self.value, deadline=time.monotonic() + seconds))
        finally:
            for proc in gate.pending:
                proc.wait(timeout=3)  # Test-only collection after the gate has returned failure.
            gate.reap()
        self.assertEqual(gate.pending, [])

    def test_extra_partial_false_authorizing_and_failed_receipts_are_refused(self):
        for output, exit_code in ((input_gate.RECEIPT + b"extra", 0), (input_gate.RECEIPT[:-2], 0),
                                  (input_gate.RECEIPT.replace(b'"start_authorized":false', b'"start_authorized":true'), 0),
                                  (input_gate.RECEIPT, 1)):
            with self.subTest(exit=exit_code, size=len(output)):
                self.run_script("import os,sys\nsys.stdin.buffer.read()\nos.write(1," + repr(output)
                                + ")\nsys.exit(" + str(exit_code) + ")\n")

    def test_stdout_overflow_cannot_block_on_input_backpressure(self):
        self.run_script("import os\nos.write(1,b'x'*10000)\n")

    def test_stalled_helper_is_killed_within_shared_deadline(self):
        self.run_script("import signal\nsignal.pause()\n", seconds=0.2)

    def test_early_success_without_consuming_complete_request_is_refused(self):
        # A pipe may buffer a small request before the helper exits. Force a request
        # larger than pipe capacity so incomplete delivery is observable.
        self.gate.snapshot = lambda value, deadline: b"x" * (2 * 1024 * 1024)
        gate = self.script_gate("import os\nos.write(1," + repr(input_gate.RECEIPT) + ")\n")
        raw = b"x" * (2 * 1024 * 1024)
        gate.snapshot = lambda value, deadline: raw
        gate.approval = input_gate.InputApproval(gate.approval.intent_sha256, durable.digest(raw),
                                                gate.approval.helper_sha256, os.geteuid(), os.getegid())
        self.assert_refused(lambda: gate.verify(self.value, deadline=time.monotonic() + 3))
        for proc in gate.pending:
            proc.wait(timeout=3)
        gate.reap()

    def test_actual_command_rejects_arguments_and_never_echoes_bad_input(self):
        for args, raw in ((("secret-path-argument",), durable.canonical(self.spec)),
                          ((), b"secret-invalid-json"), ((), durable.canonical(self.spec) + b"{}")):
            result = subprocess.run((str(self.helper), *args), input=raw, capture_output=True, timeout=3,
                                    cwd="/", env={"PATH": "/usr/bin:/bin"})
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(result.stdout, input_gate.RECEIPT.replace(b'"matched":true', b'"matched":false'))
