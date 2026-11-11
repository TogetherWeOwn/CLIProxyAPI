"""Stdout-evidence controls. These verify evidence capture and nothing else."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("stdout_evidence", ROOT / "stdout_evidence.py")
stdout_evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stdout_evidence)

COMMAND = ["python3", "-I", "ops/stock-recovery/packet.py", "ops/stock-recovery/manifest.json"]


def fake_run(returncode=0, payload=b'{"source_binding": "BOUND"}\n'):
    """Stand in for subprocess.run without executing anything."""
    def run(command, stdout=None, check=False, **kwargs):
        stdout.write(payload)
        return subprocess.CompletedProcess(command, returncode)
    return run


class StdoutEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.evidence = self.base / "qualification-evidence"
        self.output = "source-binding.json"

    def capture(self, evidence=None, output=None, command=None, run=None):
        with mock.patch.object(subprocess, "run", side_effect=run or fake_run()) as seen:
            code = stdout_evidence.capture(
                str(evidence or self.evidence), output or self.output,
                command if command is not None else COMMAND)
        return code, seen

    def test_valid_capture_runs_and_returns_zero(self):
        code, seen = self.capture()
        self.assertEqual(code, 0)
        seen.assert_called_once()
        self.assertEqual(seen.call_args.args[0], COMMAND)
        self.assertEqual(seen.call_args.kwargs["check"], False)
        self.assertEqual((self.evidence / self.output).read_bytes(),
                         b'{"source_binding": "BOUND"}\n')

    def test_missing_evidence_directory_is_created_with_parents(self):
        evidence = self.base / "nested" / "deep"
        code, _seen = self.capture(evidence=evidence)
        self.assertEqual(code, 0)
        self.assertTrue(evidence.is_dir())
        self.assertTrue((evidence / self.output).is_file())

    def test_existing_evidence_directory_is_reused(self):
        self.evidence.mkdir()
        code, _seen = self.capture()
        self.assertEqual(code, 0)
        self.assertTrue((self.evidence / self.output).is_file())

    def test_child_nonzero_exit_code_propagates(self):
        code, _seen = self.capture(run=fake_run(returncode=1))
        self.assertEqual(code, 1)

    def test_child_stdout_bytes_land_exactly_in_output_file(self):
        self.capture(run=fake_run(payload=b"\xff\xfe binary bytes\n"))
        self.assertEqual((self.evidence / self.output).read_bytes(), b"\xff\xfe binary bytes\n")

    def test_child_stderr_stays_on_the_workflow_log(self):
        _code, seen = self.capture()
        self.assertNotIn("stderr", seen.call_args.kwargs)

    def test_missing_command_binary_fails_closed(self):
        def run(command, stdout=None, check=False, **kwargs):
            raise FileNotFoundError("python3")
        with self.assertRaisesRegex(stdout_evidence.StdoutEvidenceError, "failed to start"):
            self.capture(run=run)

    def test_empty_directory_fails_closed(self):
        with self.assertRaisesRegex(stdout_evidence.StdoutEvidenceError, "empty"):
            stdout_evidence.capture("", self.output, COMMAND)

    def test_malformed_directory_fails_closed(self):
        with self.assertRaisesRegex(stdout_evidence.StdoutEvidenceError, "malformed"):
            stdout_evidence.capture(str(self.evidence) + " ", self.output, COMMAND)

    def test_symlinked_directory_fails_closed(self):
        real = self.base / "real-evidence"
        real.mkdir()
        link = self.base / "linked-evidence"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(stdout_evidence.StdoutEvidenceError, "symlink"):
            self.capture(evidence=link)

    def test_existing_regular_file_at_directory_fails_closed(self):
        regular = self.base / "file-evidence"
        regular.write_bytes(b"not a directory")
        with self.assertRaisesRegex(stdout_evidence.StdoutEvidenceError, "not a directory"):
            self.capture(evidence=regular)

    def test_output_name_with_separator_fails_closed(self):
        with self.assertRaisesRegex(stdout_evidence.StdoutEvidenceError, "bare filename"):
            self.capture(output="nested/source-binding.json")

    def test_parent_output_name_fails_closed(self):
        with self.assertRaisesRegex(stdout_evidence.StdoutEvidenceError, "bare filename"):
            self.capture(output="..")

    def test_symlinked_output_fails_closed_and_preserves_target(self):
        self.evidence.mkdir()
        target = self.base / "target.json"
        target.write_bytes(b"PRESERVE")
        link = self.evidence / self.output
        link.symlink_to(target)
        with self.assertRaisesRegex(stdout_evidence.StdoutEvidenceError, "symlink"):
            self.capture()
        self.assertEqual(target.read_bytes(), b"PRESERVE")

    def test_output_directory_fails_closed(self):
        self.evidence.mkdir()
        existing = self.evidence / self.output
        existing.mkdir()
        with self.assertRaisesRegex(stdout_evidence.StdoutEvidenceError, "is a directory"):
            self.capture()

    def test_existing_regular_output_is_truncated_on_capture(self):
        self.evidence.mkdir()
        existing = self.evidence / self.output
        existing.write_bytes(b"OLD STALE EVIDENCE\n")
        self.capture(run=fake_run(payload=b"NEW\n"))
        self.assertEqual(existing.read_bytes(), b"NEW\n")

    def test_empty_command_fails_closed_without_subprocess(self):
        with mock.patch.object(subprocess, "run") as seen:
            with self.assertRaisesRegex(stdout_evidence.StdoutEvidenceError, "empty"):
                stdout_evidence.capture(str(self.evidence), self.output, [])
        seen.assert_not_called()

    def test_malformed_command_fails_closed_without_subprocess(self):
        with mock.patch.object(subprocess, "run") as seen:
            with self.assertRaisesRegex(stdout_evidence.StdoutEvidenceError, "malformed"):
                stdout_evidence.capture(str(self.evidence), self.output, ["python3", ""])
        seen.assert_not_called()

    def test_bad_output_never_touches_subprocess(self):
        with mock.patch.object(subprocess, "run") as seen:
            with self.assertRaises(stdout_evidence.StdoutEvidenceError):
                stdout_evidence.capture(str(self.evidence), "a/b.json", COMMAND)
        seen.assert_not_called()

    def test_main_returns_child_code(self):
        with mock.patch.object(subprocess, "run", side_effect=fake_run(returncode=3)) as seen:
            code = stdout_evidence.main([
                "--dir", str(self.evidence), "--output", self.output, "--", *COMMAND])
        self.assertEqual(code, 3)
        self.assertEqual(seen.call_args.args[0], COMMAND)

    def test_main_returns_one_on_validation_failure(self):
        with mock.patch.object(subprocess, "run") as seen:
            code = stdout_evidence.main([
                "--dir", "/missing", "--output", "a/b.json", *COMMAND])
        self.assertEqual(code, 1)
        seen.assert_not_called()

    def test_main_returns_one_when_command_cannot_start(self):
        def run(command, stdout=None, check=False, **kwargs):
            raise FileNotFoundError("python3")
        with mock.patch.object(subprocess, "run", side_effect=run):
            code = stdout_evidence.main([
                "--dir", str(self.evidence), "--output", self.output, *COMMAND])
        self.assertEqual(code, 1)

    def test_main_without_separator_returns_cmd_after_flags(self):
        with mock.patch.object(subprocess, "run", side_effect=fake_run()) as seen:
            code = stdout_evidence.main([
                "--dir", str(self.evidence), "--output", self.output, *COMMAND])
        self.assertEqual(code, 0)
        self.assertEqual(seen.call_args.args[0], COMMAND)


if __name__ == "__main__":
    unittest.main()
