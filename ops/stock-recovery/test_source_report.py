"""Source-report controls. These verify HOLD-report composition only."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("source_report", ROOT / "source_report.py")
source_report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source_report)

# Token-identical to the former workflow shell lines.
PACKET_COMMAND = [
    "python3", "-I", "ops/stock-recovery/stdout_evidence.py",
    "--dir", "qualification-evidence", "--output", "source-binding.json",
    "--", "python3", "-I", "ops/stock-recovery/packet.py",
    "ops/stock-recovery/manifest.json",
]
IDENTITY_COMMAND = [
    "python3", "-I", "ops/stock-recovery/actions_identity.py",
    "--mode", "source", "--output", "qualification-evidence/actions-identity.json",
]


def fake_run(codes):
    """Stand in for subprocess.run without executing anything."""
    remaining = list(codes)

    def run(command, check=False, **kwargs):
        return subprocess.CompletedProcess(command, remaining.pop(0))
    return run


class SourceReportTests(unittest.TestCase):
    def record(self, run):
        with mock.patch.object(subprocess, "run", side_effect=run) as seen:
            code = source_report.record()
        return code, seen

    def test_valid_report_runs_packet_then_identity_and_returns_zero(self):
        code, seen = self.record(fake_run([0, 0]))
        self.assertEqual(code, 0)
        self.assertEqual(seen.call_count, 2)
        first, second = seen.call_args_list
        self.assertEqual(first.args[0], PACKET_COMMAND)
        self.assertEqual(second.args[0], IDENTITY_COMMAND)

    def test_child_commands_are_fixed_and_checked_without_a_shell(self):
        _code, seen = self.record(fake_run([0, 0]))
        for call in seen.call_args_list:
            self.assertEqual(call.kwargs["check"], False)
            self.assertNotIn("shell", call.kwargs)
            self.assertNotIn("env", call.kwargs)

    def test_packet_nonzero_code_propagates_and_identity_never_runs(self):
        code, seen = self.record(fake_run([1]))
        self.assertEqual(code, 1)
        seen.assert_called_once()
        self.assertEqual(seen.call_args.args[0], PACKET_COMMAND)

    def test_identity_nonzero_code_propagates_after_packet_succeeds(self):
        code, seen = self.record(fake_run([0, 2]))
        self.assertEqual(code, 2)
        self.assertEqual(seen.call_count, 2)

    def test_packet_failure_to_start_fails_closed_without_identity(self):
        def run(command, check=False, **kwargs):
            raise FileNotFoundError("python3")
        with mock.patch.object(subprocess, "run", side_effect=run) as seen:
            with self.assertRaisesRegex(source_report.SourceReportError, "failed to start"):
                source_report.record()
        seen.assert_called_once()

    def test_identity_failure_to_start_fails_closed(self):
        calls = []

        def run(command, check=False, **kwargs):
            calls.append(command)
            if len(calls) == 2:
                raise FileNotFoundError("python3")
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(source_report.SourceReportError, "failed to start"):
                source_report.record()

    def test_command_constants_match_workflow_tokens(self):
        self.assertEqual(source_report.PACKET_COMMAND, PACKET_COMMAND)
        self.assertEqual(source_report.IDENTITY_COMMAND, IDENTITY_COMMAND)

    def test_record_command_lists_are_not_mutated_by_runs(self):
        packet_before = list(source_report.PACKET_COMMAND)
        identity_before = list(source_report.IDENTITY_COMMAND)
        self.record(fake_run([0, 0]))
        self.assertEqual(source_report.PACKET_COMMAND, packet_before)
        self.assertEqual(source_report.IDENTITY_COMMAND, identity_before)

    def test_main_returns_child_code(self):
        with mock.patch.object(subprocess, "run", side_effect=fake_run([0, 3])):
            self.assertEqual(source_report.main(), 3)

    def test_main_returns_zero_on_success(self):
        with mock.patch.object(subprocess, "run", side_effect=fake_run([0, 0])):
            self.assertEqual(source_report.main(), 0)

    def test_main_returns_one_when_a_command_cannot_start(self):
        def run(command, check=False, **kwargs):
            raise FileNotFoundError("python3")
        with mock.patch.object(subprocess, "run", side_effect=run):
            self.assertEqual(source_report.main(), 1)

    def test_main_returns_one_on_packet_failure_without_executing(self):
        with mock.patch.object(subprocess, "run", side_effect=fake_run([1])):
            self.assertEqual(source_report.main(), 1)

    def test_error_messages_do_not_echo_the_head_value(self):
        secret = "do-not-print-this"

        def run(command, check=False, **kwargs):
            self.assertNotIn(secret, " ".join(command))
            raise FileNotFoundError(secret)
        with mock.patch.object(subprocess, "run", side_effect=run) as seen:
            with self.assertRaises(source_report.SourceReportError) as caught:
                source_report.record()
        self.assertNotIn(secret, str(caught.exception))
        seen.assert_called_once()

    def test_failure_to_start_never_touches_the_network_or_files(self):
        # The module only spawns children; with subprocess guarded, no
        # evidence file may appear. Run from an empty scratch cwd.
        def run(command, check=False, **kwargs):
            raise FileNotFoundError("python3")
        with tempfile.TemporaryDirectory() as scratch:
            previous = os.getcwd()
            os.chdir(scratch)
            try:
                with mock.patch.object(subprocess, "run", side_effect=run):
                    with self.assertRaises(source_report.SourceReportError):
                        source_report.record()
                self.assertFalse(Path("qualification-evidence").exists())
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
