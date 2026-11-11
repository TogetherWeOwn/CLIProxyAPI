"""Bootstrap-smoke controls. These verify the fixed help-smoke command only."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("bootstrap_smoke", ROOT / "bootstrap_smoke.py")
bootstrap_smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap_smoke)


def fake_run(returncode=0, payload=b"CLIProxyAPI Version: v8.0.60\n"):
    """Stand in for subprocess.run without executing anything."""
    def run(command, stdout=None, stderr=None, check=False):
        stdout.write(payload)
        return subprocess.CompletedProcess(command, returncode)
    return run


class BootstrapSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "stock-root-1-1"
        self.root.mkdir()
        self.output = self.base / "help.log"

    def run_smoke(self, root=None, output=None, run=None):
        with mock.patch.object(subprocess, "run", side_effect=run or fake_run()) as seen:
            code = bootstrap_smoke.run_smoke(
                str(root or self.root), str(output or self.output))
        return code, seen

    def test_command_vector_is_the_exact_fixed_smoke(self):
        command = bootstrap_smoke.build_smoke_command(self.root)
        self.assertEqual(command, [
            "sudo", "unshare", "--net", "--pid", "--fork", "--kill-child",
            "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "chroot", "--userspec=65534:65534", str(self.root),
            "/CLIProxyAPI", "--help",
        ])

    def test_valid_root_runs_and_returns_zero(self):
        code, seen = self.run_smoke()
        self.assertEqual(code, 0)
        seen.assert_called_once()
        self.assertEqual(seen.call_args.args[0],
                         bootstrap_smoke.build_smoke_command(self.root))
        self.assertEqual(seen.call_args.kwargs["stderr"], subprocess.STDOUT)
        self.assertEqual(seen.call_args.kwargs["check"], False)

    def test_output_file_captures_child_output(self):
        self.run_smoke(run=fake_run(payload=b"Usage of /CLIProxyAPI\n"))
        self.assertEqual(self.output.read_bytes(), b"Usage of /CLIProxyAPI\n")

    def test_child_nonzero_exit_code_propagates(self):
        code, _seen = self.run_smoke(run=fake_run(returncode=127))
        self.assertEqual(code, 127)

    def test_missing_command_binary_fails_closed(self):
        def run(command, stdout=None, stderr=None, check=False):
            raise FileNotFoundError("sudo")
        with self.assertRaisesRegex(bootstrap_smoke.BootstrapSmokeError, "failed to start"):
            self.run_smoke(run=run)

    def test_relative_root_fails_closed(self):
        with self.assertRaisesRegex(bootstrap_smoke.BootstrapSmokeError, "must be absolute"):
            bootstrap_smoke.run_smoke("stock-root-1-1", str(self.output))

    def test_empty_root_fails_closed(self):
        with self.assertRaisesRegex(bootstrap_smoke.BootstrapSmokeError, "empty"):
            bootstrap_smoke.run_smoke("", str(self.output))

    def test_missing_root_fails_closed(self):
        with self.assertRaisesRegex(bootstrap_smoke.BootstrapSmokeError, "not a directory"):
            bootstrap_smoke.run_smoke(str(self.base / "missing"), str(self.output))

    def test_root_regular_file_fails_closed(self):
        regular = self.base / "regular"
        regular.write_bytes(b"not a directory")
        with self.assertRaisesRegex(bootstrap_smoke.BootstrapSmokeError, "not a directory"):
            bootstrap_smoke.run_smoke(str(regular), str(self.output))

    def test_symlinked_root_fails_closed(self):
        link = self.base / "linked-root"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(bootstrap_smoke.BootstrapSmokeError, "symlink"):
            bootstrap_smoke.run_smoke(str(link), str(self.output))

    def test_filesystem_root_fails_closed(self):
        with self.assertRaisesRegex(bootstrap_smoke.BootstrapSmokeError, "too shallow"):
            bootstrap_smoke.run_smoke("/", str(self.output))

    def test_single_level_root_fails_closed(self):
        with self.assertRaisesRegex(bootstrap_smoke.BootstrapSmokeError, "too shallow"):
            bootstrap_smoke.run_smoke("/tmp", str(self.output))

    def test_symlinked_output_fails_closed_and_preserves_target(self):
        target = self.base / "target.log"
        target.write_bytes(b"PRESERVE")
        link = self.base / "help.log"
        link.symlink_to(target)
        with self.assertRaisesRegex(bootstrap_smoke.BootstrapSmokeError, "symlink"):
            bootstrap_smoke.run_smoke(str(self.root), str(link))
        self.assertEqual(target.read_bytes(), b"PRESERVE")

    def test_output_directory_fails_closed(self):
        with self.assertRaisesRegex(bootstrap_smoke.BootstrapSmokeError, "is a directory"):
            bootstrap_smoke.run_smoke(str(self.root), str(self.root))

    def test_missing_output_directory_fails_closed(self):
        with self.assertRaisesRegex(bootstrap_smoke.BootstrapSmokeError, "not a directory"):
            bootstrap_smoke.run_smoke(str(self.root), str(self.base / "missing" / "help.log"))

    def test_failed_start_never_touches_subprocess_for_bad_root(self):
        with mock.patch.object(subprocess, "run") as seen:
            with self.assertRaises(bootstrap_smoke.BootstrapSmokeError):
                bootstrap_smoke.run_smoke("/missing", str(self.output))
        seen.assert_not_called()

    def test_main_returns_child_code(self):
        with mock.patch.object(subprocess, "run", side_effect=fake_run(returncode=42)):
            code = bootstrap_smoke.main([str(self.root), str(self.output)])
        self.assertEqual(code, 42)

    def test_main_returns_one_on_validation_failure(self):
        with mock.patch.object(subprocess, "run") as seen:
            code = bootstrap_smoke.main(["/missing", str(self.output)])
        self.assertEqual(code, 1)
        seen.assert_not_called()

    def test_main_returns_one_when_command_cannot_start(self):
        def run(command, stdout=None, stderr=None, check=False):
            raise FileNotFoundError("unshare")
        with mock.patch.object(subprocess, "run", side_effect=run):
            code = bootstrap_smoke.main([str(self.root), str(self.output)])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
