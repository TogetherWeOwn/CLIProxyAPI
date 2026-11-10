"""Disposable-location controls. These verify safe allocation only, not recovery."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("disposable_locations", ROOT / "disposable_locations.py")
disposable_locations = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(disposable_locations)


class DisposableLocationsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.env_file = self.base / "github-env.txt"
        self.env_file.write_bytes(b"EXISTING=1\n")

    def env(self, **overrides):
        values = {
            "RUNNER_TEMP": str(self.base),
            "GITHUB_RUN_ID": "42888246984",
            "GITHUB_RUN_ATTEMPT": "1",
        }
        values.update(overrides)
        return values

    def test_builds_expected_paths_for_valid_env(self):
        download, root = disposable_locations.build_locations(self.env())
        self.assertEqual(download, self.base / "stock-runtime-42888246984-1")
        self.assertEqual(root, self.base / "stock-root-42888246984-1")

    def test_run_and_attempt_appear_in_names(self):
        download, root = disposable_locations.build_locations(
            self.env(GITHUB_RUN_ID="7", GITHUB_RUN_ATTEMPT="3"))
        self.assertEqual(download.name, "stock-runtime-7-3")
        self.assertEqual(root.name, "stock-root-7-3")

    def test_download_and_root_differ(self):
        download, root = disposable_locations.build_locations(self.env())
        self.assertNotEqual(download, root)

    def test_trailing_slash_base_is_normalized(self):
        download, root = disposable_locations.build_locations(
            self.env(RUNNER_TEMP=str(self.base) + "/"))
        self.assertEqual(download, self.base / "stock-runtime-42888246984-1")
        self.assertEqual(root, self.base / "stock-root-42888246984-1")

    def test_missing_runner_temp_fails_closed(self):
        values = self.env()
        del values["RUNNER_TEMP"]
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "missing"):
            disposable_locations.build_locations(values)

    def test_empty_runner_temp_fails_closed(self):
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "missing"):
            disposable_locations.build_locations(self.env(RUNNER_TEMP=""))

    def test_relative_runner_temp_fails_closed(self):
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "absolute"):
            disposable_locations.build_locations(self.env(RUNNER_TEMP="runner-temp"))

    def test_filesystem_root_base_fails_closed(self):
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "too shallow"):
            disposable_locations.build_locations(self.env(RUNNER_TEMP="/"))

    def test_two_part_base_yields_cleanup_satisfying_children(self):
        # /tmp itself is too shallow as a cleanup *target*, but as a base it
        # yields children of exactly the depth the cleanup rule accepts.
        download, root = disposable_locations.build_locations(self.env(RUNNER_TEMP="/tmp"))
        self.assertEqual(download, Path("/tmp/stock-runtime-42888246984-1"))
        self.assertEqual(root, Path("/tmp/stock-root-42888246984-1"))
        self.assertGreaterEqual(len(download.parts), 3)
        self.assertGreaterEqual(len(root.parts), 3)

    def test_malformed_runner_temp_fails_closed(self):
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "malformed"):
            disposable_locations.build_locations(self.env(RUNNER_TEMP=" " + str(self.base)))

    def test_control_char_runner_temp_fails_closed(self):
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "malformed"):
            disposable_locations.build_locations(self.env(RUNNER_TEMP=str(self.base) + "\nINJECTED=1"))

    def test_nonexistent_runner_temp_fails_closed(self):
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "not a directory"):
            disposable_locations.build_locations(self.env(RUNNER_TEMP=str(self.base / "missing")))

    def test_file_runner_temp_fails_closed(self):
        target = self.base / "file.txt"
        target.write_bytes(b"keep")
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "not a directory"):
            disposable_locations.build_locations(self.env(RUNNER_TEMP=str(target)))

    def test_symlinked_runner_temp_fails_closed(self):
        link = self.base / "link"
        link.symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "symlink"):
            disposable_locations.build_locations(self.env(RUNNER_TEMP=str(link)))

    def test_missing_run_id_fails_closed(self):
        values = self.env()
        del values["GITHUB_RUN_ID"]
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "missing"):
            disposable_locations.build_locations(values)

    def test_non_numeric_run_id_fails_closed(self):
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "malformed"):
            disposable_locations.build_locations(self.env(GITHUB_RUN_ID="42;rm -r /"))

    def test_missing_run_attempt_fails_closed(self):
        values = self.env()
        del values["GITHUB_RUN_ATTEMPT"]
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "missing"):
            disposable_locations.build_locations(values)

    def test_non_numeric_run_attempt_fails_closed(self):
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "malformed"):
            disposable_locations.build_locations(self.env(GITHUB_RUN_ATTEMPT="abc"))

    def test_oversized_run_id_fails_closed(self):
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "oversized"):
            disposable_locations.build_locations(self.env(GITHUB_RUN_ID="1" * 33))

    def test_write_env_file_appends_two_lines_preserving_existing(self):
        download, root = disposable_locations.build_locations(self.env())
        lines = disposable_locations.write_env_file(
            self.env(GITHUB_ENV=str(self.env_file)), download, root)
        expected = "DOWNLOAD=%s\nROOT=%s\n" % (download, root)
        self.assertEqual(lines, expected)
        self.assertEqual(
            self.env_file.read_bytes(), b"EXISTING=1\n" + expected.encode("utf-8"))

    def test_write_env_file_creates_missing_file(self):
        missing = self.base / "new-env.txt"
        download, root = disposable_locations.build_locations(self.env())
        lines = disposable_locations.write_env_file(
            self.env(GITHUB_ENV=str(missing)), download, root)
        self.assertEqual(missing.read_bytes(), lines.encode("utf-8"))

    def test_missing_github_env_fails_closed(self):
        download, root = disposable_locations.build_locations(self.env())
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "missing"):
            disposable_locations.write_env_file(self.env(), download, root)

    def test_relative_github_env_fails_closed(self):
        download, root = disposable_locations.build_locations(self.env())
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "absolute"):
            disposable_locations.write_env_file(
                self.env(GITHUB_ENV="github-env.txt"), download, root)

    def test_symlinked_github_env_fails_closed(self):
        link = self.base / "env-link"
        link.symlink_to(self.env_file)
        download, root = disposable_locations.build_locations(self.env())
        with self.assertRaisesRegex(disposable_locations.DisposableLocationsError, "symlink"):
            disposable_locations.write_env_file(
                self.env(GITHUB_ENV=str(link)), download, root)
        self.assertEqual(self.env_file.read_bytes(), b"EXISTING=1\n")

    def test_main_writes_env_file_and_returns_zero(self):
        env = self.env(GITHUB_ENV=str(self.env_file))
        download, root = disposable_locations.build_locations(env)
        import os
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(disposable_locations.main([]), 0)
        expected = "DOWNLOAD=%s\nROOT=%s\n" % (download, root)
        self.assertEqual(
            self.env_file.read_bytes(), b"EXISTING=1\n" + expected.encode("utf-8"))

    def test_main_returns_one_without_echoing_secret_value(self):
        import io
        import os
        import sys
        sentinel = "SENTINEL_SECRET_VALUE"
        env = self.env(RUNNER_TEMP=sentinel, GITHUB_ENV=str(self.env_file))
        stderr = io.StringIO()
        original = sys.stderr
        sys.stderr = stderr
        try:
            with unittest.mock.patch.dict(os.environ, env, clear=True):
                code = disposable_locations.main([])
        finally:
            sys.stderr = original
        self.assertEqual(code, 1)
        self.assertNotIn(sentinel, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
