"""Disposable-cleanup controls. These verify safe removal only, not recovery."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("disposable_cleanup", ROOT / "disposable_cleanup.py")
disposable_cleanup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(disposable_cleanup)


class DisposableCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def make_dir(self, name="root"):
        target = self.base / name
        nested = target / "a" / "b"
        nested.mkdir(parents=True)
        (target / "file.txt").write_bytes(b"synthetic")
        (nested / "leaf.txt").write_bytes(b"synthetic")
        return target

    def test_removes_nested_directory_tree(self):
        target = self.make_dir()
        outcome = disposable_cleanup.remove_disposable(str(target))
        self.assertEqual(outcome, "removed")
        self.assertFalse(os.path.lexists(target))

    def test_removes_empty_directory(self):
        target = self.base / "empty"
        target.mkdir()
        self.assertEqual(disposable_cleanup.remove_disposable(str(target)), "removed")
        self.assertFalse(os.path.lexists(target))

    def test_missing_path_is_idempotent_noop(self):
        missing = self.base / "missing"
        self.assertEqual(disposable_cleanup.remove_disposable(str(missing)), "absent")

    def test_missing_parent_still_reports_absent(self):
        nested = self.base / "no-parent" / "child"
        self.assertEqual(disposable_cleanup.remove_disposable(str(nested)), "absent")

    def test_symlinked_path_fails_closed_and_preserves_target(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_bytes(b"keep")
        link = self.base / "link"
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(disposable_cleanup.DisposableCleanupError, "symlink"):
            disposable_cleanup.remove_disposable(str(link))
        self.assertTrue(os.path.lexists(link))
        self.assertEqual((outside / "keep.txt").read_bytes(), b"keep")

    def test_regular_file_fails_closed_and_preserves_file(self):
        target = self.base / "file.txt"
        target.write_bytes(b"keep")
        with self.assertRaisesRegex(disposable_cleanup.DisposableCleanupError, "not a directory"):
            disposable_cleanup.remove_disposable(str(target))
        self.assertEqual(target.read_bytes(), b"keep")

    def test_empty_path_fails_closed(self):
        with self.assertRaisesRegex(disposable_cleanup.DisposableCleanupError, "empty"):
            disposable_cleanup.remove_disposable("")

    def test_relative_path_fails_closed(self):
        with self.assertRaisesRegex(disposable_cleanup.DisposableCleanupError, "absolute"):
            disposable_cleanup.remove_disposable("stock-root")

    def test_filesystem_root_fails_closed(self):
        with self.assertRaisesRegex(disposable_cleanup.DisposableCleanupError, "too shallow"):
            disposable_cleanup.remove_disposable("/")

    def test_single_level_system_path_fails_closed(self):
        with self.assertRaisesRegex(disposable_cleanup.DisposableCleanupError, "too shallow"):
            disposable_cleanup.remove_disposable("/tmp")

    def test_inner_symlink_is_removed_as_link_not_followed(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_bytes(b"keep")
        target = self.make_dir()
        inner = target / "inner-link"
        inner.symlink_to(outside, target_is_directory=True)
        self.assertEqual(disposable_cleanup.remove_disposable(str(target)), "removed")
        self.assertFalse(os.path.lexists(target))
        self.assertEqual((outside / "keep.txt").read_bytes(), b"keep")

    def test_trailing_slash_directory_is_removed(self):
        target = self.make_dir()
        self.assertEqual(disposable_cleanup.remove_disposable(str(target) + "/"), "removed")
        self.assertFalse(os.path.lexists(target))

    def test_multiple_paths_reports_removed_and_absent(self):
        target = self.make_dir()
        missing = self.base / "absent"
        result = disposable_cleanup.remove_disposables([str(target), str(missing)])
        self.assertEqual(result["removed"], [str(target)])
        self.assertEqual(result["absent"], [str(missing)])
        self.assertEqual(result["qualification"], "HOLD")
        self.assertEqual(result["service_recovery"], "NOT_TESTED")
        self.assertFalse(os.path.lexists(target))

    def test_no_paths_fails_closed(self):
        with self.assertRaisesRegex(disposable_cleanup.DisposableCleanupError, "no disposable paths"):
            disposable_cleanup.remove_disposables([])

    def test_main_returns_zero_on_success(self):
        target = self.make_dir()
        self.assertEqual(disposable_cleanup.main([str(target)]), 0)
        self.assertFalse(os.path.lexists(target))

    def test_main_returns_one_on_symlink(self):
        outside = self.base / "outside2"
        outside.mkdir()
        link = self.base / "link2"
        link.symlink_to(outside, target_is_directory=True)
        self.assertEqual(disposable_cleanup.main([str(link)]), 1)
        self.assertTrue(os.path.lexists(link))


if __name__ == "__main__":
    unittest.main()
