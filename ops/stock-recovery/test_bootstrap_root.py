"""Bootstrap-root controls. These verify root topology only, not recovery."""

import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("bootstrap_root", ROOT / "bootstrap_root.py")
bootstrap_root = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap_root)


def make_runtime(base):
    runtime = base / "runtime"
    runtime.mkdir(mode=0o700)
    (runtime / "CLIProxyAPI").write_bytes(b"synthetic-binary")
    libs = runtime / "libs"
    for name in bootstrap_root.FROZEN_LIBS:
        target = libs / name
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        target.write_bytes(("synthetic-" + name).encode("utf-8"))
    return runtime


class BootstrapRootTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.runtime = make_runtime(self.base)
        self.root = self.base / "root"

    def prepare(self):
        return bootstrap_root.prepare_root(self.runtime, self.root)

    def test_complete_root_installs_binary_and_loader_set(self):
        result = self.prepare()
        self.assertEqual(result["qualification"], "HOLD")
        self.assertEqual(result["service_recovery"], "NOT_TESTED")
        self.assertEqual(result["binary_digest"], bootstrap_root.digest(b"synthetic-binary"))
        self.assertEqual((self.root / "CLIProxyAPI").read_bytes(), b"synthetic-binary")
        for name in bootstrap_root.FROZEN_LIBS:
            published = self.root / name
            self.assertTrue(published.is_file())
            self.assertEqual(published.read_bytes(), ("synthetic-" + name).encode("utf-8"))
            self.assertEqual(result["libs"][name], bootstrap_root.digest(published.read_bytes()))
        self.assertFalse((self.root / "etc/ld.so.cache").is_symlink())

    def test_merged_usr_topology_resolves_loader_interp(self):
        self.prepare()
        self.assertEqual(os.readlink(self.root / "lib"), "usr/lib")
        self.assertEqual(os.readlink(self.root / "lib64"), "usr/lib64")
        loader = self.root / "lib64" / bootstrap_root.LOADER_NAME
        self.assertTrue(loader.is_symlink())
        self.assertEqual(os.readlink(self.root / "usr/lib64" / bootstrap_root.LOADER_NAME),
                         "/lib/x86_64-linux-gnu/" + bootstrap_root.LOADER_NAME)
        # The absolute loader link resolves only under chroot; emulate the
        # chroot lookup relative to the root for the content check.
        frozen = self.root / "usr/lib/x86_64-linux-gnu" / bootstrap_root.LOADER_NAME
        self.assertEqual(frozen.read_bytes(),
                         b"synthetic-usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")

    def test_modes_are_exact(self):
        self.prepare()
        mode = lambda path: stat.S_IMODE(path.stat().st_mode)
        self.assertEqual(mode(self.root), 0o755)
        self.assertEqual(mode(self.root / "CLIProxyAPI"), 0o755)
        self.assertEqual(mode(self.root / "etc/ld.so.cache"), 0o644)
        self.assertEqual(mode(self.root / "usr/lib/x86_64-linux-gnu/libc.so.6"), 0o755)

    def test_existing_root_is_not_overwritten(self):
        self.root.mkdir()
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"keep")
        with self.assertRaisesRegex(bootstrap_root.BootstrapRootError, "already exists"):
            self.prepare()
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_missing_binary_fails_closed_before_creating_root(self):
        (self.runtime / "CLIProxyAPI").unlink()
        with self.assertRaisesRegex(bootstrap_root.BootstrapRootError, "missing"):
            self.prepare()
        self.assertFalse(self.root.exists())

    def test_missing_lib_fails_closed_before_creating_root(self):
        (self.runtime / "libs/usr/lib/x86_64-linux-gnu/libc.so.6").unlink()
        with self.assertRaisesRegex(bootstrap_root.BootstrapRootError, "missing"):
            self.prepare()
        self.assertFalse(self.root.exists())

    def test_missing_loader_cache_fails_closed_before_creating_root(self):
        (self.runtime / "libs/etc/ld.so.cache").unlink()
        with self.assertRaisesRegex(bootstrap_root.BootstrapRootError, "missing"):
            self.prepare()
        self.assertFalse(self.root.exists())

    def test_symlinked_source_fails_closed(self):
        (self.runtime / "CLIProxyAPI").unlink()
        outside = self.base / "outside"
        outside.write_bytes(b"synthetic-binary")
        (self.runtime / "CLIProxyAPI").symlink_to(outside)
        with self.assertRaisesRegex(bootstrap_root.BootstrapRootError, "symlink"):
            self.prepare()
        self.assertFalse(self.root.exists())

    def test_symlinked_lib_fails_closed(self):
        lib = self.runtime / "libs/usr/lib/x86_64-linux-gnu/libc.so.6"
        lib.unlink()
        outside = self.base / "outside-lib"
        outside.write_bytes(b"synthetic-lib")
        lib.symlink_to(outside)
        with self.assertRaisesRegex(bootstrap_root.BootstrapRootError, "symlink"):
            self.prepare()
        self.assertFalse(self.root.exists())

    def test_empty_binary_fails_closed(self):
        (self.runtime / "CLIProxyAPI").write_bytes(b"")
        with self.assertRaisesRegex(bootstrap_root.BootstrapRootError, "size out of bounds"):
            self.prepare()
        self.assertFalse(self.root.exists())

    def test_oversized_lib_fails_closed(self):
        lib = self.runtime / "libs/usr/lib/x86_64-linux-gnu/libc.so.6"
        lib.write_bytes(b"x" * (bootstrap_root.MAX_LIB + 1))
        with self.assertRaisesRegex(bootstrap_root.BootstrapRootError, "size out of bounds"):
            self.prepare()
        self.assertFalse(self.root.exists())

    def test_nonregular_source_fails_closed(self):
        (self.runtime / "CLIProxyAPI").unlink()
        (self.runtime / "CLIProxyAPI").mkdir()
        with self.assertRaisesRegex(bootstrap_root.BootstrapRootError, "not regular"):
            self.prepare()
        self.assertFalse(self.root.exists())

    def test_runtime_dir_must_be_a_directory(self):
        with self.assertRaisesRegex(bootstrap_root.BootstrapRootError, "not a directory"):
            bootstrap_root.prepare_root(self.base / "missing", self.root)


if __name__ == "__main__":
    unittest.main()
