"""Synthetic local-record tests only; not watchdog or runtime recovery evidence."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("stock_attempt", ROOT / "attempt.py")
attempt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(attempt)
PACKAGE = "sha256:" + "a" * 64
OBSERVATION = "sha256:" + "b" * 64
NONCE = "c" * 32


class AttemptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)

    def test_forward_watchdog_manual_recovery_share_one_resource_lock(self):
        for role in ("forward", "watchdog", "manual-recovery"):
            with self.subTest(role=role), attempt.Ownership(self.root):
                with self.assertRaises(BlockingIOError):
                    with attempt.Ownership(self.root):
                        self.fail("second owner admitted")
        # Never a per-attempt lock and never unlink the shared lock on release.
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["ownership.lock"])

    def test_separate_process_is_excluded_and_can_enter_after_release(self):
        code = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location('attempt', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
try:
    with m.Ownership(sys.argv[2]):
        pass
except BlockingIOError:
    raise SystemExit(7)
"""
        command = [sys.executable, "-I", "-c", code, str(ROOT / "attempt.py"), str(self.root)]
        with attempt.Ownership(self.root):
            blocked = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(blocked.returncode, 7, blocked.stderr)
        entered = subprocess.run(command, capture_output=True, check=False)
        self.assertEqual(entered.returncode, 0, entered.stderr)

    def test_private_resource_directory_required(self):
        self.root.chmod(0o755)
        with self.assertRaises(attempt.AttemptError):
            with attempt.Ownership(self.root):
                pass

    def test_resource_and_lock_symlinks_are_rejected(self):
        link = self.root / "alias"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            with attempt.Ownership(link):
                pass
        (self.root / "ownership.lock").symlink_to(self.root / "outside")
        with self.assertRaises(OSError):
            with attempt.Ownership(self.root):
                pass
        self.assertFalse((self.root / "outside").exists())

    def test_hardlinked_or_public_lock_is_rejected(self):
        lock = self.root / "ownership.lock"
        lock.touch(mode=0o600)
        os.link(lock, self.root / "alias")
        with self.assertRaises(attempt.AttemptError):
            with attempt.Ownership(self.root):
                pass
        (self.root / "alias").unlink()
        lock.chmod(0o644)
        with self.assertRaises(attempt.AttemptError):
            with attempt.Ownership(self.root):
                pass

    def test_lock_inode_replacement_rejects_writes(self):
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE, create=True) as current:
                (self.root / "ownership.lock").unlink()
                (self.root / "ownership.lock").touch(mode=0o600)
                with self.assertRaises(attempt.AttemptError):
                    current.publish("armed", OBSERVATION)

    def test_reopen_exact_identity_and_durable_record(self):
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE, create=True) as current:
                stored = current.publish("armed", OBSERVATION)
                self.assertEqual(stored["package_digest"], PACKAGE)
                self.assertEqual(stored["attempt_id"], NONCE)
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE) as current:
                self.assertEqual(current.read("armed"), stored)

    def test_records_cannot_be_overwritten(self):
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE, create=True) as current:
                first = current.publish("failure", OBSERVATION)
                with self.assertRaises(FileExistsError):
                    current.publish("failure", PACKAGE)
                self.assertEqual(current.read("failure"), first)
        self.assertFalse(list(self.root.rglob(".pending-*")))

    def test_attempt_nonce_cannot_be_reused(self):
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE, create=True):
                pass
            with self.assertRaises(FileExistsError):
                with owner.attempt(PACKAGE, NONCE, create=True):
                    pass

    def test_another_package_cannot_adopt_attempt(self):
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE, create=True):
                pass
            with self.assertRaises(attempt.AttemptError):
                with owner.attempt(OBSERVATION, NONCE):
                    pass

    def test_foreign_record_identity_is_rejected(self):
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE, create=True) as current:
                current.publish("armed", OBSERVATION)
                path = self.root / ("attempt-" + NONCE) / "armed.json"
                value = json.loads(path.read_text())
                value["attempt_id"] = "d" * 32
                path.write_text(json.dumps(value))
                with self.assertRaises(attempt.AttemptError):
                    current.read("armed")

    def test_symlink_receipt_is_rejected(self):
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE, create=True) as current:
                path = self.root / ("attempt-" + NONCE)
                (path / "armed.json").symlink_to(path / "identity.json")
                with self.assertRaises(OSError):
                    current.read("armed")

    def test_invalid_identity_and_paths_are_rejected(self):
        with attempt.Ownership(self.root) as owner:
            for package, nonce in (("a" * 64, NONCE), (PACKAGE, "../escape"), (PACKAGE, "a"), (None, NONCE)):
                with self.subTest(package=package, nonce=nonce), self.assertRaises(attempt.AttemptError):
                    with owner.attempt(package, nonce, create=True):
                        pass

    def test_no_record_can_claim_functional_success(self):
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE, create=True) as current:
                for kind in ("verified", "recovered", "rolledback", "../armed"):
                    with self.subTest(kind=kind), self.assertRaises(attempt.AttemptError):
                        current.publish(kind, OBSERVATION)
                with self.assertRaises(attempt.AttemptError):
                    current.publish("armed", "ready=true")

    def test_file_sync_failure_never_acknowledges_publication(self):
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE, create=True) as current:
                with mock.patch.object(attempt.os, "fsync", side_effect=OSError("injected sync failure")):
                    with self.assertRaises(OSError):
                        current.publish("armed", OBSERVATION)
                self.assertFalse((self.root / ("attempt-" + NONCE) / "armed.json").exists())

    def test_directory_sync_failure_never_acknowledges_publication(self):
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE, create=True) as current:
                with mock.patch.object(attempt, "_sync_directory", side_effect=OSError("injected directory sync")):
                    with self.assertRaises(OSError):
                        current.publish("stop-intent", OBSERVATION)
                # A visible record after a failed sync is NOT an acknowledgement.
                # Recovery/stop control must treat the exception as failure.

    def test_closed_attempt_cannot_write_through_a_reused_descriptor(self):
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE, create=True) as previous:
                pass
            with owner.attempt(PACKAGE, "d" * 32, create=True) as current:
                with self.assertRaises(attempt.AttemptError):
                    previous.publish("armed", OBSERVATION)
                current.publish("armed", OBSERVATION)

    def test_owner_cannot_publish_after_release(self):
        with attempt.Ownership(self.root) as owner:
            with owner.attempt(PACKAGE, NONCE, create=True) as current:
                current.publish("stop-intent", OBSERVATION)
        with self.assertRaises(attempt.AttemptError):
            current.publish("failure", OBSERVATION)


if __name__ == "__main__":
    unittest.main()
