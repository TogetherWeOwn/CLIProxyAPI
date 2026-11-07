import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from host_recovery.collection import FileCapture
from host_recovery.durable import Rejected, digest, directory, read_file


class FileCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "synthetic-log"
        self.source.write_bytes(b"first\n")
        self.source.chmod(0o600)
        self.spool = self.root / "private-spool"
        self.spool.mkdir(mode=0o700)

    def capture(self, **kwargs):
        args = dict(source_id="stdout-mirror", path=str(self.source), uid=os.geteuid(), gid=os.getegid(), mode=0o600)
        args.update(kwargs)
        return FileCapture(**args)

    def test_handle_identity_offsets_hash_and_private_raw_artifact(self):
        with self.capture() as capture, directory(str(self.spool), private=True) as spool:
            receipt = capture.snapshot(spool)
            raw, st = read_file(spool, receipt["raw_handle"])
            source = self.source.stat()
            self.assertEqual(raw, b"first\n")
            self.assertEqual(receipt["raw_sha256"], digest(raw))
            self.assertEqual((receipt["device"], receipt["inode"]), (source.st_dev, source.st_ino))
            self.assertEqual(receipt["start_offset"], 0)
            self.assertEqual(receipt["end_offset"], len(raw))
            self.assertEqual(st.st_mode & 0o777, 0o600)
            self.assertNotIn("path", receipt)
            self.assertEqual(receipt["coverage"], "prefix_only")
            self.assertFalse(receipt["producer_drained"])

    def test_snapshot_appends_preserve_prefix_and_previous_raw_artifacts(self):
        with self.capture() as capture, directory(str(self.spool), private=True) as spool:
            first = capture.snapshot(spool)
            with self.source.open("ab") as stream:
                stream.write(b"second\n")
            second = capture.snapshot(spool)
            self.assertNotEqual(first["raw_handle"], second["raw_handle"])
            self.assertEqual(read_file(spool, first["raw_handle"])[0], b"first\n")
            self.assertEqual(read_file(spool, second["raw_handle"])[0], b"first\nsecond\n")
            self.assertEqual(second["previous_end_offset"], 6)
            self.assertFalse(second["producer_drained"])

    def test_repeated_empty_reads_and_eof_never_mean_drained(self):
        self.source.write_bytes(b"")
        with self.capture() as capture, directory(str(self.spool), private=True) as spool:
            for _ in range(3):
                value = capture.snapshot(spool)
                self.assertTrue(value["empty"])
                self.assertEqual(value["raw_sha256"], digest(b""))
                self.assertEqual(value["end_offset"], 0)
                self.assertFalse(value["producer_drained"])
        self.assertEqual(len(list(self.spool.iterdir())), 3)

    def test_rotation_with_open_handle_fails_and_cannot_recover_coverage(self):
        with self.capture() as capture, directory(str(self.spool), private=True) as spool:
            capture.snapshot(spool)
            self.source.rename(self.root / "rotated")
            self.source.write_bytes(b"replacement\n")
            self.source.chmod(0o600)
            with self.assertRaises(Rejected):
                capture.snapshot(spool)
            self.source.unlink()
            (self.root / "rotated").rename(self.source)
            with self.assertRaisesRegex(Rejected, "handle-unavailable"):
                capture.snapshot(spool)

    def test_truncation_and_same_length_rewrite_fail(self):
        for replacement in (b"", b"OTHER\n", b"other\nlonger\n"):
            with self.subTest(replacement=replacement):
                self.source.write_bytes(b"first\n")
                with self.capture() as capture, directory(str(self.spool), private=True) as spool:
                    capture.snapshot(spool)
                    self.source.write_bytes(replacement)
                    with self.assertRaises(Rejected):
                        capture.snapshot(spool)

    def test_change_during_read_fails(self):
        original = os.read
        changed = False
        with self.capture() as capture, directory(str(self.spool), private=True) as spool:
            def read(fd, count):
                nonlocal changed
                block = original(fd, count)
                if fd == capture.fd and not changed:
                    with self.source.open("ab") as stream:
                        stream.write(b"late\n")
                    changed = True
                return block
            with patch("host_recovery.collection.os.read", side_effect=read), self.assertRaises(Rejected):
                capture.snapshot(spool)

    def test_missing_source_never_becomes_empty_coverage(self):
        self.source.unlink()
        with self.assertRaises(Rejected):
            with self.capture():
                self.fail("opened missing source")
        self.assertEqual(list(self.spool.iterdir()), [])

    def test_unreadable_source_and_read_errors_fail_closed(self):
        with patch("host_recovery.collection.os.open", side_effect=PermissionError()), self.assertRaises(Rejected):
            with self.capture():
                self.fail("opened unreadable source")
        with self.capture() as capture, directory(str(self.spool), private=True) as spool:
            with patch("host_recovery.collection.os.read", side_effect=OSError(errno.EIO, "restricted text")):
                with self.assertRaisesRegex(Rejected, "^collection-snapshot-failed$"):
                    capture.snapshot(spool)
            with self.assertRaisesRegex(Rejected, "handle-unavailable"):
                capture.snapshot(spool)

    def test_symlink_hardlink_fifo_and_changed_metadata_fail(self):
        for variant in ("symlink", "hardlink", "fifo", "mode"):
            with self.subTest(variant=variant):
                self.source.unlink(missing_ok=True)
                if variant == "symlink":
                    self.source.symlink_to(self.root / "absent")
                elif variant == "hardlink":
                    self.source.write_bytes(b"x")
                    os.link(self.source, self.root / "other-link")
                elif variant == "fifo":
                    os.mkfifo(self.source, 0o600)
                else:
                    self.source.write_bytes(b"x")
                    self.source.chmod(0o644)
                with self.assertRaises(Rejected):
                    with self.capture():
                        self.fail("opened unsupported source")

    def test_loss_after_open_and_metadata_change_are_not_empty(self):
        for variant in ("unlink", "mode"):
            self.source.write_bytes(b"first\n")
            self.source.chmod(0o600)
            with self.subTest(variant=variant), self.capture() as capture, directory(str(self.spool), private=True) as spool:
                if variant == "unlink":
                    self.source.unlink()
                else:
                    self.source.chmod(0o644)
                with self.assertRaises(Rejected):
                    capture.snapshot(spool)

    def test_source_overflow_fails_before_receipt(self):
        with self.source.open("r+b") as stream:
            stream.truncate(4 * 1024 * 1024 + 1)
        with self.capture() as capture, directory(str(self.spool), private=True) as spool:
            with self.assertRaises(Rejected):
                capture.snapshot(spool)
        self.assertEqual(list(self.spool.iterdir()), [])

    def test_all_persistence_faults_poison_capture_without_acknowledgment(self):
        for failure in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
            for code in (errno.EIO, errno.ENOSPC):
                with self.subTest(failure=failure, code=code):
                    with self.capture() as capture, directory(str(self.spool), private=True) as spool:
                        def fault(stage):
                            if stage == failure:
                                raise OSError(code, "restricted text")
                        with self.assertRaisesRegex(Rejected, "^collection-snapshot-failed$"):
                            capture.snapshot(spool, fault=fault)
                        with self.assertRaisesRegex(Rejected, "handle-unavailable"):
                            capture.snapshot(spool)

    def test_unrestricted_spool_is_refused(self):
        self.spool.chmod(0o755)
        with self.capture() as capture, directory(str(self.spool)) as spool:
            with self.assertRaises(Rejected):
                capture.snapshot(spool)

    def test_path_identity_mode_and_closed_handle_contracts(self):
        for kwargs in ({"source_id": "../bad"}, {"path": "relative"}, {"uid": True},
                       {"gid": -1}, {"mode": 0o666}):
            with self.subTest(kwargs=kwargs), self.assertRaises(Rejected):
                self.capture(**kwargs)
        capture = self.capture()
        with self.assertRaises(Rejected):
            capture.snapshot(0)
        with capture:
            with self.assertRaises(Rejected):
                capture.__enter__()
        with self.assertRaises(Rejected):
            capture.__enter__()
