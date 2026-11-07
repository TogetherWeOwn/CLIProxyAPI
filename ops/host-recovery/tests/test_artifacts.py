"""Synthetic ZIP/installed bytes; no actual plugin loading or host-service proof."""
from dataclasses import replace
import errno
import io
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

from fixture_home import fixture_home

from host_recovery import artifacts, durable, input_gate
import test_input_gate
from test_installation import approve
from test_recovery_state import intent


def package(entries, compression=zipfile.ZIP_DEFLATED, comment=b""):
    raw = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # Intentional duplicate-entry negative.
        with zipfile.ZipFile(raw, "w", compression=compression) as archive:
            archive.comment = comment
            for name, content in entries:
                archive.writestr(name, content)
    return raw.getvalue()


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".recovery-artifact-test-", dir=fixture_home())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.archive_root, self.library_root = self.root / "archives", self.root / "installed"
        self.archive_root.mkdir(mode=0o700)
        self.library_root.mkdir(mode=0o700)
        self.archive, self.library = self.archive_root / "package.zip", self.library_root / "meta.so"
        self.library_bytes = b"synthetic-not-an-executable-library\x00" * 5000
        self.library.write_bytes(self.library_bytes)
        self.library.chmod(0o700)
        self.archive.write_bytes(package((("lib/meta.so", self.library_bytes), ("manifest.json", b"{}"))))
        self.archive.chmod(0o600)
        self.value, self.time, self.boundary_ok, self.checks = intent(), 1000.0, True, 0
        self.configure()

    def configure(self):
        self.approval = artifacts.PluginArtifactApproval(durable.digest(durable.canonical(self.value)),
            durable.digest(self.archive.read_bytes()), durable.digest(self.library.read_bytes()),
            approve(self.archive_root), approve(self.library_root), self.archive.name, self.library.name,
            "lib/meta.so", os.geteuid(), os.getegid())
        self.gate = artifacts.PluginArtifactGate(approval=self.approval, check=self.check, clock=lambda: self.time)

    def check(self):
        self.checks += 1
        return self.boundary_ok

    def verify(self):
        return self.gate.verify(self.value, deadline=self.time + 10)

    def refused(self):
        with self.assertRaisesRegex(durable.Rejected, "^artifact-check-unconfirmed$"):
            self.verify()

    def repin_archive(self, raw):
        self.archive.write_bytes(raw)
        self.configure()

    def test_dual_pins_and_member_bytes_match_without_loading_or_writing(self):
        before = {p: (durable.signature(p.stat()), p.read_bytes()) for p in (self.archive, self.library)}
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("no-execution")):
            self.assertIs(self.verify(), True)
        self.assertGreater(self.checks, 10)
        after = {p: (durable.signature(p.stat()), p.read_bytes()) for p in before}
        self.assertEqual(before, after)
        self.assertEqual(sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*")),
                         ["archives", "archives/package.zip", "installed", "installed/meta.so"])

    def test_stored_archive_is_supported(self):
        self.repin_archive(package((("lib/meta.so", self.library_bytes),), compression=zipfile.ZIP_STORED))
        self.assertTrue(self.verify())

    def test_archive_and_library_pins_are_both_mandatory(self):
        for field in ("archive_sha256", "library_sha256", "intent_sha256"):
            with self.subTest(field=field):
                self.gate.approval = replace(self.approval, **{field: "f" * 64})
                self.refused()
        self.gate.approval = self.approval
        self.value["attempt_id"] = "other-attempt"
        self.refused()

    def test_individually_valid_pins_do_not_prove_archive_member_correspondence(self):
        # Both supplied file hashes match, but the archived member is different.
        other = b"x" * len(self.library_bytes)
        self.repin_archive(package((("lib/meta.so", other),)))
        self.refused()

    def test_missing_wrong_and_wrong_size_members_refuse(self):
        for entries in ((("other.so", self.library_bytes),), (("lib/meta.so", b"short"),)):
            with self.subTest(entries=entries[0][0]):
                self.repin_archive(package(entries))
                self.refused()

    def test_duplicate_unsafe_null_backslash_and_directory_entries_refuse(self):
        unsafe = ("../escape", "/absolute", "lib/../escape", "lib//meta.so", "bad\\name", "folder/")
        for name in unsafe:
            with self.subTest(name=name):
                self.repin_archive(package((("lib/meta.so", self.library_bytes), (name, b"secret-content"))))
                self.refused()
        self.repin_archive(package((("lib/meta.so", self.library_bytes), ("lib/meta.so", self.library_bytes))))
        self.refused()
        raw = package((("lib/meta.so", self.library_bytes), ("badXname", b"secret-content")))
        self.repin_archive(raw.replace(b"badXname", b"bad\x00name"))
        self.refused()

    def test_special_and_writable_archive_entries_refuse(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600, stat.S_IFDIR | 0o700,
                     stat.S_IFREG | 0o666, stat.S_IFREG | 0o4755):
            with self.subTest(mode=mode):
                entry = zipfile.ZipInfo("lib/meta.so")
                entry.external_attr = mode << 16
                self.repin_archive(package(((entry, self.library_bytes),)))
                self.refused()

    def test_encryption_flags_extra_and_unsupported_compression_refuse(self):
        raw = bytearray(self.archive.read_bytes())
        offset = raw.index(b"PK\x01\x02")
        raw[offset + 8] |= 1
        self.repin_archive(raw)
        self.refused()
        entry = zipfile.ZipInfo("lib/meta.so")
        entry.extra = b"\xfe\xca\x00\x00"
        self.repin_archive(package(((entry, self.library_bytes),)))
        self.refused()
        self.repin_archive(package((("lib/meta.so", self.library_bytes),), compression=zipfile.ZIP_BZIP2))
        self.refused()

    def test_archive_comment_prefix_trailing_and_multidisk_refuse(self):
        original = self.archive.read_bytes()
        variants = [package((("lib/meta.so", self.library_bytes),), comment=b"secret-comment"),
                    b"prefix" + original, original + b"tail", b"not-a-zip"]
        raw = bytearray(original)
        struct.pack_into("<H", raw, len(raw) - 18, 1)  # EOCD disk number.
        variants.append(raw)
        for raw in variants:
            with self.subTest(size=len(raw)):
                self.repin_archive(raw)
                self.refused()

    def test_zip64_locator_is_refused_before_zip_parser(self):
        raw = bytearray(self.archive.read_bytes())
        raw[-42:-38] = b"PK\x06\x07"
        self.repin_archive(raw)
        reached = []
        original = artifacts._File.read_at
        def read(source, offset, count):
            if count == 22:
                reached.append("end-record-read")
            return original(source, offset, count)
        with mock.patch.object(artifacts._File, "read_at", read), mock.patch.object(
                artifacts.zipfile, "ZipFile", side_effect=AssertionError("parser-must-not-run")) as parser:
            self.refused()
            self.assertEqual(parser.call_count, 0)
        self.assertEqual(reached, ["end-record-read"])

    def test_crc_corruption_refuses_even_when_full_archive_pin_matches(self):
        raw = bytearray(package((("lib/meta.so", self.library_bytes),), compression=zipfile.ZIP_STORED))
        at = raw.index(self.library_bytes)
        raw[at] ^= 1
        self.repin_archive(raw)
        self.refused()

    def test_archive_library_member_count_directory_and_expansion_limits(self):
        for constant, limit in (("MAX_ARCHIVE", self.archive.stat().st_size - 1),
                                ("MAX_LIBRARY", self.library.stat().st_size - 1),
                                ("MAX_MEMBERS", 1), ("MAX_DIRECTORY", 1)):
            with self.subTest(limit=constant), mock.patch.object(artifacts, constant, limit):
                self.refused()
        self.repin_archive(package((("lib/meta.so", self.library_bytes), ("another", self.library_bytes))))
        with mock.patch.object(artifacts, "MAX_LIBRARY", len(self.library_bytes) + 1):
            self.refused()  # Aggregate expansion, not just individual member size.

    def test_empty_files_refuse(self):
        for path in (self.archive, self.library):
            before = path.read_bytes()
            path.write_bytes(b"")
            self.refused()
            path.write_bytes(before)

    def test_missing_symlink_hardlink_fifo_and_unsafe_file_modes_refuse(self):
        for path in (self.archive, self.library):
            saved = path.with_name("saved")
            path.rename(saved)
            self.refused()
            path.symlink_to(saved)
            self.refused()
            path.unlink()
            os.link(saved, path)
            self.refused()
            path.unlink()
            os.mkfifo(path, 0o600)
            self.refused()  # O_NONBLOCK avoids a FIFO-open wait.
            path.unlink()
            saved.rename(path)
            mode = path.stat().st_mode & 0o777
            path.chmod(0o666)
            self.refused()
            path.chmod(mode)

    def test_owner_xattr_and_root_identity_mismatch_refuse(self):
        self.gate.approval = replace(self.approval, uid=self.approval.uid, gid=self.approval.gid,
                                    archive_root=replace(self.approval.archive_root, inode=self.approval.archive_root.inode + 1))
        self.refused()
        self.gate.approval = self.approval
        with mock.patch.object(artifacts.os, "listxattr", return_value=["user.secret"]):
            self.refused()
        original = artifacts.os.fstat
        def wrong_owner(fd):
            result = original(fd)
            if stat.S_ISREG(result.st_mode):
                values = list(result)
                values[4] += 1
                return os.stat_result(values)
            return result
        with mock.patch.object(artifacts.os, "fstat", side_effect=wrong_owner):
            self.refused()

    def test_changed_bytes_cannot_reuse_a_successful_verification(self):
        self.assertTrue(self.verify())
        for path in (self.archive, self.library):
            raw = path.read_bytes()
            path.write_bytes(raw + b"changed")
            self.refused()
            path.write_bytes(raw)

    def test_path_replacement_during_verification_refuses_and_does_not_reopen(self):
        original = self.gate._member
        for path in (self.archive, self.library):
            def member(archive, size, current):
                original(archive, size, current)
                replacement = path.with_name("replacement")
                replacement.write_bytes(path.read_bytes())
                replacement.chmod(path.stat().st_mode & 0o777)
                os.replace(replacement, path)
            self.gate._member = member
            self.refused()
        self.gate._member = original

    def test_root_replacement_during_verification_refuses(self):
        original = self.gate._member
        def member(archive, size, current):
            original(archive, size, current)
            self.archive_root.rename(self.archive_root.with_name("retained"))
            self.archive_root.mkdir(mode=0o700)
        self.gate._member = member
        self.refused()

    def test_same_inode_mutation_during_verification_refuses(self):
        original, reached = self.gate._member, []
        def member(archive, size, current):
            original(archive, size, current)
            with self.library.open("r+b") as stream:
                stream.write(b"changed")
            reached.append("library-mutated")
        self.gate._member = member
        self.refused()
        self.assertEqual(reached, ["library-mutated"])

    def test_same_inode_archive_mutation_after_parse_is_refused(self):
        original, reached = self.gate._member, []
        def member(archive, size, current):
            original(archive, size, current)
            with self.archive.open("r+b") as stream:
                stream.write(b"changed")
            reached.append("archive-mutated")
        self.gate._member = member
        self.refused()
        self.assertEqual(reached, ["archive-mutated"])

    def test_readonly_protected_files_are_supported(self):
        self.archive.chmod(0o400)
        self.library.chmod(0o500)
        self.assertTrue(self.verify())

    def test_storage_faults_and_short_reads_are_fixed_code_failures(self):
        for error in (errno.EIO, errno.ENOSPC):
            with self.subTest(error=error), mock.patch.object(artifacts.os, "pread", side_effect=OSError(error, "secret-path")) as read:
                self.refused()
                self.assertEqual(read.call_count, 1)
        with mock.patch.object(artifacts.os, "pread", return_value=b"") as read:
            self.refused()
            self.assertEqual(read.call_count, 1)

    def test_inclusive_deadline_expiry_and_clock_regression_refuse(self):
        with self.assertRaisesRegex(durable.Rejected, "^artifact-check-unconfirmed$"):
            self.gate.verify(self.value, deadline=self.time)
        original = self.gate._member
        def member(archive, size, current):
            original(archive, size, current)
            self.time += 10
        self.gate._member = member
        self.refused()
        self.gate._member = original
        ticks = iter((1000.0, 999.0))
        self.gate.clock = lambda: next(ticks)
        self.refused()

    def test_boundary_revocation_and_callback_errors_refuse_without_secrets(self):
        self.boundary_ok = False
        self.refused()
        self.boundary_ok = True
        original = self.gate._member
        def member(archive, size, current):
            original(archive, size, current)
            self.boundary_ok = False
        self.gate._member = member
        self.refused()
        def fail():
            raise OSError("secret-approval-or-path")
        self.gate.check = fail
        self.refused()

    def test_invalid_approvals_and_untyped_boundaries_are_rejected(self):
        for field, value in (("archive_sha256", ""), ("library_sha256", "G" * 64),
                             ("archive_name", "../archive"), ("library_name", "."),
                             ("library_member", "../escape"), ("uid", True),
                             ("library_root", None)):
            with self.subTest(field=field), self.assertRaises(durable.Rejected):
                replace(self.approval, **{field: value})
        with self.assertRaises(durable.Rejected):
            artifacts.PluginArtifactGate(approval=None, check=self.check, clock=lambda: self.time)

    def test_failure_paths_close_all_owned_descriptors(self):
        count = lambda: len(os.listdir("/proc/self/fd"))
        before = count()
        self.assertTrue(self.verify())
        self.assertEqual(count(), before)
        with mock.patch.object(artifacts.os, "pread", side_effect=OSError(errno.EIO, "secret")):
            self.refused()
        self.assertEqual(count(), before)


class ArtifactBarrierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="recovery-artifact-input-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / "guard"
        subprocess.run(("go", "build", "-o", str(cls.binary), "./ops/host-recovery/inputguard/cmd"),
                       cwd=test_input_gate.ROOT, check=True, capture_output=True, timeout=180)

    def setUp(self):
        self.inputs = test_input_gate.InputGateTests()
        self.inputs.binary = self.binary
        self.inputs.setUp()
        self.addCleanup(self.inputs.doCleanups)
        self.files = ArtifactTests()
        self.files.setUp()
        self.addCleanup(self.files.doCleanups)
        self.files.value = self.inputs.value
        self.files.configure()
        self.fx = self.inputs.fx
        self.files.gate.clock = lambda: self.fx.time
        self.fx.engine.boundary = input_gate.GuardedBoundary(self.fx.boundary, self.inputs.gate,
            preflight_deadline=self.fx.time + 20, artifact_gate=self.files.gate)

    def test_both_guards_run_before_arm_and_again_after_stop(self):
        checks = []
        original = self.files.gate.verify
        def verify(value, *, deadline):
            checks.append(deadline)
            return original(value, deadline=deadline)
        self.files.gate.verify = verify
        self.fx.engine.admit(self.inputs.value)
        result = self.fx.engine.forward()
        self.assertEqual(result["outcome"], "candidate_verified")
        self.assertFalse(result["production_acceptance"])
        self.assertTrue(result["start_fenced"])
        self.assertEqual(len(checks), 2)
        self.assertEqual(checks[1], self.inputs.captures[-1])
        self.assertEqual(len(self.inputs.captures), 4)

    def test_non_true_artifact_results_cannot_admit(self):
        for result in (False, None, 1, {"matched": True}):
            with self.subTest(result=result), mock.patch.object(self.files.gate, "verify", return_value=result):
                with self.assertRaises(durable.Rejected):
                    self.fx.engine.admit(self.inputs.value)
                self.assertEqual(os.listdir(self.fx.state), [])
                self.assertEqual(self.inputs.captures, [])
        with self.assertRaises(durable.Rejected):
            input_gate.GuardedBoundary(self.fx.boundary, self.inputs.gate, preflight_deadline=self.fx.time + 20,
                                       artifact_gate=lambda: True)

    def test_bad_archive_before_arm_cannot_write_intent_or_stop(self):
        self.files.archive.write_bytes(b"secret-invalid-package")
        with self.assertRaisesRegex(durable.Rejected, "^artifact-check-unconfirmed$"):
            self.fx.engine.admit(self.inputs.value)
        self.assertEqual(os.listdir(self.fx.state), [])
        self.assertEqual(self.fx.boundary.calls, ["preflight"])
        self.assertEqual(self.inputs.captures, [])

    def test_drift_after_arm_recovers_without_candidate_mutation_or_start(self):
        self.fx.engine.admit(self.inputs.value)
        self.files.library.write_bytes(b"secret-changed-library")
        self.fx.receipt_fault = True
        result = self.fx.engine.forward()
        self.assertEqual(result["original_cause"], "forward-revalidate-failed")
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertNotIn("mutate", self.fx.boundary.calls)
        self.assertNotIn("start-candidate", self.fx.boundary.calls)
        self.assertFalse(result["alert"]["receipt_persisted"])
        self.assertTrue(result["alert"]["transport_delivered"])
        self.assertEqual(len(self.fx.notices), 1)
        self.assertEqual(self.fx.file.read_bytes(), b"original-baseline-config")

    def test_existing_preflight_and_stopped_checks_cannot_be_skipped(self):
        with mock.patch.object(self.files.gate, "verify", wraps=self.files.gate.verify) as verify:
            self.fx.boundary.overrides["preflight"] = False
            with self.assertRaises(durable.Rejected):
                self.fx.engine.admit(self.inputs.value)
            self.assertEqual(verify.call_count, 0)
            self.fx.boundary.overrides.clear()
            self.fx.engine.admit(self.inputs.value)
            self.fx.boundary.overrides["revalidate"] = False
            result = self.fx.engine.forward()
            self.assertEqual(verify.call_count, 1)
            self.assertEqual(result["outcome"], "baseline_restored")
            self.assertNotIn("mutate", self.fx.boundary.calls)

    def test_stopped_storage_fault_still_attempts_transport_and_recovery(self):
        self.fx.engine.admit(self.inputs.value)
        self.fx.receipt_fault = True
        with mock.patch.object(artifacts.os, "pread", side_effect=OSError(errno.EIO, "secret-artifact")) as read:
            result = self.fx.engine.forward()
            self.assertEqual(read.call_count, 1)
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertTrue(result["alert"]["transport_delivered"])
        self.assertFalse(result["alert"]["receipt_persisted"])
        self.assertNotIn("mutate", self.fx.boundary.calls)

    def test_artifact_work_consumes_original_stopped_revalidation_deadline(self):
        self.fx.engine.admit(self.inputs.value)
        original = self.files.gate._member
        def member(archive, size, current):
            original(archive, size, current)
            self.fx.time += 20
        self.files.gate._member = member
        result = self.fx.engine.forward()
        self.assertEqual(result["original_cause"], "forward-revalidate-failed")
        self.assertNotIn("mutate", self.fx.boundary.calls)
        self.assertNotIn("start-candidate", self.fx.boundary.calls)
        self.assertTrue(result["start_fenced"])
        self.assertFalse(result["production_acceptance"])
