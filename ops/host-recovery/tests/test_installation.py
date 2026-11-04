"""Owned synthetic roots only; no installation or real manager/daemon drill."""
from dataclasses import asdict, replace
import errno
import fcntl
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from host_recovery import durable, installation, jobs, loading
from test_recovery_state import intent

ROOT = Path(__file__).resolve().parent.parent


def approve(path):
    st = path.stat()
    return installation.DirectoryApproval(str(path), st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode & 0o7777)


class InstallationTests(unittest.TestCase):
    def setUp(self):
        # /tmp and CI/workspace parents can be group/world writable. Create only
        # fresh owned fixtures below the test user's protected home; never chmod
        # an existing ancestor or weaken the acquisition rule for test setup.
        temp = tempfile.TemporaryDirectory(prefix=".recovery-installation-test-", dir=pwd.getpwuid(os.geteuid()).pw_dir)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.content, self.journal = self.root / "content", self.root / "journal"
        self.content.mkdir(mode=0o700)
        self.journal.mkdir(mode=0o700)
        self.approval = installation.InstallationApproval("installation-a", approve(self.content), approve(self.journal))

    def open(self):
        return installation.open_installation(self.approval)

    def state(self):
        return {str(p.relative_to(self.root)): (p.stat().st_ino, p.stat().st_mode, p.read_bytes() if p.is_file() else None)
                for p in self.root.rglob("*")}

    def seed(self):
        raw = b'{"synthetic":true}\n'
        (self.content / "settings.json").write_bytes(raw)
        (self.content / "settings.json").chmod(0o600)
        index = durable.canonical({"schema": "host-recovery-content-v1", "source_revision": "a" * 40,
            "files": [{"path": "settings.json", "mode": 0o600, "sha256": durable.digest(raw)}]})
        (self.content / loading.INDEX).write_bytes(index)
        (self.content / loading.INDEX).chmod(0o600)
        content = loading.ContentApproval(durable.digest(index), "a" * 40, os.geteuid(), os.getegid())
        value = intent()
        value["installation_id"] = self.approval.installation_id
        value["owner"]["installation_id"] = value["installation_id"]
        intent_pin = durable.digest(durable.canonical(value))
        recovery = loading.RecoveryApproval(intent_pin, value["package_sha256"], value["manifest_sha256"],
            value["baseline_sha256"], value["policy_sha256"], value["installation_id"], value["attempt_id"],
            os.geteuid(), os.getegid())
        arm = {"schema": "host-recovery-arm-v1", "arm": {"boot_id": "boot-a", "monotonic": 1000.0},
               "intent_sha256": intent_pin}
        owner = {**value["owner"], "invocation_id": "b" * 32}
        request = {"schema": "host-recovery-reconcile-request-v1", "attempt_id": value["attempt_id"],
            "intent_sha256": intent_pin, "owner": owner, "original_arm": arm["arm"], "failure_lower_bound": 1000.0,
            "deadline": 1180.0, "detection_upper_bound_seconds": 50.0, "forward_allowed": False,
            "production_acceptance": False}
        request["request_id"] = durable.digest(durable.canonical(request))
        for name, obj in (("intent.json", value), ("arm.json", arm), ("reconcile-request.json", request)):
            (self.journal / name).write_bytes(durable.canonical(obj))
            (self.journal / name).chmod(0o600)
        return dict(content_approval=content, recovery_approval=recovery,
            binding=jobs.RecoveryJobBinding(request["request_id"], "/synthetic/recovery.service", "c" * 64, "d" * 64),
            supervisor_owner=owner, boot_id="boot-a", now=1050.0)

    def test_open_is_readonly_and_closes_all_borrowed_handles(self):
        before = self.state()
        with self.open() as handles:
            handles.validate()
            fds = [row[1] for root in (handles._content, handles._journal) for row in root.chain]
            self.assertTrue(all(not os.get_inheritable(fd) for fd in fds))
        self.assertEqual(self.state(), before)
        with self.assertRaisesRegex(durable.Rejected, "unavailable"):
            handles.validate()
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_snapshot_binds_both_roots_to_external_approvals_under_lock(self):
        args = self.seed()
        before = self.state()
        with self.open() as handles:
            content, inputs = handles.snapshot(**args)
            self.assertEqual(content.json("settings.json"), {"synthetic": True})
            self.assertEqual(inputs.intent["installation_id"], self.approval.installation_id)
            self.assertEqual(inputs.request["deadline"], 1180.0)
            self.assertFalse(inputs.request["forward_allowed"])
            with durable.directory(str(self.journal), private=True) as fd:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(self.state(), before)
        self.assertNotIn("start_permission", inputs.request)

    def test_expired_snapshot_is_not_renewed_and_poisons_session(self):
        args = self.seed()
        args["now"] = 1180.0
        with self.assertRaises(durable.Rejected):
            with self.open() as handles:
                with self.assertRaises(durable.Rejected):
                    handles.snapshot(**args)
                self.assertTrue(handles.failed)
                handles.validate()

    def test_snapshot_owner_or_installation_disagreement_refuses(self):
        args = self.seed()
        for key, value in (("content_approval", replace(args["content_approval"], uid=os.geteuid() + 1)),
                           ("recovery_approval", replace(args["recovery_approval"], gid=os.getegid() + 1)),
                           ("recovery_approval", replace(args["recovery_approval"], installation_id="foreign"))):
            with self.subTest(key=key), self.assertRaisesRegex(durable.Rejected, "loading-approval-mismatch"):
                with self.open() as handles:
                    handles.snapshot(**{**args, key: value})

    def test_bad_content_does_not_read_journal(self):
        args = self.seed()
        (self.content / "settings.json").write_bytes(b"bad")
        with patch.object(loading, "load_recovery") as read:
            with self.assertRaises(durable.Rejected):
                with self.open() as handles:
                    handles.snapshot(**args)
        read.assert_not_called()

    def test_changed_ancestry_after_load_does_not_return_snapshot(self):
        args = self.seed()
        actual = loading.load_recovery
        def changed(*a, **kw):
            value = actual(*a, **kw)
            self.content.rename(self.root / "old-content")
            self.content.mkdir(mode=0o700)
            return value
        with patch.object(loading, "load_recovery", side_effect=changed):
            with self.assertRaisesRegex(durable.Rejected, "directory-changed"):
                with self.open() as handles:
                    handles.snapshot(**args)

    def test_noncanonical_absolute_paths_refuse(self):
        for path in ("/", "relative", "/tmp/", "/tmp//x", "/tmp/./x", "/tmp/../x", "/tmp/a\0x",
                     "/" + "a" * 4096, "/a" * 65):
            with self.subTest(path=path), self.assertRaises(durable.Rejected):
                replace(self.approval.content, path=path)

    def test_invalid_numeric_pins_or_modes_refuse(self):
        for field, value in (("device", True), ("device", -1), ("inode", 0), ("inode", "1"),
                             ("uid", -1), ("gid", 2147483648), ("mode", True), ("mode", 0o777), ("mode", 0o1700)):
            with self.subTest(field=field, value=value), self.assertRaises(durable.Rejected):
                replace(self.approval.content, **{field: value})

    def test_wrong_independent_leaf_pins_refuse(self):
        for field, value in (("device", self.approval.content.device + 1), ("inode", self.approval.content.inode + 1),
                             ("uid", os.geteuid() + 1), ("gid", os.getegid() + 1), ("mode", 0o755)):
            with self.subTest(field=field), self.assertRaises(durable.Rejected):
                approved = replace(self.approval, content=replace(self.approval.content, **{field: value}))
                with installation.open_installation(approved):
                    self.fail("unapproved root admitted")

    def test_equal_nested_and_inode_alias_roots_refuse(self):
        for content in (self.approval.journal, replace(self.approval.content, path=str(self.journal / "nested")),
                        replace(self.approval.content, path=str(self.root)),
                        replace(self.approval.content, device=self.approval.journal.device, inode=self.approval.journal.inode)):
            with self.subTest(content=content), self.assertRaises(durable.Rejected):
                replace(self.approval, content=content)

    def test_journal_requires_private_mode_and_typed_approval(self):
        for changes in ({"journal": replace(self.approval.journal, mode=0o755)}, {"content": object()},
                        {"installation_id": ""}):
            with self.subTest(changes=changes), self.assertRaises(durable.Rejected):
                replace(self.approval, **changes)
        with self.assertRaises(durable.Rejected):
            with installation.open_installation(asdict(self.approval)):
                self.fail("dictionary accepted")

    def test_missing_path_is_not_created(self):
        self.content.rmdir()
        with self.assertRaises(OSError):
            with self.open():
                self.fail("missing root admitted")
        self.assertFalse(self.content.exists())

    def test_symlink_ancestor_or_leaf_never_follows(self):
        for kind in ("ancestor", "leaf"):
            with self.subTest(kind=kind):
                if kind == "leaf":
                    self.content.rename(self.root / "target")
                    self.content.symlink_to("target", target_is_directory=True)
                else:
                    link = self.root / "link"
                    link.symlink_to(self.root, target_is_directory=True)
                    self.approval = replace(self.approval, content=replace(self.approval.content, path=str(link / "content")))
                with self.assertRaises(OSError):
                    with self.open():
                        self.fail("symlink followed")

    def test_regular_file_or_fifo_leaf_refuses_without_block(self):
        self.content.rmdir()
        for kind in ("file", "fifo"):
            if kind == "file":
                self.content.write_bytes(b"not a directory")
            else:
                os.mkfifo(self.content, 0o600)
            with self.subTest(kind=kind), self.assertRaises(OSError):
                with self.open():
                    self.fail("non-directory admitted")
            self.content.unlink()

    def test_group_other_write_and_special_ancestor_modes_refuse(self):
        for mode in (0o770, 0o707, 0o1700, 0o2700, 0o4700):
            self.root.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(durable.Rejected):
                with self.open():
                    self.fail("unsafe ancestry admitted")
        self.root.chmod(0o700)

    def test_extended_ancestor_metadata_refuses(self):
        os.setxattr(self.root, "user.installation-test", b"unsupported")
        with self.assertRaises(durable.Rejected):
            with self.open():
                self.fail("extended metadata admitted")

    def test_replaced_leaf_does_not_adopt_new_lock_namespace(self):
        self.journal.rename(self.root / "old-journal")
        self.journal.mkdir(mode=0o700)
        with self.assertRaisesRegex(durable.Rejected, "root-pin-mismatch"):
            with self.open():
                self.fail("replacement journal admitted")

    def test_live_ancestor_replacement_revokes_handles(self):
        original = self.root / "parent"
        original.mkdir(mode=0o700)
        self.content.rename(original / "content")
        self.content = original / "content"
        self.approval = replace(self.approval, content=approve(self.content))
        with self.assertRaisesRegex(durable.Rejected, "directory-changed"):
            with self.open() as handles:
                original.rename(self.root / "moved")
                original.mkdir(mode=0o700)
                handles.validate()
        self.assertTrue(handles.closed)

    def test_exit_revalidation_detects_replacement_without_explicit_check(self):
        with self.assertRaisesRegex(durable.Rejected, "directory-changed"):
            with self.open() as handles:
                self.journal.rename(self.root / "old-journal")
                self.journal.mkdir(mode=0o700)
        self.assertTrue(handles.closed)

    def test_changed_protection_is_sticky_even_if_restored(self):
        with self.assertRaisesRegex(durable.Rejected, "unavailable"):
            with self.open() as handles:
                self.content.chmod(0o777)
                with self.assertRaises(durable.Rejected):
                    handles.validate()
                self.content.chmod(0o700)
                handles.validate()

    def test_directory_writes_do_not_replace_identity_or_lock(self):
        with self.open() as handles:
            (self.journal / "synthetic-record").write_bytes(b"unrelated change")
            handles.validate()
            with self.assertRaises(BlockingIOError):
                with self.open():
                    self.fail("overlapping lock admitted")
        with self.open() as handles:
            handles.validate()

    def test_same_lock_as_existing_supervisor_primitive(self):
        owner = {key: "synthetic" for key in ("installation_id", "attempt_id", "unit", "invocation_id", "boot_id")}
        with durable.installation_lock(str(self.journal), owner):
            with self.assertRaises(BlockingIOError):
                with self.open():
                    self.fail("second lock namespace")
        with self.open():
            with self.assertRaises(BlockingIOError):
                with durable.installation_lock(str(self.journal), owner):
                    self.fail("second lock namespace")

    def test_open_faults_do_not_leak_fds_or_change_files(self):
        actual = installation.os.open
        initial = len(os.listdir("/proc/self/fd"))
        before = self.state()
        with patch.object(installation.os, "open", wraps=actual) as opened:
            with self.open():
                count = opened.call_count
        for number in range(1, count + 1):
            calls = 0
            def broken(*a, **kw):
                nonlocal calls
                calls += 1
                if calls == number:
                    raise OSError(errno.EIO, "synthetic")
                return actual(*a, **kw)
            with patch.object(installation.os, "open", side_effect=broken):
                with self.assertRaises(OSError):
                    with self.open():
                        self.fail("fault was ignored")
            self.assertEqual(len(os.listdir("/proc/self/fd")), initial)
        self.assertEqual(self.state(), before)

    def test_metadata_failures_at_each_ancestry_step_close_all_fds(self):
        actual = installation.protected
        before = len(os.listdir("/proc/self/fd"))
        with patch.object(installation, "protected", wraps=actual) as observed:
            with self.open():
                count = observed.call_count
        for number in range(1, count + 1):
            calls = 0
            def broken(*a, **kw):
                nonlocal calls
                calls += 1
                if calls == number:
                    raise OSError(errno.EIO, "synthetic-metadata")
                return actual(*a, **kw)
            with self.subTest(step=number), patch.object(installation, "protected", side_effect=broken):
                with self.assertRaises(OSError):
                    with self.open():
                        pass
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_world_writable_sticky_ancestor_is_not_an_approved_root(self):
        with tempfile.TemporaryDirectory(prefix="recovery-untrusted-ancestor-", dir="/tmp") as temp:
            approved = replace(self.approval, content=approve(Path(temp)))
            with self.assertRaisesRegex(durable.Rejected, "protected-ancestry"):
                with installation.open_installation(approved):
                    self.fail("sticky writable ancestor admitted")

    def test_lock_failure_closes_all_fds(self):
        before = len(os.listdir("/proc/self/fd"))
        with patch.object(installation.fcntl, "flock", side_effect=OSError(errno.ENOSPC, "synthetic")):
            with self.assertRaises(OSError):
                with self.open():
                    self.fail("failed lock admitted")
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_leaf_open_race_is_detected_and_descriptors_closed(self):
        actual = installation.os.open
        before = len(os.listdir("/proc/self/fd"))
        changed = False
        def replaced(path, *a, **kw):
            nonlocal changed
            fd = actual(path, *a, **kw)
            if path == "content" and not changed:
                changed = True
                self.content.rename(self.root / "moved-content")
                self.content.mkdir(mode=0o700)
            return fd
        with patch.object(installation.os, "open", side_effect=replaced):
            with self.assertRaisesRegex(durable.Rejected, "directory-changed"):
                with self.open():
                    self.fail("replacement race admitted")
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_caller_exception_is_preserved_and_lock_released(self):
        with self.assertRaisesRegex(RuntimeError, "synthetic-caller"):
            with self.open() as handles:
                raise RuntimeError("synthetic-caller")
        self.assertTrue(handles.closed)
        with self.open() as next_handles:
            next_handles.validate()

    def test_real_process_sigkill_releases_same_lock_without_touching_records(self):
        self.seed()
        before = self.state()
        script = """
import json,signal,sys
sys.path.insert(0,sys.argv[1])
from host_recovery.installation import DirectoryApproval,InstallationApproval,open_installation
obj=json.loads(sys.argv[2])
a=InstallationApproval(obj['installation_id'],DirectoryApproval(**obj['content']),DirectoryApproval(**obj['journal']))
with open_installation(a):
    print('locked',flush=True)
    signal.pause()
"""
        process = subprocess.Popen([sys.executable, "-I", "-c", script, str(ROOT), json.dumps(asdict(self.approval))],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        try:
            # Deterministic readiness, bounded independently from process cleanup.
            import selectors
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(10), "child did not report lock acquisition")
            self.assertEqual(process.stdout.readline(), "locked\n")
            with self.assertRaises(BlockingIOError):
                with self.open():
                    self.fail("child's lock overlapped")
            process.kill()
            _, error = process.communicate(timeout=10)
            self.assertEqual(process.returncode, -signal.SIGKILL, error)
            with self.open() as handles:
                handles.validate()
            self.assertEqual(self.state(), before)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)
