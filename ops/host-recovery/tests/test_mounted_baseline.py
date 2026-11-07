"""Synthetic files and self pidfd/procfs; NO authenticated daemon/container fixture."""
from contextlib import ExitStack, contextmanager
import copy
from dataclasses import replace
import errno
import os
import unittest
from unittest.mock import patch

from host_recovery import durable, mounted_baseline, write_set
from test_installation import approve
import test_write_set


class MountedBaselineTests(unittest.TestCase):
    def setUp(self):
        self.fx = test_write_set.WriteSetTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.mounts = [{"Type": "bind", "Source": str(path), "Destination": str(path),
                        "Mode": "ro", "RW": False, "Propagation": "rprivate"}
                       for path in self.fx.paths.values()]
        self.approval = mounted_baseline.MountedBaselineApproval(
            durable.digest(durable.canonical(self.fx.value)), self.fx.value["old_object_id"],
            durable.digest(durable.canonical(self.mounts)))

    @contextmanager
    def open(self, **changes):
        with ExitStack() as stack:
            fd = os.pidfd_open(os.getpid())
            stack.callback(os.close, fd)
            verifier = stack.enter_context(write_set.open_write_set_verifier(baseline=approve(self.fx.backup),
                roots=self.fx.approvals, baseline_sha256=self.fx.pin, check=self.fx.check, clock=lambda: self.fx.time))
            args = dict(pid=os.getpid(), pidfd=fd, approval=self.approval, mounts=self.mounts,
                        verifier=verifier, check=self.fx.check, clock=lambda: self.fx.time)
            args.update(changes)
            yield stack.enter_context(mounted_baseline.open_mounted_baseline(**args))

    def test_process_root_complete_files_retained_and_descriptors_closed_without_grants(self):
        with self.open() as view:
            with view.observe(self.fx.value, deadline=1100) as receipt:
                self.assertTrue(receipt["mounted_files_verified"])
                self.assertTrue(receipt["process_root_observed"])
                self.assertFalse(receipt["plugin_readiness_verified"])
                self.assertFalse(receipt["start_authorized"])
                self.assertEqual(receipt["roots"], 3)
                self.assertNotIn(str(self.fx.root), str(receipt))
                self.assertFalse(view.verifier._reader.restored)
            retained = view._retained
            for fd in retained:
                self.assertFalse(os.get_inheritable(fd))
        for fd in retained:
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.fx.assert_baseline()

    def test_missing_root_mapping_refuses_even_when_source_inventory_matches(self):
        mounts = self.mounts[:2]
        approval = replace(self.approval, mounts_sha256=durable.digest(durable.canonical(mounts)))
        with self.open(mounts=mounts, approval=approval) as view, self.assertRaises(durable.Rejected):
            with view.observe(self.fx.value, deadline=1100):
                self.fail("incomplete roots accepted")
        self.assertTrue(view.failed)

    def test_destination_identity_cannot_be_replaced_by_identical_bytes(self):
        duplicate = self.fx.root / "same-bytes-different-inode"
        duplicate.mkdir(mode=0o700)
        mounts = copy.deepcopy(self.mounts)
        mounts[2]["Destination"] = str(duplicate)
        approval = replace(self.approval, mounts_sha256=durable.digest(durable.canonical(mounts)))
        with self.open(mounts=mounts, approval=approval) as view, self.assertRaises(durable.Rejected):
            with view.observe(self.fx.value, deadline=1100):
                self.fail("different destination accepted")

    def test_symlink_destination_has_no_path_fallback(self):
        link = self.fx.root / "linked-config"
        link.symlink_to(self.fx.paths["config"], target_is_directory=True)
        mounts = copy.deepcopy(self.mounts)
        mounts[1]["Destination"] = str(link)
        approval = replace(self.approval, mounts_sha256=durable.digest(durable.canonical(mounts)))
        with self.open(mounts=mounts, approval=approval) as view, self.assertRaises(durable.Rejected):
            with view.observe(self.fx.value, deadline=1100):
                self.fail("symlink destination accepted")

    def test_changed_bytes_after_result_yield_are_not_repaired_or_accepted(self):
        path = self.fx.paths["auth"] / "unrelated.json"
        with self.open() as view, self.assertRaises(durable.Rejected):
            with view.observe(self.fx.value, deadline=1100):
                self.fx.put(path, b"changed-during-observation-persistence")
        self.assertEqual(path.read_bytes(), b"changed-during-observation-persistence")
        self.assertTrue(view.failed)

    def test_destination_replaced_after_yield_refuses_original_open_handles(self):
        with self.assertRaisesRegex(durable.Rejected, "^installation-directory-changed$"):
            with self.open() as view, self.assertRaises(durable.Rejected):
                with view.observe(self.fx.value, deadline=1100):
                    path = self.fx.paths["plugin"]
                    path.rename(self.fx.root / "detached-plugin")
                    path.mkdir(mode=0o700)
        self.assertTrue(view.failed)

    def test_independent_approval_and_object_linkage_are_not_learned_from_current_state(self):
        for field in ("intent_sha256", "object_id", "mounts_sha256"):
            with self.subTest(field=field), self.open(approval=replace(self.approval, **{field: "0" * 64})) as view:
                with self.assertRaises(durable.Rejected):
                    with view.observe(self.fx.value, deadline=1100):
                        self.fail("unapproved process mapping accepted")

    def test_callback_replacement_and_mount_drift_after_yield_refuse(self):
        for target in ("check", "clock", "mounts", "verifier", "approval"):
            with self.subTest(target=target), self.open(mounts=copy.deepcopy(self.mounts)) as view:
                with self.assertRaises(durable.Rejected):
                    with view.observe(self.fx.value, deadline=1100):
                        if target == "check":
                            view.process.check = lambda **kw: True
                        elif target == "clock":
                            view.process.clock = lambda: self.fx.time
                        elif target == "mounts":
                            view.mounts[0]["RW"] = True
                        elif target == "verifier":
                            view.verifier = copy.copy(view.verifier)
                        else:
                            view.approval = replace(view.approval, object_id="0" * 64)
                self.assertTrue(view.failed)

    def test_reached_mounted_read_failures_poison_view(self):
        for code in (errno.EIO, errno.ENOSPC):
            with self.subTest(code=code), self.open() as view:
                reached = []
                def fail(*args, **kwargs):
                    reached.append(code)
                    raise OSError(code, "synthetic-mounted-read-fault")
                with patch.object(view.verifier, "verify_mounted_files", side_effect=fail), self.assertRaises(durable.Rejected):
                    with view.observe(self.fx.value, deadline=1100):
                        self.fail("failed read accepted")
                self.assertEqual(reached, [code])
                self.assertTrue(view.failed)

    def test_original_pidfd_and_proc_access_required_without_caller_view_fallback(self):
        fd = os.open(self.fx.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(durable.Rejected), self.open(pidfd=fd):
                self.fail("directory accepted as pidfd")
        finally:
            os.close(fd)
        with self.open() as view:
            reached = []
            def fail(*args):
                reached.append("proc-root")
                raise PermissionError("synthetic-proc-denial")
            with patch.object(view, "_view", side_effect=fail), self.assertRaises(durable.Rejected):
                with view.observe(self.fx.value, deadline=1100):
                    self.fail("proc denial accepted")
            self.assertEqual(reached, ["proc-root"])

    def test_caught_reentrant_observation_poisoning(self):
        with self.open() as view, self.assertRaises(durable.Rejected):
            with view.observe(self.fx.value, deadline=1100):
                with self.assertRaises(durable.Rejected):
                    with view.observe(self.fx.value, deadline=1100):
                        self.fail("reentrant observation accepted")
        self.assertTrue(view.failed)

    def test_expiry_fence_loss_and_nonfinite_clock_fail_closed(self):
        for target in ("expiry", "fence", "clock"):
            with self.subTest(target=target), self.open() as view:
                time, fenced = self.fx.time, self.fx.fenced
                try:
                    with self.assertRaises(durable.Rejected):
                        with view.observe(self.fx.value, deadline=1100):
                            if target == "expiry":
                                self.fx.time = 1100
                            elif target == "fence":
                                self.fx.fenced = False
                            else:
                                self.fx.time = float("nan")
                finally:
                    self.fx.time, self.fx.fenced = time, fenced
                self.assertTrue(view.failed)

    def test_kernel_view_change_between_observations_is_not_adopted(self):
        with self.open() as view, self.assertRaises(durable.Rejected):
            with view.observe(self.fx.value, deadline=1100):
                capture = view._view
                reached = []
                def changed(stack):
                    handles, signature = capture(stack)
                    reached.append("changed-view")
                    return handles, (signature[0], (*signature[1][:-1], signature[1][-1] + 1))
                view._view = changed
        self.assertEqual(reached, ["changed-view"])
        self.assertTrue(view.failed)
