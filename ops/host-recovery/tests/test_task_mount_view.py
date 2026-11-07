"""Real pidfds/procfs with synthetic cgroup files; not Docker qualification."""
from contextlib import ExitStack
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from host_recovery import runtime_processes as source
from host_recovery.broker_runtime import RuntimeDomain
from host_recovery.durable import Rejected
import test_mounted_baseline


class TaskMountViewTests(unittest.TestCase):
    def setUp(self):
        self.stack = self.enterContext(ExitStack())
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.object_id, self.pid = "e" * 64, os.getpid()
        self.time, self.allowed, self.hook = 1, True, None
        self.group = self.root / ("docker-" + self.object_id + ".scope")
        self.group.mkdir()
        (self.root / "cgroup.procs").write_bytes(b"")
        (self.group / "cgroup.procs").write_text(str(self.pid) + "\n")
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        self.domain = Mock(spec=RuntimeDomain)
        self.domain.fd, self.domain.device, self.domain.cgroup = fd, os.fstat(fd).st_dev, "/runtime.slice"
        self.domain.configuration.return_value = b"synthetic-domain"
        self.membership = "0::/runtime.slice/" + self.group.name + "\n"
        original = open
        def read(path, *args, **kwargs):
            if path == "/proc/%d/cgroup" % self.pid:
                return io.BytesIO(self.membership.encode())
            return original(path, *args, **kwargs)
        self.enterContext(patch.object(source, "open", side_effect=read, create=True))
        self.witness = None

    def capture(self):
        self.witness = source.RuntimeProcessWitness.capture(domain=self.domain, check=lambda: None)
        self.addCleanup(self.witness.close)
        return self.witness

    def check(self, *, deadline):
        if self.hook:
            self.hook()
        return self.allowed

    def view(self, **changes):
        args = dict(object_id=self.object_id, pid=self.pid, check=self.check, clock=lambda: self.time)
        args.update(changes)
        return self.stack.enter_context(self.witness.docker_task_mount_view(**args))

    def test_captured_pidfd_selected_without_another_numeric_lookup(self):
        self.capture()
        original = self.witness._fds[0][0]
        with patch.object(source.os, "pidfd_open", side_effect=AssertionError("numeric lookup")):
            view = self.view()
            receipt = view.observe(deadline=50)
            self.assertFalse(receipt["container_namespace_verified"])
            self.assertFalse(receipt["start_authorized"])
            self.assertNotEqual(view.pidfd, original)
            self.assertFalse(os.get_inheritable(view.pidfd))
            self.stack.close()
            os.fstat(original)
            with self.assertRaises(OSError):
                os.fstat(view.pidfd)

    def test_only_exact_full_object_id_and_captured_task_pid_are_supported(self):
        self.capture()
        for change in ({"object_id": "short"}, {"object_id": "E" * 64}, {"object_id": "a" * 64},
                       {"object_id": "../" + self.object_id}, {"pid": True}, {"pid": 1},
                       {"pid": self.pid + 100000}, {"check": None}, {"clock": None}):
            with self.subTest(change=change), self.assertRaises(Rejected):
                self.view(**change)

    def test_cgroup_membership_change_revokes_the_view_permanently(self):
        self.capture()
        view = self.view()
        view._current(50)
        self.membership = "0::/other.slice\n"
        with self.assertRaises(Rejected):
            view._current(50)
        self.membership = "0::/runtime.slice/" + self.group.name + "\n"
        with self.assertRaises(Rejected):
            view._current(50)

    def test_replaced_same_name_group_is_not_adopted(self):
        self.capture()
        view = self.view()
        self.group.rename(self.root / "detached")
        self.group.mkdir()
        (self.group / "cgroup.procs").write_text(str(self.pid) + "\n")
        with self.assertRaises(Rejected):
            view._current(50)

    def test_missing_or_added_process_refuses_the_retained_inventory(self):
        for raw in (b"", (str(self.pid) + "\n24\n").encode()):
            with self.subTest(raw=raw):
                (self.group / "cgroup.procs").write_text(str(self.pid) + "\n")
                self.capture()
                view = self.view()
                (self.group / "cgroup.procs").write_bytes(raw)
                with self.assertRaises(Rejected):
                    view._current(50)

    def test_closed_witness_or_changed_domain_cannot_supply_authority(self):
        self.capture()
        view = self.view()
        self.witness.close()
        with self.assertRaises(Rejected):
            view._current(50)
        self.capture()
        view = self.view()
        self.domain.configuration.return_value = b"changed"
        with self.assertRaises(Rejected):
            view._current(50)

    def test_nonliteral_authority_refuses_and_remains_revoked(self):
        self.capture()
        for flag in (False, 1, None):
            with self.subTest(flag=flag):
                self.allowed = flag
                view = self.view()
                with self.assertRaises(Rejected):
                    view._current(50)
                self.allowed = True
                with self.assertRaises(Rejected):
                    view._current(50)

    def test_expiry_and_backward_clock_cannot_extend_original_view(self):
        self.capture()
        view = self.view()
        view._current(50)
        self.time = 0
        with self.assertRaises(Rejected):
            view._current(50)
        self.time = 50
        with self.assertRaises(Rejected):
            self.view()._current(50)

    def test_caught_reentrant_authority_failure_is_not_a_green_outer_read(self):
        self.capture()
        view = self.view()
        def reenter():
            self.hook = None
            with self.assertRaises(Rejected):
                view._current(50)
        self.hook = reenter
        with self.assertRaises(Rejected):
            view._current(50)

    def test_final_authority_callback_cannot_replace_the_task_scope(self):
        self.capture()
        view = self.view()
        scanned, replaced = False, False
        original = source._scan
        def scan(*args):
            nonlocal scanned
            result = original(*args)
            scanned = True
            return result
        def replace():
            nonlocal replaced
            if scanned and not replaced:
                replaced = True
                self.group.rename(self.root / "detached")
                self.group.mkdir()
                (self.group / "cgroup.procs").write_text(str(self.pid) + "\n")
        self.hook = replace
        with patch.object(source, "_scan", side_effect=scan), self.assertRaises(Rejected):
            view._current(50)
        self.assertTrue(replaced)

    def test_actual_process_death_invalidates_view_without_reacquisition(self):
        process = subprocess.Popen([sys.executable, "-I", "-c", "import os; os.read(0, 1)"], stdin=subprocess.PIPE)
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdin.close()
        self.addCleanup(cleanup)
        self.pid = process.pid
        (self.group / "cgroup.procs").write_text(str(self.pid) + "\n")
        self.capture()
        view = self.view()
        view._current(50)
        process.stdin.close()
        self.assertEqual(process.wait(timeout=5), 0)
        with patch.object(source.os, "pidfd_open", side_effect=AssertionError("PID reacquisition")):
            with self.assertRaises(Rejected):
                view._current(50)

    def test_witness_maps_into_complete_mounted_baseline_observation(self):
        fixture = test_mounted_baseline.MountedBaselineTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.assertEqual(self.object_id, fixture.approval.object_id)
        self.capture()
        with fixture.open(pidfd=None, witness=self.witness) as view:
            with view.observe(fixture.fx.value, deadline=1100) as receipt:
                self.assertTrue(receipt["process_root_observed"])
                self.assertTrue(receipt["mounted_files_verified"])
                self.assertFalse(receipt["start_authorized"])
                self.assertFalse(receipt["plugin_readiness_verified"])
        fixture.fx.assert_baseline()

    def test_two_identity_sources_are_rejected_rather_than_falling_back(self):
        fixture = test_mounted_baseline.MountedBaselineTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.capture()
        with self.assertRaises(Rejected):
            with fixture.open(witness=self.witness):
                self.fail("ambiguous identity accepted")
