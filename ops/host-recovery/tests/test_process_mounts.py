"""Own-process kernel observations and scripted negatives; no daemon or setns."""
from contextlib import ExitStack
import errno
import os
import socket
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

from host_recovery import deployment, durable, process_mounts
import test_bind_sources


class ProcessMountTests(unittest.TestCase):
    def setUp(self):
        self.stack = self.enterContext(ExitStack())
        self.pidfd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, self.pidfd)
        self.time, self.calls, self.hook = 1, [], None

    def check(self, *, deadline):
        self.calls.append(deadline)
        if self.hook:
            return self.hook()
        return True

    def open(self, **overrides):
        args = dict(pid=os.getpid(), pidfd=self.pidfd, check=self.check, clock=lambda: self.time)
        args.update(overrides)
        return self.stack.enter_context(process_mounts.open_process_mount_view(**args))

    def observe(self, view):
        return view.observe(deadline=50)

    def test_real_self_namespace_root_and_pidfd_with_non_authorizing_receipt(self):
        view = self.open()
        receipt = self.observe(view)
        self.assertEqual(receipt, self.observe(view))
        self.assertEqual(self.calls, [50] * 4)
        self.assertIs(receipt["source_namespace_matches"], True)
        self.assertIs(receipt["container_namespace_verified"], False)
        self.assertIs(receipt["start_authorized"], False)
        self.assertEqual(set(receipt), {"schema", "view_sha256", "source_namespace_matches",
                                       "container_namespace_verified", "start_authorized"})
        self.assertEqual(len(view._retained), 4)
        self.assertTrue(all(not os.get_inheritable(fd) for fd in (*view._retained, view.pidfd, view.proc)))

    def test_wrong_numeric_pid_cannot_rebind_a_real_pidfd(self):
        with self.assertRaises(durable.Rejected):
            self.open(pid=os.getpid() + 1)

    def test_regular_descriptor_is_not_a_pidfd(self):
        with open("/dev/null", "rb") as stream, self.assertRaises(durable.Rejected):
            self.open(pidfd=stream.fileno())

    def test_invalid_pid_or_fd_types_refuse(self):
        for override in ({"pid": True}, {"pid": 0}, {"pidfd": True}, {"pidfd": -1}, {"check": None}):
            with self.subTest(override=override), self.assertRaises(durable.Rejected):
                self.open(**override)

    def test_descriptor_ownership_and_context_close(self):
        view = self.open()
        self.observe(view)
        owned = (*view._retained, view.pidfd, view.proc)
        self.stack.close()
        os.fstat(self.pidfd)
        for fd in owned:
            with self.assertRaises(OSError):
                os.fstat(fd)
        with self.assertRaises(durable.Rejected):
            self.observe(view)

    def test_actual_process_exit_revokes_retained_view(self):
        child = subprocess.Popen([sys.executable, "-I", "-c",
            "import sys; sys.stdout.write('ready\\n'); sys.stdout.flush(); sys.stdin.buffer.read(1)"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            self.assertEqual(child.stdout.readline(), b"ready\n")
            fd = os.pidfd_open(child.pid)
            try:
                view = self.open(pid=child.pid, pidfd=fd)
                self.observe(view)
                child.stdin.close()
                self.assertEqual(child.wait(timeout=5), 0)
                with self.assertRaises(durable.Rejected):
                    self.observe(view)
            finally:
                os.close(fd)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            if not child.stdin.closed:
                child.stdin.close()
            child.stdout.close()

    def test_nonliteral_or_failed_authority_is_sticky(self):
        for flag in (False, 1, None):
            with self.subTest(flag=flag):
                view = self.open()
                self.hook = lambda: flag
                with self.assertRaises(durable.Rejected):
                    self.observe(view)
                self.hook = None
                with self.assertRaises(durable.Rejected):
                    self.observe(view)

    def test_changed_callback_or_clock_refuses(self):
        for field in ("check", "clock"):
            with self.subTest(field=field):
                view = self.open()
                self.observe(view)
                setattr(view, field, lambda **kwargs: True)
                with self.assertRaises(durable.Rejected):
                    self.observe(view)

    def test_caught_reentrant_refusal_still_poisons_outer_observation(self):
        view = self.open()
        reached = []
        def reenter():
            with self.assertRaises(durable.Rejected):
                self.observe(view)
            reached.append(True)
            return True
        self.hook = reenter
        with self.assertRaises(durable.Rejected):
            self.observe(view)
        self.assertEqual(reached, [True])

    def test_trailing_callback_expiry_and_backwards_clock_refuse(self):
        for value in (0, 50):
            with self.subTest(value=value):
                self.time = 1
                view = self.open()
                def expire():
                    self.time = value
                    return True
                self.hook = expire
                with self.assertRaises(durable.Rejected):
                    self.observe(view)
                self.hook = None

    def test_different_mount_namespace_refuses(self):
        view = self.open()
        with patch.object(process_mounts, "mount_identity", side_effect=[(1, 2), (1, 3)]), self.assertRaises(durable.Rejected):
            self.observe(view)
        self.assertTrue(view.failed)

    def test_same_root_inode_on_different_mount_refuses(self):
        view = self.open()
        with patch.object(process_mounts, "root_identity", side_effect=[(1, 2, 3), (1, 2, 4)]), self.assertRaises(durable.Rejected):
            self.observe(view)

    def test_later_equal_but_replaced_views_cannot_replace_original(self):
        view = self.open()
        self.observe(view)
        with patch.object(process_mounts, "mount_identity", return_value=(999, 999)), self.assertRaises(durable.Rejected):
            self.observe(view)

    def test_reached_kernel_read_faults_refuse_without_descriptor_leak(self):
        for code in (errno.EIO, errno.ENOSPC):
            with self.subTest(code=code):
                view = self.open()
                before = set(os.listdir("/proc/self/fd"))
                reached = []
                def fail(fd):
                    reached.append(code)
                    raise OSError(code, "synthetic-kernel-read")
                with patch.object(process_mounts, "mount_identity", side_effect=fail), self.assertRaises(durable.Rejected):
                    self.observe(view)
                self.assertEqual(reached, [code])
                self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_fdinfo_rejects_missing_duplicate_overflow_and_non_numeric_identity(self):
        for raw in (b"", b"Pid:\t1\nPid:\t1\n", b"Pid:\t-1\n", b"Pid:\t0\n", b"Pid:\t1\n" + b"x" * 4096):
            with self.subTest(raw=raw[:40]), patch("builtins.open", unittest.mock.mock_open(read_data=raw)), self.assertRaises(durable.Rejected):
                process_mounts.fdinfo_number(self.pidfd, b"Pid")


class PeerMountTests(unittest.TestCase):
    def setUp(self):
        self.stack = self.enterContext(ExitStack())
        self.client, self.server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.client.close)
        self.addCleanup(self.server.close)
        self.expected = (os.getpid(), os.geteuid(), os.getegid())
        self.time, self.fenced = 1, True

    def check(self, *, deadline):
        return self.fenced

    def open(self, **overrides):
        args = dict(sock=self.client, expected_peer=self.expected, check=self.check, clock=lambda: self.time)
        args.update(overrides)
        return self.stack.enter_context(process_mounts.open_peer_mount_view(**args))

    def test_kernel_connection_pidfd_drives_non_authorizing_mount_observation(self):
        view = self.open()
        with patch.object(os, "pidfd_open", side_effect=AssertionError("numeric lookup forbidden")):
            receipt = view.observe(deadline=50)
        self.assertEqual(process_mounts.fdinfo_number(view.pidfd, b"Pid"), self.expected[0])
        self.assertIs(receipt["source_namespace_matches"], True)
        self.assertIs(receipt["start_authorized"], False)
        self.assertIs(receipt["container_namespace_verified"], False)
        self.assertEqual(receipt, view.observe(deadline=50))

    def test_seqpacket_peer_is_supported_without_changing_socket_or_consuming_payload(self):
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with client, server:
            server.sendall(b"synthetic-protocol-record")
            view = self.open(sock=client)
            view.observe(deadline=50)
            self.assertTrue(client.getblocking())
            self.assertEqual(client.recv(128), b"synthetic-protocol-record")

    def test_peer_tuple_must_match_all_three_independently_supplied_fields(self):
        for index in range(3):
            expected = list(self.expected)
            expected[index] += 1
            with self.subTest(index=index), self.assertRaises(durable.Rejected):
                self.open(expected_peer=tuple(expected))

    def test_malformed_approval_and_nonconnection_sockets_refuse(self):
        for expected in (None, list(self.expected), (True, 0, 0), (0, 0, 0), (1, -1, 0)):
            with self.subTest(expected=expected), self.assertRaises(durable.Rejected):
                self.open(expected_peer=expected)
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as datagram, self.assertRaises(durable.Rejected):
            self.open(sock=datagram)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unconnected, self.assertRaises(durable.Rejected):
            self.open(sock=unconnected)

    def test_missing_peerpidfd_support_refuses_without_numeric_fallback_or_leak(self):
        original = socket.socket.getsockopt
        reached = []
        def unsupported(sock, level, option, *args):
            if level == socket.SOL_SOCKET and option == 77:
                reached.append(option)
                raise OSError(errno.ENOPROTOOPT, "synthetic-old-kernel")
            return original(sock, level, option, *args)
        before = set(os.listdir("/proc/self/fd"))
        with patch.object(socket.socket, "getsockopt", unsupported), patch.object(os, "pidfd_open") as lookup:
            with self.assertRaises(durable.Rejected):
                self.open()
        lookup.assert_not_called()
        self.assertEqual(reached, [77])
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_wrong_peerpidfd_is_not_replaced_by_a_matching_numeric_lookup(self):
        original = socket.socket.getsockopt
        with open("/dev/null", "rb") as stream:
            def wrong(sock, level, option, *args):
                if level == socket.SOL_SOCKET and option == 77:
                    return struct.pack("i", os.dup(stream.fileno()))
                return original(sock, level, option, *args)
            before = set(os.listdir("/proc/self/fd"))
            with patch.object(socket.socket, "getsockopt", wrong), self.assertRaises(durable.Rejected):
                self.open()
            self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_half_close_revokes_even_with_buffered_data_and_live_peer_process(self):
        view = self.open()
        view.observe(deadline=50)
        self.server.sendall(b"buffered-prefix-is-not-liveness")
        self.server.shutdown(socket.SHUT_WR)
        self.assertFalse(process_mounts.wait_for_cancellation(view.pidfd, 0))
        with self.assertRaises(durable.Rejected):
            view.observe(deadline=50)
        self.assertTrue(view.failed)

    def test_original_socket_close_cannot_be_hidden_by_retained_duplicate(self):
        view = self.open()
        view.observe(deadline=50)
        self.client.close()
        with self.assertRaises(durable.Rejected):
            view.observe(deadline=50)
        self.assertTrue(view.failed)

    def test_callback_disconnect_is_rechecked_before_receipt(self):
        def disconnect(*, deadline):
            self.server.shutdown(socket.SHUT_WR)
            return True
        view = self.open(check=disconnect)
        with self.assertRaises(durable.Rejected):
            view.observe(deadline=50)
        self.assertTrue(view.failed)

    def test_disconnect_during_final_kernel_reads_is_rechecked_before_receipt(self):
        view = self.open()
        original_capture = view._capture
        reached = []
        def capture(stack):
            result = original_capture(stack)
            reached.append(True)
            if len(reached) == 2:
                self.client.close()
            return result
        with patch.object(view, "_capture", side_effect=capture), self.assertRaises(durable.Rejected):
            view.observe(deadline=50)
        self.assertEqual(reached, [True, True])

    def test_original_authority_remains_mandatory_and_sticky(self):
        view = self.open()
        self.fenced = False
        with self.assertRaises(durable.Rejected):
            view.observe(deadline=50)
        self.fenced = True
        with self.assertRaises(durable.Rejected):
            view.observe(deadline=50)

    def test_owned_connection_pidfd_and_proc_close_but_borrowed_socket_survives(self):
        view = self.open()
        view.observe(deadline=50)
        owned = (view.pidfd, view.proc, view._connection[1].fileno(), *view._retained)
        self.assertTrue(all(not os.get_inheritable(fd) for fd in owned))
        self.stack.close()
        self.server.sendall(b"still-open")
        self.assertEqual(self.client.recv(32), b"still-open")
        for fd in owned:
            with self.assertRaises(OSError):
                os.fstat(fd)


class DeploymentProcessMountTests(unittest.TestCase):
    def setUp(self):
        self.fx = test_bind_sources.BindSourceTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.observer = self.enterContext(self.fx.open())
        self.pidfd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, self.pidfd)
        self.view = self.enterContext(process_mounts.open_process_mount_view(pid=os.getpid(), pidfd=self.pidfd,
            check=self.fx.fx.check, clock=lambda: self.fx.fx.time))
        template, self.docker = self.fx.gate(self.observer)
        self.gate = deployment.OldDeploymentGate(objects=template.objects, approval=template.approval,
            check=template.check, clock=template.clock, bind_sources=self.observer, daemon_view=self.view)

    def verify(self):
        return self.gate.verify(self.fx.fx.value, deadline=1100)

    def test_socket_derived_view_composes_with_stopped_deployment_guard_without_start_grant(self):
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with client, server, process_mounts.open_peer_mount_view(sock=client,
                expected_peer=(os.getpid(), os.geteuid(), os.getegid()),
                check=self.fx.fx.check, clock=lambda: self.fx.fx.time) as view:
            gate = deployment.OldDeploymentGate(objects=self.gate.objects, approval=self.gate.approval,
                check=self.gate.check, clock=self.gate.clock, bind_sources=self.observer, daemon_view=view)
            receipt = gate.verify(self.fx.fx.value, deadline=1100)
            self.assertIs(receipt["daemon_source_namespace_verified"], True)
            self.assertIs(receipt["start_authorized"], False)
            server.shutdown(socket.SHUT_WR)
            with self.assertRaises(durable.Rejected):
                gate.verify(self.fx.fx.value, deadline=1100)

    def test_fresh_namespace_observations_supplement_but_do_not_authorize_start(self):
        with patch.object(self.view, "observe", wraps=self.view.observe) as observe:
            receipt = self.verify()
        self.assertEqual(observe.call_count, 6)
        self.assertIs(receipt["bind_source_baseline_verified"], True)
        self.assertIs(receipt["daemon_source_namespace_verified"], True)
        self.assertIs(receipt["start_authorized"], False)
        self.assertEqual(len(self.docker.calls), 8)

    def test_final_namespace_callback_cannot_hide_running_object(self):
        original, reached = self.view.observe, []
        def observe(*, deadline):
            result = original(deadline=deadline)
            reached.append(True)
            if len(reached) == 6:
                self.docker.state.update(running=True, status="running")
            return result
        with patch.object(self.view, "observe", side_effect=observe), self.assertRaises(durable.Rejected):
            self.verify()
        self.assertEqual(len(reached), 6)
        self.assertEqual(len(self.docker.calls), 7)

    def test_namespace_option_requires_baseline_source_observer(self):
        with self.assertRaises(durable.Rejected):
            deployment.OldDeploymentGate(objects=self.gate.objects, approval=self.gate.approval,
                check=self.gate.check, clock=self.gate.clock, daemon_view=self.view)

    def test_source_only_receipt_does_not_claim_daemon_namespace(self):
        gate, _ = self.fx.gate(self.observer)
        self.assertIs(gate.verify(self.fx.fx.value, deadline=1100)["daemon_source_namespace_verified"], False)

    def test_source_callback_namespace_loss_cannot_pass(self):
        original = self.observer.verify_bind_sources
        reached = []
        def sources(*args, **kwargs):
            result = original(*args, **kwargs)
            reached.append(True)
            self.view.closed = True
            return result
        with patch.object(self.observer, "verify_bind_sources", side_effect=sources), self.assertRaises(durable.Rejected):
            self.verify()
        self.assertEqual(reached, [True])

    def test_view_removal_before_one_shot_start_refuses(self):
        oracle = test_bind_sources.test_deployment.Oracle()
        oracle.receipt["baseline_sha256"] = self.fx.fx.pin
        boundary = deployment.RecoveredDeploymentBoundary(oracle, self.gate)
        receipt = boundary.verify_baseline_stopped(self.fx.fx.value, deadline=1100)
        self.gate.daemon_view = None
        with self.assertRaises(durable.Rejected):
            boundary.start_old(self.fx.fx.value, receipt, deadline=1100)
        self.assertEqual(oracle.starts, 0)

    def test_final_daemon_read_cannot_remove_view(self):
        reached = []
        def change(argv):
            if len(self.docker.calls) == 8:
                reached.append(True)
                self.gate.daemon_view = None
        self.docker.hook = change
        with self.assertRaises(durable.Rejected):
            self.verify()
        self.assertEqual(reached, [True])
