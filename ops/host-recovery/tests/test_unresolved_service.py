"""Real CLI/lock/signals/local alerts; no installed manager/daemon/full fence."""
from contextlib import contextmanager
import copy
import errno
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

from host_recovery import alert, durable, unresolved_service, worker
from test_alert import NOTICE
from test_installation import approve
import test_broker

ROOT = Path(__file__).resolve().parent.parent


class UnresolvedServiceTests(unittest.TestCase):
    def setUp(self):
        self.case = test_broker.BrokerTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.endpoint = self.case.installation.root / "alerts"
        self.receipts = self.case.installation.root / "notices"
        self.endpoint.mkdir(mode=0o700)
        self.receipts.mkdir(mode=0o700)
        self.listener = alert.AlertListener(str(self.endpoint / "alert.sock"), "synthetic-route",
            sender_uid=os.geteuid(), capacity=64, max_peers=4, peer_seconds=1.)
        self.addCleanup(self.listener.close)
        self.stop_read, self.stop_write = os.pipe2(os.O_CLOEXEC)
        self.addCleanup(os.close, self.stop_read)
        self.addCleanup(os.close, self.stop_write)
        self.admitted = threading.Event()
        original = self.listener._request
        def request(value):
            reply = original(value)
            if value.get("kind") == "notice":
                self.admitted.set()
            return reply
        self.listener._request = request
        self.thread = threading.Thread(target=self.listener.serve, args=(self.stop_read,), daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.end = time.monotonic() + 30.

    def stop(self):
        if self.thread is not None:
            os.write(self.stop_write, b"!")
            self.thread.join(5)
            self.assertFalse(self.thread.is_alive())
            self.thread = None

    def alerts(self, **changes):
        args = dict(endpoint=approve(self.endpoint), receipts=approve(self.receipts),
            route_id="synthetic-route", listener_uid=os.geteuid(), instance_id=self.listener.instance_id,
            deadline=self.end)
        args.update(changes)
        return unresolved_service.ServiceAlerts(**args)

    def test_real_notice_persistence_and_volatile_admission_are_distinct(self):
        owner = self.alerts()
        result = durable.notify(NOTICE, owner.persist, owner.transport)
        self.assertTrue(result["receipt_persisted"])
        self.assertTrue(result["transport_delivered"])
        self.stop()
        self.assertEqual(self.listener.drain(), NOTICE)
        self.assertIsNone(self.listener.drain())
        saved = self.receipts / ("notice-" + durable.digest(durable.canonical(NOTICE)) + ".json")
        self.assertEqual(saved.read_bytes(), durable.canonical(NOTICE))
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        self.assertEqual(owner.status(), {"receipt_count": 1, "transport_attempt_count": 1,
            "volatile_admission_count": 1, "listener_instance_verified": True,
            "external_delivery_verified": False, "human_acknowledged": False})

    def test_every_reached_storage_fault_still_attempts_real_local_transport(self):
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point):
                    receipts = self.receipts / (str(code) + "-" + point)
                    receipts.mkdir(mode=0o700)
                    reached = []
                    def fault(actual):
                        if actual == point:
                            reached.append(actual)
                            raise OSError(code, "synthetic-private-error")
                    owner = self.alerts(receipts=approve(receipts), fault=fault)
                    result = durable.notify(NOTICE, owner.persist, owner.transport)
                    self.assertEqual(reached, [point])
                    self.assertFalse(result["receipt_persisted"])
                    self.assertTrue(result["transport_delivered"])
                    self.assertEqual(owner.status()["receipt_count"], 0)
                    self.assertEqual(owner.status()["volatile_admission_count"], 1)
        self.stop()
        self.assertEqual(len(self.listener.inbox), 12)

    def test_preexisting_receipt_and_stage_are_never_overwritten(self):
        owner = self.alerts()
        name = "notice-" + durable.digest(durable.canonical(NOTICE)) + ".json"
        for path in (self.receipts / name, self.receipts / (".stage-" + name)):
            path.write_bytes(b"retained-uncertain-evidence")
            path.chmod(0o600)
            before = path.stat().st_ino
            with self.assertRaises(durable.Rejected):
                owner.persist(NOTICE)
            self.assertEqual(path.read_bytes(), b"retained-uncertain-evidence")
            self.assertEqual(path.stat().st_ino, before)

    def test_wrong_pinned_listener_instance_never_admits_or_rechallenges(self):
        owner = self.alerts(instance_id="different-instance")
        with self.assertRaises(durable.Rejected):
            owner.transport(NOTICE)
        owner.instance_id = self.listener.instance_id
        other = {**NOTICE, "recovery_error": "recovery-restore-failed"}
        with self.assertRaises(durable.Rejected):
            owner.transport(other)
        self.assertFalse(owner.challenge_verified)
        self.assertFalse(self.listener.inbox)

    def test_context_exit_after_deadline_cannot_record_persistence_or_admission(self):
        original = unresolved_service.open_approved_directory
        for operation in ("persist", "transport"):
            now = [1000.]
            owner = self.alerts(clock=lambda: now[0], deadline=1001.)
            @contextmanager
            def slow_exit(approval):
                with original(approval) as directory:
                    yield directory
                now[0] = 1002.
            with self.subTest(operation=operation):
                with patch.object(unresolved_service, "open_approved_directory", side_effect=slow_exit), \
                        self.assertRaises(durable.Rejected):
                    getattr(owner, operation)(NOTICE)
                self.assertEqual(owner.status()["receipt_count"], 0)
                self.assertEqual(owner.status()["volatile_admission_count"], 0)

    def test_killed_helper_is_reaped_during_hold_not_only_when_service_returns(self):
        commands = unresolved_service.LocalCommands()
        previous = signal.getsignal(signal.SIGCHLD)
        def service(approval, **kw):
            proc = subprocess.Popen([sys.executable, "-I", "-c", "pass"])
            self.addCleanup(proc.wait)
            commands.pending.append(proc)
            # Observe exit without reaping. This owned child is now a zombie;
            # the runner's SIGCHLD owner must reap it without ending the hold.
            os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT)
            os.kill(os.getpid(), signal.SIGCHLD)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(commands.pending, [])
            return {"start_permission": False}
        with patch.object(unresolved_service, "LocalCommands", return_value=commands), \
                patch.object(unresolved_service, "run_supervisor", side_effect=service):
            unresolved_service.run_unresolved(self.case.fixture.approval,
                endpoint=self.case.endpoint_approval, alerts=self.alerts(), deadline=self.end)
        self.assertEqual(signal.getsignal(signal.SIGCHLD), previous)

    def test_same_notice_is_never_retried_after_ack_or_uncertain_send(self):
        owner = self.alerts()
        self.assertTrue(owner.transport(NOTICE))
        with self.assertRaises(durable.Rejected):
            owner.transport(copy.deepcopy(NOTICE))
        self.stop()
        self.assertEqual(len(self.listener.inbox), 1)

    def test_missing_listener_failure_stays_sticky_for_distinct_later_notices(self):
        self.stop()
        self.listener.close()
        owner = self.alerts()
        for notice in (NOTICE, {**NOTICE, "recovery_error": "recovery-restore-failed"}):
            result = durable.notify(notice, owner.persist, owner.transport)
            self.assertTrue(result["receipt_persisted"])
            self.assertFalse(result["transport_delivered"])
        self.assertTrue(owner.challenge_attempted)
        self.assertFalse(owner.challenge_verified)
        self.assertEqual(owner.status()["volatile_admission_count"], 0)

    def test_clock_expiry_never_renews_alert_window_or_claims_admission(self):
        now = [1000.]
        owner = self.alerts(clock=lambda: now[0], deadline=1001.)
        now[0] = 1001.
        result = durable.notify(NOTICE, owner.persist, owner.transport)
        self.assertFalse(result["receipt_persisted"])
        self.assertFalse(result["transport_delivered"])
        self.assertFalse(owner.challenge_attempted)
        self.assertEqual(owner.timer.deadline, 1001.)

    def test_changed_alert_directory_identity_cannot_redirect_delivery(self):
        owner = self.alerts()
        self.endpoint.rename(self.endpoint.with_name("old-alerts"))
        self.endpoint.mkdir(mode=0o700)
        with self.assertRaises(durable.Rejected):
            owner.transport(NOTICE)
        self.assertFalse(self.listener.inbox)

    def test_runner_has_fixed_deny_boundaries_and_retains_command_owner(self):
        transport = Mock()
        def service(approval, **kw):
            self.assertFalse(kw["fence"]({}, deadline=1.))
            self.assertFalse(kw["result_oracle"]({}, {}, deadline=1.))
            self.assertIs(kw["commands"], transport)
            self.assertFalse(worker.cancellation_pending(kw["cancel_fd"]))
            return {"start_permission": False}
        with patch.object(unresolved_service, "LocalCommands", return_value=transport), \
                patch.object(unresolved_service, "run_supervisor", side_effect=service):
            result = unresolved_service.run_unresolved(self.case.fixture.approval,
                endpoint=self.case.endpoint_approval, alerts=self.alerts(), deadline=self.end)
        self.assertEqual(result["operation"], "hold_without_execution_authority")
        self.assertFalse(result["start_permission"])
        transport.reap.assert_called_once_with()

    def test_runner_reaps_on_failure_and_rejects_overlapping_roots_before_service(self):
        transport = Mock()
        with patch.object(unresolved_service, "LocalCommands", return_value=transport), \
                patch.object(unresolved_service, "run_supervisor", side_effect=OSError("private")):
            with self.assertRaises(OSError):
                unresolved_service.run_unresolved(self.case.fixture.approval,
                    endpoint=self.case.endpoint_approval, alerts=self.alerts(), deadline=self.end)
        transport.reap.assert_called_once_with()
        with patch.object(unresolved_service, "run_supervisor") as run:
            with self.assertRaises(durable.Rejected):
                unresolved_service.run_unresolved(self.case.fixture.approval,
                    endpoint=approve(self.endpoint), alerts=self.alerts(), deadline=self.end)
            run.assert_not_called()

    def cli(self, **changes):
        options = {"approval": str(self.case.fixture.path), "sha256": self.case.fixture.pin,
            "uid": os.geteuid(), "gid": os.getegid(), "deadline": self.end,
            "alert-deadline": self.end, "alert-route": "synthetic-route",
            "listener-uid": os.geteuid(), "listener-instance": self.listener.instance_id}
        for name, path in (("endpoint", self.case.endpoint), ("alert-endpoint", self.endpoint),
                           ("alert-receipts", self.receipts)):
            options.update({name: str(path), name + "-device": path.stat().st_dev,
                            name + "-inode": path.stat().st_ino})
        options.update(changes)
        argv = [sys.executable, "-I", str(ROOT / "supervise.py")]
        for key, value in options.items():
            argv.extend(("--" + key, str(value)))
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            child.stdout.close()
            child.stderr.close()
        self.addCleanup(cleanup)
        return child

    def test_actual_cli_manager_failure_holds_lock_and_sigterm_exits_unresolved(self):
        before = self.case.original()
        child = self.cli()
        self.assertTrue(self.admitted.wait(5), "CLI did not attempt its local alert")
        self.case.locked()
        self.assertIsNone(child.poll())
        child.send_signal(signal.SIGTERM)
        output, error = child.communicate(timeout=5)
        self.assertEqual((child.returncode, output, error), (3, b"", b""))
        self.case.unlocked()
        self.assertEqual(before, self.case.original())
        self.assertFalse((self.case.installation.journal / "reconcile-worker.json").exists())
        self.stop()
        self.assertEqual(self.listener.drain()["outcome"], "recovery_unresolved")

    def test_actual_cli_sigterm_interrupts_stalled_alert_challenge(self):
        stalled = self.case.installation.root / "stalled-alert"
        stalled.mkdir(mode=0o700)
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            listener.bind(str(stalled / "alert.sock"))
            (stalled / "alert.sock").chmod(0o600)
            listener.listen(1)
            child = self.cli(**{"alert-endpoint": str(stalled),
                "alert-endpoint-device": stalled.stat().st_dev,
                "alert-endpoint-inode": stalled.stat().st_ino})
            with selectors.DefaultSelector() as ready:
                ready.register(listener, selectors.EVENT_READ)
                self.assertTrue(ready.select(5), "CLI did not connect to stalled listener")
            connection, _ = listener.accept()
            with connection:
                with selectors.DefaultSelector() as ready:
                    ready.register(connection, selectors.EVENT_READ)
                    self.assertTrue(ready.select(5), "challenge not sent")
                self.assertEqual(durable.decode(connection.recv(4096))["kind"], "challenge")
                self.case.locked()
                child.send_signal(signal.SIGTERM)
                output, error = child.communicate(timeout=2)
                self.assertEqual((child.returncode, output, error), (3, b"", b""))
        self.case.unlocked()

    def test_actual_cli_sigkill_keeps_durable_intent_and_no_terminal(self):
        before = self.case.original()
        child = self.cli()
        self.assertTrue(self.admitted.wait(5))
        self.case.locked()
        child.kill()
        output, error = child.communicate(timeout=5)
        self.assertEqual((child.returncode, output, error), (-signal.SIGKILL, b"", b""))
        self.case.unlocked()
        self.assertEqual(before, self.case.original())
        self.assertFalse((self.case.installation.journal / "terminal.json").exists())

    def test_actual_cli_pin_failure_is_silent_and_cannot_claim_or_delete_evidence(self):
        before = self.case.original()
        child = self.cli(sha256="0" * 64)
        output, error = child.communicate(timeout=5)
        self.assertEqual((child.returncode, output, error), (1, b"", b""))
        self.case.unlocked()
        self.assertEqual(before, self.case.original())
        self.assertEqual(list(self.receipts.iterdir()), [])

    def test_no_execute_flag_and_argument_errors_never_echo_untrusted_content(self):
        result = subprocess.run([sys.executable, "-I", str(ROOT / "supervise.py"),
            "--execute", "private-secret"], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"host-recovery-supervisor: invalid-arguments\n")


class CommandCancellationTests(unittest.TestCase):
    def test_shutdown_cancels_helper_output_wait_and_retains_pending_owner(self):
        commands = unresolved_service.LocalCommands()
        with unresolved_service.shutdown_pipe(reap=commands.reap) as cancel_fd:
            commands.cancel_fd = cancel_fd
            script = "import os,signal;os.kill(os.getppid(),signal.SIGTERM);r,w=os.pipe();os.read(r,1)"
            with self.assertRaisesRegex(durable.Rejected, "command-cancelled"):
                commands.run((sys.executable, "-I", "-c", script), deadline=time.monotonic() + 30.)
            self.assertTrue(worker.cancellation_pending(cancel_fd))
        for proc in commands.pending:
            proc.wait(timeout=5)
        commands.reap()
        self.assertEqual(commands.pending, [])

    def test_shutdown_after_stdout_eof_cancels_pidfd_wait(self):
        commands = unresolved_service.LocalCommands()
        original = os.pidfd_open
        reached = []
        def opening(pid, flags):
            fd = original(pid, flags)
            reached.append(pid)
            os.kill(os.getpid(), signal.SIGTERM)
            return fd
        with unresolved_service.shutdown_pipe(reap=commands.reap) as cancel_fd:
            commands.cancel_fd = cancel_fd
            script = "import os;os.close(1);r,w=os.pipe();os.read(r,1)"
            with patch.object(os, "pidfd_open", side_effect=opening), \
                    self.assertRaisesRegex(durable.Rejected, "command-cancelled"):
                commands.run((sys.executable, "-I", "-c", script), deadline=time.monotonic() + 30.)
            self.assertEqual(len(reached), 1)
        for proc in commands.pending:
            proc.wait(timeout=5)
        commands.reap()
        self.assertEqual(commands.pending, [])

    def test_reap_keeps_pending_list_identity_for_interrupted_append(self):
        commands = unresolved_service.LocalCommands()
        pending = commands.pending
        commands.reap()
        self.assertIs(commands.pending, pending)


class ShutdownPipeTests(unittest.TestCase):
    def test_repeated_signals_and_full_pipe_cancel_without_blocking_and_restore_handlers(self):
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
        with unresolved_service.shutdown_pipe() as fd:
            for sig in (signal.SIGTERM, signal.SIGINT):
                stop = signal.getsignal(sig)
                for _ in range(10000):
                    stop(sig, None)
            self.assertTrue(worker.cancellation_pending(fd))
        with self.assertRaises(OSError):
            os.fstat(fd)
        self.assertEqual({sig: signal.getsignal(sig) for sig in previous}, previous)
