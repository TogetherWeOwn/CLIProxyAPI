"""Actual lock/process/IPC lifecycle; SCRIPTED manager/fence/oracle boundaries."""
from dataclasses import asdict
import errno
import fcntl
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import broker, durable, launch, outcomes, service, worker
import test_broker

ROOT = Path(__file__).resolve().parent.parent


SERVICE_CHILD = r'''
import json,os,signal,sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
sys.path[:0]=[sys.argv[1],sys.argv[1]+'/tests']
from host_recovery import broker,durable,launch,outcomes,service,worker
from host_recovery.installation import DirectoryApproval
import test_broker
value=json.loads(sys.argv[2])
approval=launch.parse_launch(durable.canonical(value['approval']))
case=test_broker.BrokerTests()
case.fixture=SimpleNamespace(approval=approval)
case.installation=SimpleNamespace(journal=Path(approval.installation.journal.path))
case.endpoint=Path(value['endpoint']['path'])
case.owner=value['owner']
case.notices=[];case.deadlines=[];case.listeners=[]
case.process=None;case.pid=123;case.invocation='c'*32;case.fenced=True
case.on_accept=lambda process:None
case.on_fence=lambda:None
case.after_reply=lambda process:None
identity=Mock()
identity.bootstrap.return_value={'owner':case.owner}
identity.observe_owner.return_value=case.owner
read,write=os.pipe2(os.O_NONBLOCK|os.O_CLOEXEC)
def stop(*args):
    os.write(write,b'stop')
for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,stop)
real_select=service.select.select
def wait(*args):
    if len(args)==4 and args[3]!=0:
        print('READY',flush=True)
    return real_select(*args)
def listener(*args,**kwargs):
    if value['mode']=='idle':
        result=worker.WorkerListener(*args,**kwargs)
        print('READY',flush=True)
        return result
    kwargs.pop('cancel_fd')
    return case.listener(*args,**kwargs)
with patch.object(launch,'SystemdSupervisorIdentity',return_value=identity), \
     patch.object(broker,'SystemdRecoveryJobs',return_value=SimpleNamespace(observe=case.observe,observe_worker=case.observe_worker)), \
     patch.object(broker,'WorkerListener',side_effect=listener), \
     patch.object(service.select,'select',side_effect=wait):
    result=service.run_supervisor(approval,endpoint=DirectoryApproval(**value['endpoint']),deadline=1170.,
        fence=case.fence,result_oracle=lambda intent,result,**kw:outcomes.expected_oracle(intent,result),
        persist_alert=lambda n:None,transport_alert=lambda n:True,commands=SimpleNamespace(run=lambda *a,**kw:b''),
        cancel_fd=read,clock=lambda:1050.,boot_id=lambda:case.owner['boot_id'])
print(json.dumps(result),flush=True)
os.close(read);os.close(write)
'''


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.case = test_broker.BrokerTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.read, self.write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self.addCleanup(os.close, self.read)
        self.addCleanup(os.close, self.write)
        self.held = 0
        self.on_hold = lambda: None

    def hold(self, reads, writes, exceptions, timeout=None):
        self.assertEqual((reads, writes, exceptions), ([self.read], [], []))
        self.held += 1
        self.case.locked()
        if self.case.process is not None:
            self.assertTrue(self.case.process.closed)
            with self.assertRaises(durable.Rejected):
                self.case.process.manager.observe_owner(self.case.owner, deadline=1170.)
        if self.on_hold() is not False:
            os.write(self.write, b"stop")
            return ([self.read], [], [])
        return ([], [], [])

    def listener(self, *args, cancel_fd, **kwargs):
        self.assertEqual(cancel_fd, self.read)
        return self.case.listener(*args, **kwargs)

    def run_service(self, **changes):
        args = dict(endpoint=self.case.endpoint_approval, deadline=1170., fence=self.case.fence,
            result_oracle=lambda intent, result, **kw: outcomes.expected_oracle(intent, result),
            persist_alert=self.case.persist, transport_alert=lambda n: self.case.notices.append(n) or True,
            commands=SimpleNamespace(run=lambda *a, **kw: b""), cancel_fd=self.read,
            clock=lambda: self.case.fixture.now, boot_id=lambda: self.case.owner["boot_id"])
        args.update(changes)
        real_select = service.select.select
        def select(*args):
            return real_select(*args) if len(args) == 4 and args[3] == 0 else self.hold(*args)
        with patch.object(launch, "SystemdSupervisorIdentity", return_value=self.case.identity), \
                patch.object(broker, "SystemdRecoveryJobs", return_value=self.case.job), \
                patch.object(broker, "WorkerListener", side_effect=self.listener), \
                patch.object(service.select, "select", side_effect=select):
            # cancellation_pending also uses select; let real nonblocking probes
            # run unchanged while instrumenting only the passive blocking hold.
            return service.run_supervisor(self.case.fixture.approval, **args)

    def assert_unsettled(self, result):
        self.assertEqual(result["state"], "shutdown_unresolved")
        for key in ("installation_settled", "start_permission", "recovery_completed", "production_acceptance"):
            self.assertIs(result[key], False)
        self.case.unlocked()

    def test_result_keeps_lock_and_revokes_session_before_passive_hold(self):
        before = self.case.original()
        result = self.run_service()
        self.assertTrue(result["worker_result_observed"])
        self.assertIsNone(result["exchange_error"])
        self.assertEqual(self.held, 1)
        self.assertEqual(before, self.case.original())
        self.assertTrue(all(value.closed for value in self.case.listeners))
        self.assert_unsettled(result)
        self.assertEqual(self.case.notices, [])

    def test_passive_hold_outlives_original_deadline_without_retry_or_renewal(self):
        self.on_hold = lambda: setattr(self.case.fixture, "now", 9999.)
        result = self.run_service()
        self.assertTrue(result["worker_result_observed"])
        self.assertEqual(len(self.case.listeners), 1)
        self.assertTrue(all(end == 1170. for end in self.case.deadlines))
        self.assert_unsettled(result)

    def test_original_deadline_alarm_escalates_once_without_unlock_or_retry(self):
        def advance():
            if self.held == 1:
                self.case.fixture.now = 1170.
                return False
        self.on_hold = advance
        reached = []
        def persist(notice):
            reached.append(notice["recovery_error"])
            raise OSError(errno.ENOSPC, "scripted disk fault")
        result = self.run_service(persist_alert=persist)
        self.assertTrue(result["hold_deadline_missed"])
        self.assertTrue(result["worker_result_observed"])
        self.assertEqual(self.held, 2)
        self.assertEqual(reached, ["supervisor-expired-continuation-required"])
        self.assertEqual([n["recovery_error"] for n in self.case.notices], reached)
        self.assertEqual(len(self.case.listeners), 1)
        self.assert_unsettled(result)

    def test_hold_clock_uncertainty_is_not_labelled_measured_expiry(self):
        def change():
            if self.held == 1:
                self.case.fixture.now = float("nan")
                return False
        self.on_hold = change
        result = self.run_service()
        self.assertIsNone(result["hold_deadline_missed"])
        self.assertEqual(self.held, 2)
        self.assertEqual([n["recovery_error"] for n in self.case.notices],
                         ["supervisor-clock-continuation-required"])
        self.assert_unsettled(result)

    def test_fence_denial_and_alert_disk_error_still_hold_and_attempt_transport(self):
        self.case.fenced = False
        reached = []
        def persist(notice):
            reached.append(True)
            raise OSError(errno.ENOSPC, "scripted disk fault")
        result = self.run_service(persist_alert=persist)
        self.assertFalse(result["worker_result_observed"])
        self.assertEqual(result["exchange_error"], "supervisor-worker-result-unconfirmed")
        self.assertTrue(reached)
        self.assertTrue(self.case.notices)
        self.assertEqual(self.held, 1)
        self.assertFalse((self.case.installation.journal / "reconcile-worker.json").exists())
        self.assert_unsettled(result)

    def test_bootstrap_failure_holds_preacquired_lock_without_opening_listener(self):
        def bootstrap(**kw):
            self.case.locked()
            raise durable.Rejected("scripted-manager-loss")
        self.case.identity.bootstrap.side_effect = bootstrap
        result = self.run_service()
        self.assertEqual(self.case.listeners, [])
        self.assertEqual(self.held, 1)
        self.assertFalse(result["worker_result_observed"])
        self.assertTrue(self.case.notices)
        self.assert_unsettled(result)

    def test_storage_fault_reached_during_result_keeps_request_and_no_observed_receipt(self):
        reached = []
        def fault(point):
            if point == "file-fsync":
                reached.append(point)
                raise OSError(errno.EIO, "scripted result fsync")
        self.case.after_reply = lambda process: setattr(process.log, "fault", fault)
        result = self.run_service()
        self.assertEqual(reached, ["file-fsync"])
        self.assertFalse(result["worker_result_observed"])
        self.assertFalse((self.case.installation.journal / "reconcile-result-observed.json").exists())
        self.assertEqual(self.held, 1)
        self.assertTrue(self.case.notices)
        self.assert_unsettled(result)

    def test_oracle_refusal_is_unresolved_and_never_retried(self):
        result = self.run_service(result_oracle=lambda *a, **kw: False)
        self.assertFalse(result["worker_result_observed"])
        self.assertEqual(len(self.case.listeners), 1)
        self.assertEqual(self.held, 1)
        self.assertTrue(self.case.notices)
        self.assert_unsettled(result)

    def test_already_cancelled_does_not_bootstrap_claim_or_alert(self):
        os.write(self.write, b"stop")
        result = self.run_service()
        self.assertEqual(self.held, 0)
        self.case.identity.bootstrap.assert_not_called()
        self.assertEqual(self.case.listeners, [])
        self.assertEqual(self.case.notices, [])
        self.assert_unsettled(result)

    def test_invalid_policy_refuses_before_acquiring_or_calling_manager(self):
        for change in ({"fence": None}, {"result_oracle": None}, {"commands": None},
                       {"transport_alert": None}, {"cancel_fd": -1}, {"cancel_fd": True}):
            with self.subTest(change=change), self.assertRaises(durable.Rejected):
                self.run_service(**change)
        self.case.identity.bootstrap.assert_not_called()
        self.case.unlocked()

    def test_endpoint_preexistence_is_not_unlinked_or_retried(self):
        def unavailable(*a, **kw):
            raise FileExistsError("scripted retained socket")
        self.case.listener = unavailable
        result = self.run_service()
        self.assertFalse(result["worker_result_observed"])
        self.assertEqual(self.held, 1)
        self.assert_unsettled(result)

    def test_changed_original_record_refuses_normal_shutdown_after_holding(self):
        def tamper():
            self.case.installation.journal.rename(self.case.installation.root / "moved-journal")
            self.case.installation.journal.mkdir(mode=0o700)
        self.on_hold = tamper
        with self.assertRaisesRegex(durable.Rejected, "service-installation-unconfirmed"):
            self.run_service()
        self.assertEqual(self.held, 1)

    def service_child(self, mode):
        payload = {"approval": {"schema": "host-recovery-launch-v1", **asdict(self.case.fixture.approval)},
                   "endpoint": asdict(self.case.endpoint_approval), "owner": self.case.owner, "mode": mode}
        child = subprocess.Popen([sys.executable, "-I", "-c", SERVICE_CHILD, str(ROOT), json.dumps(payload)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            child.stdout.close()
            child.stderr.close()
        self.addCleanup(cleanup)
        with selectors.DefaultSelector() as wait:
            wait.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(wait.select(5), "service did not reach its lifecycle boundary")
        self.assertEqual(child.stdout.readline().strip(), "READY")
        self.case.locked()
        return child

    def test_actual_sigterm_exits_passive_hold_without_settling_or_replaying(self):
        original = self.case.original()
        child = self.service_child("result")
        self.assertTrue((self.case.installation.journal / "reconcile-result-observed.json").exists())
        child.send_signal(signal.SIGTERM)
        output, error = child.communicate(timeout=5)
        self.assertEqual((child.returncode, error), (0, ""))
        result = json.loads(output)
        self.assertTrue(result["worker_result_observed"])
        self.assertEqual(original, self.case.original())
        self.assert_unsettled(result)

    def test_actual_sigkill_releases_kernel_lock_but_leaves_original_durable_latch(self):
        original = self.case.original()
        child = self.service_child("result")
        child.kill()
        output, error = child.communicate(timeout=5)
        self.assertEqual((child.returncode, output, error), (-signal.SIGKILL, "", ""))
        self.assertEqual(original, self.case.original())
        self.assertTrue((self.case.installation.journal / "reconcile-result-observed.json").exists())
        self.case.unlocked()
        # A restart may read the prior claim, but cannot recreate its peer/reply.
        result = self.run_service()
        self.assertFalse(result["worker_result_observed"])
        self.assertEqual(self.case.listeners, [])
        self.assert_unsettled(result)

    def test_actual_sigint_wakes_idle_accept_with_no_worker_or_deadline_reset(self):
        original = self.case.original()
        child = self.service_child("idle")
        child.send_signal(signal.SIGINT)
        output, error = child.communicate(timeout=5)
        self.assertEqual((child.returncode, error), (0, ""))
        result = json.loads(output)
        self.assertFalse(result["worker_result_observed"])
        self.assertEqual(result["exchange_error"], "supervisor-worker-result-unconfirmed")
        self.assertFalse((self.case.installation.journal / "reconcile-worker.json").exists())
        self.assertEqual(original, self.case.original())
        self.assert_unsettled(result)

    def test_status_never_exposes_paths_peer_nonce_or_raw_errors(self):
        self.case.identity.bootstrap.side_effect = ValueError("scripted-private-secret")
        raw = durable.canonical(self.run_service())
        for private in ("scripted-private-secret", str(self.case.installation.root), "fixture-nonce", '"peer"'):
            self.assertNotIn(private.encode(), raw)


class CancellationTests(unittest.TestCase):
    def setUp(self):
        self.case = test_broker.BrokerTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.read, self.write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self.addCleanup(os.close, self.read)
        self.addCleanup(os.close, self.write)

    def test_preexisting_cancellation_never_binds_listener(self):
        os.write(self.write, b"stop")
        path = str(self.case.endpoint / "never.sock")
        with self.assertRaisesRegex(durable.Rejected, "cancelled"):
            worker.WorkerListener(path, worker_uid=os.geteuid(), cancel_fd=self.read)
        self.assertFalse(Path(path).exists())

    def test_readable_cancellation_revokes_live_socket_process_lease(self):
        path = str(self.case.endpoint / "peer.sock")
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            listener.bind(path)
            listener.listen(1)
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
                client.connect(path)
                conn, _ = listener.accept()
                with conn:
                    peer = worker.PeerSession(conn, uid=os.geteuid(), cancel_fd=self.read)
                    try:
                        self.assertTrue(peer.alive())
                        os.write(self.write, b"stop")
                        self.assertFalse(peer.alive())
                        with self.assertRaises(durable.Rejected):
                            peer.reply({"schema": "never"}, deadline=time.monotonic() + 10.)
                        self.assertEqual(os.read(self.read, 4), b"stop")
                    finally:
                        peer.close()

    def test_idle_accept_wakes_on_cancellation_without_peer_or_clock_expiry(self):
        path = str(self.case.endpoint / "idle.sock")
        listener = worker.WorkerListener(path, worker_uid=os.geteuid(), clock=lambda: 1000., cancel_fd=self.read)
        try:
            os.write(self.write, b"stop")
            process = SimpleNamespace(pending_request={"deadline": 1100.}, closed=False, error=None)
            process._fail = lambda *a: setattr(process, "error", "cancelled")
            with self.assertRaises(durable.Rejected):
                listener.accept_once(supervisor=process, observer=None, deadline=1100.)
            self.assertTrue(listener.attempted)
            self.assertEqual(process.error, "cancelled")
        finally:
            listener.close()
