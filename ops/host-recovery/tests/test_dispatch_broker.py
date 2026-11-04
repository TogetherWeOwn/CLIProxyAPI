"""Real dispatch/peer/lock/journal composition; SCRIPTED manager/fence/oracle."""
import copy
from contextlib import contextmanager
from dataclasses import replace
import errno
import fcntl
import json
import os
from pathlib import Path
import pwd
import selectors
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import broker, dispatch, durable, jobs, manager, outcomes, supervisor
from test_installation import approve
from test_manager import encoded, observed
import test_supervisor

ROOT = Path(__file__).resolve().parent.parent
CLIENT = r'''
import json,os,sys
sys.path.insert(0,sys.argv[1])
from host_recovery.worker import WorkerClient
client=WorkerClient(sys.argv[2],supervisor_uid=os.geteuid(),supervisor_pid=int(sys.argv[3]),
    supervisor_owner=json.loads(sys.argv[4]),request_id=sys.argv[5],intent_sha256=sys.argv[6],clock=lambda:1050.)
try:
    claim=client.claim(deadline=1053.,result_provider=lambda claim,**kw:
        {'outcome':'baseline_restored','evidence_sha256':'e'*64})
    print(json.dumps(client.result_receipt),flush=True)
    sys.stdin.readline()
except Exception as failure:
    print(type(failure).__name__,flush=True)
    sys.exit(2)
'''


class DispatchBrokerTests(unittest.TestCase):
    def setUp(self):
        self.case = test_supervisor.SupervisorTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        temp = tempfile.TemporaryDirectory(prefix=".dispatch-broker-", dir=pwd.getpwuid(os.geteuid()).pw_dir)
        self.addCleanup(temp.cleanup)
        self.endpoint = Path(temp.name)
        self.approval = approve(self.endpoint)
        self.children, self.calls, self.oracle_calls = [], [], []
        self.addCleanup(self.stop_children)
        self.on_start = lambda process: None
        self.after_start = lambda child: None
        self.on_show = lambda process: None
        self.on_oracle = lambda process: None
        self.start_reply = b""
        self.start_failure = None
        self.source = CLIENT
        self.deadline = 1053.
        self.closed_listeners = []

    def stop_children(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()

    @contextmanager
    def fresh(self):
        value = DispatchBrokerTests()
        value.setUp()
        try:
            yield value
        finally:
            value.doCleanups()

    def locked(self):
        with durable.directory(self.case.root, private=True) as fd:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def configure(self, process):
        request = copy.deepcopy(process.plan)
        request['deadline'] = min(self.deadline, request['deadline'])
        request.pop('request_id')
        request['request_id'] = durable.digest(durable.canonical(request))
        self.request = request
        self.path = self.endpoint / ('claim-' + request['request_id'] + '.sock')
        self.row = observed(jobs.recovery_unit(request['request_id']), '', '/synthetic/recovery.service')
        self.row.update(ActiveState='inactive', SubState='dead', MainPID='0', ControlGroup='',
                        User=str(os.geteuid()), Group=str(os.getegid()))
        self.binding = jobs.RecoveryJobBinding(request['request_id'], self.row['FragmentPath'], 'f' * 64,
            durable.digest(durable.canonical(manager.static_properties(self.row))))

    def command(self, process, argv, *, deadline):
        self.locked()
        self.calls.append((argv, deadline))
        if 'show' in argv:
            self.on_show(process)
            return encoded(self.row)
        self.assertEqual(argv, ('/synthetic/systemctl', '--no-block', 'start', '--',
                                jobs.recovery_unit(self.request['request_id'])))
        # The durable request and listening socket both precede a fast worker.
        self.assertEqual(durable.decode((self.case.root / 'reconcile-request.json').read_bytes()), self.request)
        self.assertTrue(self.path.is_socket())
        self.assertFalse((self.case.root / 'reconcile-enqueued.json').exists())
        self.on_start(process)
        child = subprocess.Popen([sys.executable, '-I', '-c', self.source, str(ROOT), str(self.path),
            str(os.getpid()), json.dumps(process.owner), self.request['request_id'], process.intent_sha256],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(child)
        self.row.update(ActiveState='active', SubState='running', MainPID=str(child.pid),
                        ControlGroup='/synthetic/recovery.service', InvocationID='b' * 32)
        self.after_start(child)
        if self.start_failure:
            raise self.start_failure
        return self.start_reply

    def oracle(self, process, intent, result, *, deadline):
        self.locked()
        self.oracle_calls.append(deadline)
        self.on_oracle(process)
        return outcomes.expected_oracle(intent, result)

    def serve(self, process, **kwargs):
        transport = SimpleNamespace(run=lambda *args, **kw: self.command(process, *args, **kw))
        real_dispatch, real_jobs, real_listener = dispatch.SystemdRecoveryDispatch, jobs.SystemdRecoveryJobs, broker.WorkerListener

        def create_dispatch(**kw):
            return real_dispatch(**kw, read_fragment_hash=lambda _: 'f' * 64)

        def create_jobs(**kw):
            return real_jobs(**kw, read_fragment_hash=lambda _: 'f' * 64,
                             read_process_cgroup=lambda _: '/synthetic/recovery.service')

        def listener(*args, **kw):
            value = real_listener(*args, **kw)
            self.closed_listeners.append(value)
            return value

        args = dict(endpoint=self.approval, binding=self.binding, systemctl='/synthetic/systemctl',
                    deadline=self.deadline, commands=transport,
                    result_oracle=lambda *a, **kw: self.oracle(process, *a, **kw))
        args.update(kwargs)
        with patch.object(broker, 'SystemdRecoveryDispatch', side_effect=create_dispatch), \
                patch.object(broker, 'SystemdRecoveryJobs', side_effect=create_jobs), \
                patch.object(broker, 'WorkerListener', side_effect=listener):
            return broker.dispatch_claim(process, **args)

    def starts(self):
        return [argv for argv, _ in self.calls if 'start' in argv]

    def read(self, child):
        with selectors.DefaultSelector() as wait:
            wait.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(wait.select(5), 'worker did not report')
        return child.stdout.readline()

    def test_listener_dispatch_claim_and_result_share_original_owner_and_lock(self):
        with self.case.open() as process:
            self.configure(process)
            state = self.serve(process)
            self.assertEqual(state['state'], 'recovery_result_observed_unsettled')
            self.assertTrue(state['worker_result_observed'])
            self.case.assert_fenced(state)
            self.assertFalse(state['installation_settled'])
            self.locked()
            self.assertFalse(process.closed)
            self.assertEqual(len(self.starts()), 1)
            self.assertEqual(self.case.enqueues(), [])
            self.assertEqual(self.oracle_calls, [1053.])
            receipt = json.loads(self.read(self.children[0]))
            self.assertTrue(receipt['observed'])
            self.assertFalse(receipt['installation_settled'])
            self.assertFalse(receipt['start_permission'])
            self.assertTrue(all(deadline == 1053. for _, deadline in self.calls))
            self.assertEqual((self.case.root / 'intent.json').read_bytes(), self.case.original)
            self.assertEqual(process.worker_claim['peer']['pid'], self.children[0].pid)
            self.assertTrue(all(value.closed for value in self.closed_listeners))
            with self.assertRaises(durable.Rejected):
                self.serve(process)
            self.assertEqual(len(self.starts()), 1)
        self.assertTrue(self.path.is_socket(), 'ambiguous endpoint must not be unlinked')

    def test_fast_worker_connects_before_enqueue_reply_without_broker_startup_race(self):
        self.source = CLIENT.replace('try:\n',
            "original=client._verify_identity\ndef connected(session,deadline):\n"
            "    print('CONNECTED',flush=True)\n    return original(session,deadline)\n"
            "client._verify_identity=connected\ntry:\n", 1)
        self.after_start = lambda child: self.assertEqual(self.read(child), b'CONNECTED\n')
        with self.case.open() as process:
            self.configure(process)
            self.assertTrue(self.serve(process)['worker_result_observed'])
            self.assertTrue(json.loads(self.read(self.children[0]))['observed'])
            self.assertEqual(len(self.starts()), 1)

    def test_expired_or_cross_boot_after_enqueue_never_accepts_claim(self):
        for kind in ('clock', 'boot'):
            with self.subTest(kind=kind), self.fresh() as f, f.case.open() as process:
                f.configure(process)
                f.on_start = lambda _: setattr(f.case, 'now' if kind == 'clock' else 'boot',
                                               1053. if kind == 'clock' else 'other-boot')
                with f.assertRaises(durable.Rejected):
                    f.serve(process)
                f.assertEqual(len(f.starts()), 1)
                f.assertFalse((f.case.root / 'reconcile-enqueued.json').exists())
                f.assertFalse((f.case.root / 'reconcile-worker.json').exists())
                f.assertTrue(f.case.notices)

    def test_missing_independent_oracle_refuses_before_endpoint_or_dispatch(self):
        with self.case.open() as process:
            self.configure(process)
            with self.assertRaises(durable.Rejected):
                self.serve(process, result_oracle=None)
            self.assertEqual(self.calls, [])
            self.assertFalse(self.path.exists())

    def test_explicit_partial_lease_cannot_acknowledge_dispatch(self):
        with self.case.open() as process:
            self.configure(process)
            def enqueue(request, *, deadline):
                process.authorize_dispatch(request, deadline=deadline, phase='observe')
                return {'request_id': request['request_id'], 'accepted': True, 'separate_recovery_owner': True}
            state = process.reconcile(deadline=self.deadline, dispatch=SimpleNamespace(enqueue_recovery=enqueue))
            self.assertEqual(state['state'], 'recovery_unresolved')
            self.assertFalse((self.case.root / 'reconcile-enqueued.json').exists())

    def test_explicit_dispatch_cannot_acknowledge_without_completing_lease(self):
        with self.case.open() as process:
            self.configure(process)
            forged = SimpleNamespace(enqueue_recovery=lambda r, **kw: {
                'request_id': r['request_id'], 'accepted': True, 'separate_recovery_owner': True})
            state = process.reconcile(deadline=self.deadline, dispatch=forged)
            self.assertEqual(state['state'], 'recovery_unresolved')
            self.assertTrue((self.case.root / 'reconcile-request.json').exists())
            self.assertFalse((self.case.root / 'reconcile-enqueued.json').exists())

    def test_wrong_request_or_shortened_deadline_binding_never_starts(self):
        for change in ({'binding': replace(jobs.RecoveryJobBinding('e' * 64, '/synthetic/unit', 'f' * 64, 'e' * 64))},
                       {'deadline': 1052.}):
            with self.subTest(change=change), self.fresh() as f, f.case.open() as process:
                f.configure(process)
                with f.assertRaises(durable.Rejected):
                    f.serve(process, **change)
                f.assertEqual(f.calls, [])
                f.assertFalse(f.path.exists())
                f.assertFalse((f.case.root / 'reconcile-request.json').exists())

    def test_endpoint_policy_or_journal_nesting_never_starts(self):
        with self.case.open() as process:
            self.configure(process)
            for endpoint in (replace(self.approval, uid=os.geteuid() + 1),
                             replace(self.approval, mode=0o755), approve(self.case.root)):
                with self.subTest(endpoint=endpoint), self.assertRaises(durable.Rejected):
                    self.serve(process, endpoint=endpoint)
                self.assertEqual(self.starts(), [])

    def test_preexisting_socket_or_regular_file_is_not_removed(self):
        with self.case.open() as process:
            self.configure(process)
            self.path.write_bytes(b'prior endpoint')
            with self.assertRaises(durable.Rejected):
                self.serve(process)
            self.assertEqual(self.path.read_bytes(), b'prior endpoint')
            self.assertEqual(self.starts(), [])
            self.assertFalse((self.case.root / 'reconcile-request.json').exists())

    def test_fence_denial_before_enqueue_retains_request_without_start(self):
        with self.case.open() as process:
            self.configure(process)
            self.on_show = lambda _: setattr(self.case.manager, 'fenced', False)
            with self.assertRaises(durable.Rejected):
                self.serve(process)
            self.assertEqual(self.starts(), [])
            self.assertTrue((self.case.root / 'reconcile-request.json').exists())
            self.assertFalse((self.case.root / 'reconcile-worker.json').exists())
            self.assertTrue(self.case.notices)

    def test_lost_enqueue_reply_or_bad_ack_never_accepts_claim_or_retries(self):
        for kind in ('lost', 'bad'):
            with self.subTest(kind=kind), self.fresh() as f, f.case.open() as process:
                f.configure(process)
                if kind == 'lost':
                    f.start_failure = durable.Rejected('restricted failure text')
                else:
                    f.start_reply = b'not an enqueue acknowledgment'
                with f.assertRaises(durable.Rejected):
                    f.serve(process)
                with f.assertRaises(durable.Rejected):
                    f.serve(process)
                f.assertEqual(len(f.starts()), 1)
                f.assertTrue((f.case.root / 'reconcile-request.json').exists())
                f.assertFalse((f.case.root / 'reconcile-worker.json').exists())
                f.assertFalse((f.case.root / 'reconcile-enqueued.json').exists())
                f.assertTrue(all(value.closed for value in f.closed_listeners))

    def test_endpoint_replacement_after_enqueue_refuses_original_worker(self):
        with self.case.open() as process:
            self.configure(process)
            old = self.endpoint.with_name(self.endpoint.name + '-old')
            self.addCleanup(lambda: old.rmdir())
            def replace_endpoint(_):
                self.endpoint.rename(old)
                self.endpoint.mkdir(mode=0o700)
            self.on_start = replace_endpoint
            with self.assertRaises(durable.Rejected):
                self.serve(process)
            # Socket moved with the original directory and is retained evidence.
            old_socket = old / self.path.name
            self.addCleanup(old_socket.unlink)
            self.assertTrue(old_socket.is_socket())
            self.assertEqual(len(self.starts()), 1)
            self.assertFalse((self.case.root / 'reconcile-worker.json').exists())

    def test_oracle_denial_or_last_owner_loss_cannot_return_identity_only_success(self):
        for kind in ('oracle', 'owner'):
            with self.subTest(kind=kind), self.fresh() as f, f.case.open() as process:
                f.configure(process)
                if kind == 'oracle':
                    f.oracle = lambda *a, **kw: True
                else:
                    f.on_oracle = lambda _: setattr(f.case.manager, 'owner_change', True)
                with f.assertRaises(durable.Rejected):
                    f.serve(process)
                f.assertFalse(process.result_observed)
                f.assertTrue((f.case.root / 'reconcile-result.json').exists())
                f.assertFalse((f.case.root / 'reconcile-result-observed.json').exists())
                f.case.assert_fenced(process.status())

    def test_worker_sigkill_during_provider_does_not_record_success(self):
        self.source = CLIENT.replace("{'outcome':'baseline_restored','evidence_sha256':'e'*64}",
                                     "os.kill(os.getpid(),9)")
        with self.case.open() as process:
            self.configure(process)
            with self.assertRaises(durable.Rejected):
                self.serve(process)
            self.assertEqual(self.children[0].wait(timeout=5), -9)
            self.assertTrue((self.case.root / 'reconcile-worker.json').exists())
            self.assertFalse((self.case.root / 'reconcile-result.json').exists())
            self.assertFalse(process.result_observed)
            self.assertTrue(process.status()['alert']['transport_delivered'])
            self.locked()

    def test_every_pipeline_persistence_fault_is_reached_and_independently_alerted(self):
        for name in ('reconcile-request.json', 'reconcile-enqueued.json', 'reconcile-worker.json',
                     'reconcile-result.json', 'reconcile-result-observed.json'):
            for point in ('write', 'file-fsync', 'rename', 'directory-fsync', 'readback'):
                for code in (errno.EIO, errno.ENOSPC):
                    with self.subTest(name=name, point=point, code=code), self.fresh() as f, f.case.open() as process:
                        f.configure(process)
                        reached = []
                        original = process.log._write
                        def write(target, value):
                            def fault(stage):
                                if stage == point:
                                    reached.append((target, stage))
                                    raise OSError(code, 'restricted disk text')
                            process.log.fault = fault if target == name else None
                            return original(target, value)
                        process.log._write = write
                        process.persist_alert = lambda _: (_ for _ in ()).throw(OSError(code, 'receipt failed'))
                        with f.assertRaises(durable.Rejected):
                            f.serve(process)
                        f.assertEqual(reached, [(name, point)])
                        f.assertTrue(process.log.uncertain)
                        f.assertFalse(process.result_observed)
                        f.assertTrue(process.status()['alert']['transport_delivered'])
                        f.assertFalse(process.status()['alert']['receipt_persisted'])
                        f.assertEqual(len(f.starts()), 0 if name == 'reconcile-request.json' else 1)
                        f.assertTrue(all(value.closed for value in f.closed_listeners))
                        f.locked()

    def test_reopen_after_dispatch_cannot_enqueue_or_revive_original_peer(self):
        with self.case.open() as process:
            self.configure(process)
            self.serve(process)
        with self.case.open() as reopened:
            self.assertEqual(reopened.status()['state'], 'recovery_unresolved')
            with self.assertRaises(durable.Rejected):
                self.serve(reopened)
        self.assertEqual(len(self.starts()), 1)


if __name__ == '__main__':
    unittest.main()
