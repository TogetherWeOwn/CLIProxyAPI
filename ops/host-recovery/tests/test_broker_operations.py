"""Private synthetic broker records; no installed broker/manager/runtime proof."""
import copy
import errno
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import threading
import unittest

from fixture_home import fixture_home
from host_recovery import broker_operations as operations, durable

ATTEMPT = '11111111-1111-4111-8111-111111111111'
INVOCATION = '22222222-2222-4222-8222-222222222222'
RUNTIME = '33333333-3333-4333-8333-333333333333'


def binding():
    return dict(installation_id='synthetic', attempt_id=ATTEMPT, intent_sha256='a' * 64,
                request_sha256='b' * 64, topology_sha256='c' * 64,
                original_boot_id='boot-original', original_arm=100, failure_monotonic=101, recovery_deadline=280)


def epoch():
    return dict(boot_id='boot-original', broker_invocation_id=INVOCATION, runtime_epoch=RUNTIME)


CHILD = r'''
import os,signal,sys
sys.path.insert(0,sys.argv[1])
sys.path.insert(0,sys.argv[1]+'/tests')
from host_recovery import broker_operations as operations,durable
from test_broker_operations import binding,epoch
with durable.directory(sys.argv[2],private=True) as fd:
 journal=operations.OperationJournal(fd,binding=binding(),epoch=epoch(),clock=lambda:101,boot_id=lambda:'boot-original')
 def fault(point):
  if point==sys.argv[3]:
   print('PENDING-BARRIER',flush=True)
   signal.pause()
 journal.fault=fault
 journal.pending('contain_forward',target_sha256='d'*64,deadline=150)
'''


class OperationJournalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='.broker-operations-', dir=fixture_home())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.now, self.boot = 101, 'boot-original'

    def journal(self, *, fault=None, bound=None, generation=None):
        path = self.root / ('state-' + str(len(list(self.root.iterdir()))))
        path.mkdir(mode=0o700)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        value = operations.OperationJournal(fd, binding=bound or binding(), epoch=generation or epoch(),
                                           clock=lambda: self.now, boot_id=lambda: self.boot, fault=fault)
        return value, path

    def pending(self, journal, method='contain_forward', deadline=150):
        return journal.pending(method, target_sha256='d' * 64, deadline=deadline)

    def assert_closed(self, journal):
        status = journal.status()
        for field in ('pending_drained', 'complete_fence_proven', 'recovery_execution_allowed',
                      'start_allowed', 'production_acceptance'):
            self.assertIs(status[field], False, field)
        return status

    def test_pending_durable_before_return_and_return_is_not_drain(self):
        journal, path = self.journal()
        record = self.pending(journal)
        self.assertEqual(durable.decode((path / 'operation-01-pending.json').read_bytes()), record)
        self.assertEqual(record['binding_sha256'], durable.digest(durable.canonical(binding())))
        receipt = journal.returned(record, result='returned')
        self.assertIs(receipt['pending_drained'], False)
        status = self.assert_closed(journal)
        self.assertEqual((status['pending_count'], status['returned_count']), (1, 1))
        self.assertEqual(stat_mode(path / 'operation-01-return.json'), 0o600)

    def test_duplicate_after_return_cannot_renew_or_resubmit(self):
        journal, path = self.journal()
        record = self.pending(journal)
        journal.returned(record, result='returned')
        before = {p.name: p.read_bytes() for p in path.iterdir()}
        with self.assertRaises(durable.Rejected):
            self.pending(journal, deadline=200)
        self.assertEqual(before, {p.name: p.read_bytes() for p in path.iterdir()})
        self.assertEqual(self.assert_closed(journal)['state'], 'reconciliation_required')

    def test_unreturned_operation_blocks_every_later_method(self):
        for method in operations.METHODS - {'contain_forward'}:
            with self.subTest(method=method):
                journal, path = self.journal()
                self.pending(journal)
                with self.assertRaises(durable.Rejected):
                    self.pending(journal, method)
                self.assertFalse((path / 'operation-02-pending.json').exists())

    def test_reopened_history_never_reports_zero_pending_or_adopts_permission(self):
        for returned in (False, True):
            with self.subTest(returned=returned):
                journal, path = self.journal()
                record = self.pending(journal)
                if returned:
                    journal.returned(record, result='returned')
                before = {p.name: p.read_bytes() for p in path.iterdir()}
                newer = epoch()
                newer['broker_invocation_id'] = '44444444-4444-4444-8444-444444444444'
                reopened = operations.OperationJournal(journal.fd, binding=binding(), epoch=newer,
                    clock=lambda: self.now, boot_id=lambda: self.boot)
                status = self.assert_closed(reopened)
                self.assertTrue(status['reopened'])
                self.assertIsNone(status['pending_count'])
                with self.assertRaises(durable.Rejected):
                    self.pending(reopened)
                self.assertEqual(before, {p.name: p.read_bytes() for p in path.iterdir()})

    def test_epoch_only_and_unknown_or_staged_history_are_not_fresh(self):
        for extra in (None, '.stage-operation-01-pending.json', 'unknown.json'):
            with self.subTest(extra=extra):
                journal, path = self.journal()
                if extra:
                    (path / extra).write_bytes(b'uncertain')
                reopened = operations.OperationJournal(journal.fd, binding=binding(), epoch=epoch(),
                    clock=lambda: self.now, boot_id=lambda: self.boot)
                self.assertEqual(self.assert_closed(reopened)['state'], 'reconciliation_required')
                with self.assertRaises(durable.Rejected):
                    self.pending(reopened)

    def test_all_persistence_faults_reached_and_never_acknowledged(self):
        for point in ('create', 'write', 'file-fsync', 'rename', 'directory-fsync', 'readback'):
            for code in (errno.EIO, errno.ENOSPC):
                with self.subTest(point=point, code=code):
                    journal, path = self.journal()
                    reached = []
                    def fail(actual):
                        if actual == point:
                            reached.append(actual)
                            raise OSError(code, 'synthetic')
                    journal.fault = fail
                    with self.assertRaises(durable.Rejected):
                        self.pending(journal)
                    self.assertEqual(reached, [point])
                    self.assertEqual(self.assert_closed(journal)['state'], 'reconciliation_required')
                    journal.fault = None
                    with self.assertRaises(durable.Rejected):
                        self.pending(journal)
                    self.assertFalse((path / 'operation-01-return.json').exists())

    def test_epoch_persistence_faults_leave_no_usable_fresh_journal(self):
        for point in ('write', 'file-fsync', 'rename', 'directory-fsync', 'readback'):
            with self.subTest(point=point):
                path = self.root / ('epoch-' + point)
                path.mkdir(mode=0o700)
                reached = []
                def fail(actual):
                    if actual == point:
                        reached.append(actual)
                        raise OSError(errno.EIO, 'synthetic')
                with durable.directory(str(path), private=True) as fd:
                    with self.assertRaises(OSError):
                        operations.OperationJournal(fd, binding=binding(), epoch=epoch(),
                            clock=lambda: self.now, boot_id=lambda: self.boot, fault=fail)
                    self.assertEqual(reached, [point])
                    self.assertTrue(list(path.iterdir()))
                    reopened = operations.OperationJournal(fd, binding=binding(), epoch=epoch(),
                        clock=lambda: self.now, boot_id=lambda: self.boot)
                    with self.assertRaises(durable.Rejected): self.pending(reopened)
                    self.assert_closed(reopened)

    def test_return_write_faults_never_acknowledge_or_remove_pending(self):
        for point in ('create', 'write', 'file-fsync', 'rename', 'directory-fsync', 'readback'):
            for code in (errno.EIO, errno.ENOSPC):
                with self.subTest(point=point, code=code):
                    journal, path = self.journal()
                    record = self.pending(journal)
                    original = (path / 'operation-01-pending.json').read_bytes()
                    reached = []
                    def fail(actual):
                        if actual == point:
                            reached.append(actual)
                            raise OSError(code, 'synthetic')
                    journal.fault = fail
                    with self.assertRaises(durable.Rejected):
                        journal.returned(record, result='returned')
                    self.assertEqual(reached, [point])
                    self.assertEqual((path / 'operation-01-pending.json').read_bytes(), original)
                    self.assertEqual(self.assert_closed(journal)['state'], 'reconciliation_required')

    def test_late_persistence_and_clock_regression_or_boot_loss_refuse(self):
        for change in ('expiry', 'regression', 'boot'):
            with self.subTest(change=change):
                self.now, self.boot = 101, 'boot-original'
                journal, path = self.journal()
                def change_at_barrier(point):
                    if point == 'readback':
                        if change == 'expiry': self.now = 150
                        elif change == 'regression': self.now = 100.5
                        else: self.boot = 'different-boot'
                journal.fault = change_at_barrier
                with self.assertRaises(durable.Rejected):
                    self.pending(journal)
                self.assertTrue((path / 'operation-01-pending.json').exists())
                self.assertEqual(self.assert_closed(journal)['state'], 'reconciliation_required')

    def test_record_mutation_or_directory_drift_revokes(self):
        for drift in ('bytes', 'mode', 'extra', 'directory'):
            with self.subTest(drift=drift):
                journal, path = self.journal()
                record = self.pending(journal)
                if drift == 'bytes': (path / 'epoch.json').write_bytes(b'{}\n')
                elif drift == 'mode': (path / 'epoch.json').chmod(0o644)
                elif drift == 'extra': (path / 'late.json').write_bytes(b'{}\n')
                else: path.chmod(0o755)
                with self.assertRaises(durable.Rejected):
                    journal.returned(record, result='returned')
                self.assertEqual(self.assert_closed(journal)['state'], 'reconciliation_required')

    def test_receipt_mutation_wrong_result_and_duplicate_return_refuse(self):
        for change in ('operation_id', 'deadline', 'method', 'extra', 'result', 'duplicate'):
            with self.subTest(change=change):
                journal, path = self.journal()
                record = self.pending(journal)
                if change == 'duplicate': journal.returned(record, result='returned')
                elif change == 'extra': record['injected'] = True
                elif change not in ('result',): record[change] = 'forged'
                with self.assertRaises(durable.Rejected):
                    journal.returned(record, result='secret-response' if change == 'result' else 'returned')
                self.assert_closed(journal)

    def test_ambiguous_and_refused_returns_close_all_following_work(self):
        for result in ('ambiguous', 'refused'):
            with self.subTest(result=result):
                journal, path = self.journal()
                receipt = journal.returned(self.pending(journal), result=result)
                self.assertEqual(receipt['result'], result)
                with self.assertRaises(durable.Rejected):
                    self.pending(journal, 'cold_quiesce_runtime')
                self.assertEqual(self.assert_closed(journal)['state'], 'reconciliation_required')

    def test_inputs_and_returned_dicts_are_not_borrowed(self):
        original, generation = binding(), epoch()
        journal, path = self.journal(bound=original, generation=generation)
        original['recovery_deadline'] = 400
        generation['runtime_epoch'] = INVOCATION
        record = self.pending(journal)
        expected = copy.deepcopy(record)
        record['deadline'] = 400
        self.assertEqual(durable.decode((path / 'operation-01-pending.json').read_bytes()), expected)
        journal.returned(expected, result='returned')
        saved = durable.decode((path / 'epoch.json').read_bytes())
        self.assertEqual(saved['binding'], binding())
        self.assertEqual(saved['epoch'], epoch())

    def test_unbounded_or_forward_operations_never_enter_ledger(self):
        for method in ('exec', 'systemctl', 'create_approved_candidate', 'start_registered_candidate',
                       'start_verified_old/../../exec', [], True):
            with self.subTest(method=method):
                journal, path = self.journal()
                with self.assertRaises(durable.Rejected):
                    self.pending(journal, method)
                self.assertEqual(sorted(p.name for p in path.iterdir()), ['epoch.json'])

    def test_invalid_binding_epoch_and_nonfinite_deadlines_refuse(self):
        for key, bad in (('attempt_id', 'not-uuid'), ('original_arm', True), ('recovery_deadline', 401),
                         ('request_sha256', 'bad'), ('topology_sha256', None)):
            value = binding()
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(durable.Rejected):
                self.journal(bound=value)
        for bad in (True, float('nan'), float('inf'), 101, 281):
            journal, path = self.journal()
            with self.subTest(deadline=bad), self.assertRaises(durable.Rejected):
                self.pending(journal, deadline=bad)
        wrong = epoch()
        wrong['boot_id'] = 'other-boot'
        with self.assertRaises(durable.Rejected):
            self.journal(generation=wrong)

    def test_serialized_duplicate_consumption_records_only_one_pending(self):
        journal, path = self.journal()
        gate = threading.Barrier(3)
        results = []
        def enter():
            gate.wait()
            try: results.append(self.pending(journal))
            except durable.Rejected: results.append(None)
        threads = [threading.Thread(target=enter) for _ in range(2)]
        for thread in threads: thread.start()
        gate.wait()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(len(list(path.glob('*-pending.json'))), 1)
        self.assert_closed(journal)

    def test_sigkill_during_pending_publication_preserves_ambiguity_without_replay(self):
        root = str(Path(__file__).resolve().parent.parent)
        for point in ('write', 'directory-fsync', 'readback'):
            with self.subTest(point=point):
                path = self.root / ('child-' + point)
                path.mkdir(mode=0o700)
                child = subprocess.Popen([sys.executable, '-I', '-c', CHILD, root, str(path), point],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    with selectors.DefaultSelector() as wait:
                        wait.register(child.stdout, selectors.EVENT_READ)
                        self.assertTrue(wait.select(5), 'synthetic pending barrier not reached')
                    self.assertEqual(child.stdout.readline().strip(), b'PENDING-BARRIER')
                    child.send_signal(signal.SIGKILL)
                    child.wait(timeout=5)
                    self.assertEqual(child.returncode, -signal.SIGKILL)
                    before = {p.name: p.read_bytes() for p in path.iterdir()}
                    with durable.directory(str(path), private=True) as fd:
                        reopened = operations.OperationJournal(fd, binding=binding(), epoch=epoch(),
                            clock=lambda: self.now, boot_id=lambda: self.boot)
                        with self.assertRaises(durable.Rejected): self.pending(reopened)
                        self.assertIsNone(self.assert_closed(reopened)['pending_count'])
                    self.assertEqual(before, {p.name: p.read_bytes() for p in path.iterdir()})
                finally:
                    if child.poll() is None: child.kill()
                    child.wait(timeout=5)
                    child.stdout.close()
                    child.stderr.close()


def stat_mode(path):
    return path.stat().st_mode & 0o777
