"""Synthetic crash records, not privileged broker/cold-runtime qualification."""
import copy
import errno
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from host_recovery import broker_history as history, broker_operations as operations, durable, jobs, loading
from test_broker_operations import epoch
from test_recovery_state import intent


def original_inputs():
    value = intent()
    value['owner']['invocation_id'] = 'a' * 32
    arm = {"schema": "host-recovery-arm-v1", "arm": {"boot_id": "boot-a", "monotonic": 1000.0},
           "intent_sha256": durable.digest(durable.canonical(value))}
    request = {"schema": "host-recovery-reconcile-request-v1", "attempt_id": value["attempt_id"],
               "intent_sha256": arm["intent_sha256"], "owner": value["owner"].copy(),
               "original_arm": arm["arm"].copy(), "failure_lower_bound": 1000.0, "deadline": 1180.0,
               "detection_upper_bound_seconds": 50.0, "forward_allowed": False, "production_acceptance": False}
    request["request_id"] = durable.digest(durable.canonical(request))
    return loading.RecoveryInputs(durable.canonical(value), durable.canonical(request), durable.canonical(arm))


CHILD = r'''
import os,signal,sys
sys.path.insert(0,sys.argv[1])
sys.path.insert(0,sys.argv[1]+'/tests')
from host_recovery import broker_history as history,broker_operations as operations,durable
from test_broker_history import original_inputs
from test_broker_operations import epoch
saved=epoch();saved['boot_id']='boot-a'
with durable.directory(sys.argv[2],private=True) as fd:
 journal=operations.OperationJournal(fd,binding=history.original_binding(original_inputs(),topology_sha256='c'*64),
     epoch=saved,clock=lambda:1050,boot_id=lambda:'boot-a')
 def fault(point):
  if point=='directory-fsync':
   print('PUBLISHED',flush=True)
   signal.pause()
 if sys.argv[3]=='pending':journal.fault=fault
 record=journal.pending('contain_forward',target_sha256='d'*64,deadline=1100)
 journal.fault=fault
 journal.returned(record,result='returned')
'''


class BrokerHistoryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='broker-history-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / 'audit'
        self.path.mkdir(mode=0o700)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.fd)
        self.inputs = original_inputs()
        self.epoch = {**epoch(), 'boot_id': 'boot-a'}
        self.binding = history.original_binding(self.inputs, topology_sha256='c' * 64)
        self.journal = operations.OperationJournal(self.fd, binding=self.binding, epoch=self.epoch,
                                                  clock=lambda:1050, boot_id=lambda:'boot-a')

    def inspect(self, **overrides):
        args = dict(inputs=self.inputs, topology_sha256='c' * 64, current_epoch=self.epoch,
                    uid=os.geteuid(), gid=os.getegid())
        args.update(overrides)
        return history.inspect_history(self.fd, **args)

    def pending(self, method='contain_forward'):
        return self.journal.pending(method, target_sha256='d' * 64, deadline=1100)

    def write(self, name, value):
        path = self.path / name
        path.write_bytes(durable.canonical(value))
        path.chmod(0o600)

    def records(self):
        return {p.name:p.read_bytes() for p in self.path.iterdir()}

    def closed(self, result):
        for key in ('pending_drained', 'complete_fence_proven', 'recovery_execution_allowed',
                    'start_allowed', 'settlement_allowed', 'production_acceptance'):
            self.assertIs(result[key], False, key)

    def test_actual_original_loader_composes_with_operation_history(self):
        original = self.root / 'original'
        original.mkdir(mode=0o700)
        for name, raw in (('intent.json', self.inputs.intent_raw), ('arm.json', self.inputs.arm_raw),
                          ('reconcile-request.json', self.inputs.request_raw)):
            path = original / name
            path.write_bytes(raw)
            path.chmod(0o600)
        value, request = self.inputs.intent, self.inputs.request
        approval = loading.RecoveryApproval(durable.digest(self.inputs.intent_raw), value['package_sha256'],
            value['manifest_sha256'], value['baseline_sha256'], value['policy_sha256'], value['installation_id'],
            value['attempt_id'], os.geteuid(), os.getegid())
        binding = jobs.RecoveryJobBinding(request['request_id'], '/synthetic/recovery.service', 'e'*64, 'f'*64)
        with durable.directory(str(original), private=True) as fd:
            loaded = loading.load_recovery(fd, approval=approval, binding=binding,
                supervisor_owner=request['owner'], boot_id='boot-a', now=1050)
            self.pending()
            before = self.records()
            report = self.inspect(inputs=loaded)
            self.closed(report)
            self.assertEqual(report['operations'][0]['classification'], 'unreturned')
            self.assertEqual(before, self.records())

    def test_epoch_only_is_not_fresh_admission(self):
        before = self.records()
        report = self.inspect()
        self.assertEqual(report['state'], 'cold_reconciliation_required')
        self.assertEqual(report['recorded_operation_count'], 0)
        self.closed(report)
        self.assertEqual(before, self.records())

    def test_all_returns_remain_unproven_and_do_not_enable_reopened_journal(self):
        for method in sorted(operations.METHODS):
            record = self.pending(method)
            self.journal.returned(record, result='returned')
        report = self.inspect()
        self.closed(report)
        self.assertEqual(report['recorded_operation_count'], len(operations.METHODS))
        self.assertEqual({r['classification'] for r in report['operations']}, {'returned_unproven'})
        reopened = operations.OperationJournal(self.fd, binding=self.binding, epoch=self.epoch,
                                               clock=lambda:1050, boot_id=lambda:'boot-a')
        with self.assertRaises(durable.Rejected):
            reopened.pending('contain_forward', target_sha256='d'*64, deadline=1100)
        self.assertIsNone(reopened.status()['pending_count'])

    def test_unreturned_ambiguous_and_refused_are_not_cancellation(self):
        record = self.pending()
        self.assertEqual(self.inspect()['operations'][0]['classification'], 'unreturned')
        for result in ('ambiguous', 'refused'):
            self.write('operation-01-return.json', {'schema':'host-recovery-broker-return-v1',
                'operation_id':record['operation_id'], 'result':result, 'pending_drained':False})
            report = self.inspect()
            self.closed(report)
            self.assertEqual(report['operations'][0]['classification'], result)

    def test_changed_broker_runtime_or_boot_epoch_never_renews_original_deadline(self):
        self.pending()
        before = self.records()
        for field, value in (('broker_invocation_id', '44444444-4444-4444-8444-444444444444'),
                             ('runtime_epoch', '55555555-5555-4555-8555-555555555555'), ('boot_id', 'new-boot')):
            with self.subTest(field=field):
                report = self.inspect(current_epoch={**self.epoch, field:value})
                self.closed(report)
                self.assertTrue(report['epoch_changed'])
                self.assertEqual(report['boot_changed'], field == 'boot_id')
                self.assertEqual(report['state'], 'cross_boot_continuation_required' if field == 'boot_id'
                                 else 'cold_reconciliation_required')
        self.assertEqual(before, self.records())

    def test_foreign_original_publication_or_topology_refuses(self):
        self.pending()
        request = self.inputs.request
        request['owner']['invocation_id'] = 'e'*32
        request.pop('request_id')
        request['request_id'] = durable.digest(durable.canonical(request))
        other = loading.RecoveryInputs(self.inputs.intent_raw, durable.canonical(request), self.inputs.arm_raw)
        for args in ({'inputs':other}, {'topology_sha256':'e'*64}):
            with self.subTest(args=args), self.assertRaisesRegex(durable.Rejected, '^broker-history-unconfirmed$'):
                self.inspect(**args)

    def test_original_binding_rejects_split_arm_missing_request_and_extended_deadline(self):
        for kind in ('arm', 'missing', 'deadline', 'intent', 'schema', 'noncanonical'):
            request, arm = self.inputs.request, durable.decode(self.inputs.arm_raw)
            raw_intent = self.inputs.intent_raw
            if kind == 'arm': arm['arm']['monotonic'] = 999.0
            elif kind == 'missing': request = {}
            elif kind == 'deadline': request['deadline'] = 1400.0
            elif kind == 'intent': raw_intent = b'{}\n'
            elif kind == 'schema': request['unknown'] = True
            if request and kind != 'noncanonical':
                request.pop('request_id', None)
                request['request_id'] = durable.digest(durable.canonical(request))
            request_raw = durable.canonical(request) + (b' ' if kind == 'noncanonical' else b'')
            inputs = loading.RecoveryInputs(raw_intent, request_raw, durable.canonical(arm))
            with self.subTest(kind=kind), self.assertRaises(durable.Rejected):
                self.inspect(inputs=inputs)

    def test_unknown_staging_and_missing_epoch_preserve_bytes_and_refuse_counts(self):
        for name in ('.stage-operation-01-pending.json', 'unexpected.json'):
            path = self.path / name
            path.write_bytes(b'uncertain')
            before = self.records()
            with self.subTest(name=name), self.assertRaises(durable.Rejected): self.inspect()
            self.assertEqual(before, self.records())
            path.unlink()
        (self.path / 'epoch.json').unlink()
        with self.assertRaises(durable.Rejected): self.inspect()

    def test_gap_or_orphan_return_cannot_hide_an_operation(self):
        record = self.pending()
        self.journal.returned(record, result='returned')
        for name in ('operation-01-pending.json', 'operation-01-return.json'):
            raw = (self.path / name).read_bytes()
            (self.path / name).unlink()
            if name.endswith('return.json'):
                self.write('operation-03-return.json', {'schema':'host-recovery-broker-return-v1',
                    'operation_id':record['operation_id'], 'result':'returned', 'pending_drained':False})
            with self.subTest(name=name), self.assertRaises(durable.Rejected): self.inspect()
            (self.path / name).write_bytes(raw)
            (self.path / name).chmod(0o600)

    def test_duplicate_methods_or_later_operation_after_uncertainty_refuse(self):
        first = self.pending()
        self.journal.returned(first, result='returned')
        self.pending('cold_quiesce_runtime')
        second = durable.decode((self.path / 'operation-02-pending.json').read_bytes())
        second['method'] = first['method']
        second.pop('operation_id')
        second['operation_id'] = durable.digest(durable.canonical(second))
        self.write('operation-02-pending.json', second)
        with self.assertRaises(durable.Rejected): self.inspect()
        second['method'] = 'cold_quiesce_runtime'
        second.pop('operation_id')
        second['operation_id'] = durable.digest(durable.canonical(second))
        self.write('operation-02-pending.json', second)
        (self.path / 'operation-01-return.json').unlink()
        with self.assertRaises(durable.Rejected): self.inspect()

    def test_resigned_bad_operation_schema_method_sequence_epoch_and_deadline_refuse(self):
        original = self.pending()
        for field, value in (('sequence', True), ('sequence', 2), ('method', 'exec'), ('method', []),
                             ('epoch_sha256', 'e'*64), ('binding_sha256', 'e'*64), ('target_sha256', '../x'),
                             ('deadline', 1400), ('deadline', 999), ('deadline', True), ('state', 'drained'),
                             ('schema', 'unknown'), ('unknown', True)):
            record = copy.deepcopy(original)
            record[field] = value
            record.pop('operation_id')
            record['operation_id'] = durable.digest(durable.canonical(record))
            self.write('operation-01-pending.json', record)
            with self.subTest(field=field, value=value), self.assertRaises(durable.Rejected): self.inspect()

    def test_return_cannot_assert_drain_or_rebind_its_original_operation(self):
        pending = self.pending()
        original = self.journal.returned(pending, result='returned')
        for field, value in (('pending_drained', True), ('pending_drained', 0), ('result', 'success'),
                             ('result', []), ('operation_id', 'e'*64), ('unknown', True)):
            self.write('operation-01-return.json', {**original, field:value})
            with self.subTest(field=field), self.assertRaises(durable.Rejected): self.inspect()

    def test_malformed_duplicate_nonfinite_noncanonical_and_oversized_json_refuse(self):
        path = self.path / 'epoch.json'
        for raw in (b'{}\n', b'{"x":1,"x":2}', b'{"x":NaN}', b'[]', b'{'*1000,
                    path.read_bytes() + b' ', b'x'*(operations.MAX_RECORD_BYTES + 1)):
            path.write_bytes(raw)
            with self.subTest(size=len(raw)), self.assertRaises(durable.Rejected): self.inspect()

    def test_special_files_and_wrong_metadata_never_follow_or_block(self):
        path = self.path / 'operation-01-pending.json'
        for kind in ('symlink', 'fifo', 'directory', 'hardlink'):
            if kind == 'symlink': path.symlink_to('epoch.json')
            elif kind == 'fifo': os.mkfifo(path, 0o600)
            elif kind == 'directory': path.mkdir(mode=0o700)
            else: os.link(self.path / 'epoch.json', path)
            with self.subTest(kind=kind), self.assertRaises(durable.Rejected): self.inspect()
            path.rmdir() if kind == 'directory' else path.unlink()
        (self.path / 'epoch.json').chmod(0o644)
        with self.assertRaises(durable.Rejected): self.inspect()
        (self.path / 'epoch.json').chmod(0o600)
        self.path.chmod(0o755)
        with self.assertRaises(durable.Rejected): self.inspect()

    def test_entry_limit_and_wrong_owner_refuse(self):
        with self.assertRaises(durable.Rejected): self.inspect(uid=os.geteuid()+1)
        for number in range(history.MAX_FILES): self.write('extra-%02d.json'%number, {})
        with self.assertRaises(durable.Rejected): self.inspect()

    def test_read_error_or_late_byte_mutation_refuses_without_partial_report(self):
        original = history.read_file
        for code in (errno.EIO, errno.ENOSPC):
            reached = []
            def fail(*args, **kwargs):
                reached.append(True)
                raise OSError(code, 'synthetic')
            with patch.object(history, 'read_file', fail), self.assertRaises(durable.Rejected): self.inspect()
            self.assertEqual(reached, [True])
        calls = []
        def mutate(*args, **kwargs):
            raw, st = original(*args, **kwargs)
            calls.append(True)
            return (raw if len(calls) == 1 else raw + b' ', st)
        with patch.object(history, 'read_file', mutate), patch.object(history, 'signature', lambda st:0):
            with self.assertRaises(durable.Rejected): self.inspect()
        self.assertEqual(len(calls), 2)

    def test_addition_during_read_and_same_name_replacement_refuse(self):
        original = history.read_file
        for kind in ('addition', 'replacement'):
            calls = []
            def change(*args, **kwargs):
                result = original(*args, **kwargs)
                calls.append(True)
                if len(calls) == 1:
                    if kind == 'addition': self.write('late.json', {})
                    else:
                        raw = (self.path / 'epoch.json').read_bytes()
                        (self.path / 'epoch.json').unlink()
                        (self.path / 'epoch.json').write_bytes(raw)
                        (self.path / 'epoch.json').chmod(0o600)
                return result
            with patch.object(history, 'read_file', change), self.assertRaises(durable.Rejected): self.inspect()
            if kind == 'addition': (self.path / 'late.json').unlink()
            self.assertGreaterEqual(len(calls), 2)

    def test_crash_at_pending_and_return_publication_never_proves_drain(self):
        for phase in ('pending', 'return'):
            path = self.root / phase
            path.mkdir(mode=0o700)
            process = subprocess.Popen([sys.executable, '-I', '-u', '-c', CHILD,
                str(Path(__file__).resolve().parents[1]), str(path), phase], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            try:
                with selectors.DefaultSelector() as ready:
                    ready.register(process.stdout, selectors.EVENT_READ)
                    self.assertTrue(ready.select(10), 'synthetic child did not reach publication')
                self.assertEqual(process.stdout.readline(), b'PUBLISHED\n')
                process.kill()
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(stderr, b'')
                self.assertLess(process.returncode, 0)
                with durable.directory(str(path), private=True) as fd:
                    report = history.inspect_history(fd, inputs=self.inputs, topology_sha256='c'*64,
                        current_epoch={**self.epoch, 'broker_invocation_id':'44444444-4444-4444-8444-444444444444'},
                        uid=os.geteuid(), gid=os.getegid())
                self.closed(report)
                self.assertEqual(report['operations'][0]['classification'],
                                 'unreturned' if phase == 'pending' else 'returned_unproven')
            finally:
                if process.poll() is None: process.kill()
                process.communicate(timeout=10)


if __name__ == '__main__':
    unittest.main()
