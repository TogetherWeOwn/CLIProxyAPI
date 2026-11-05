"""Synthetic retained reload records; no runtime reconciliation or replay grant."""
import copy
import os
from pathlib import Path
import selectors
import subprocess
import sys
import unittest

from host_recovery import broker_history as history, durable
import test_broker_history as fixture


RELOAD_CHILD = r'''
import os,signal,sys
sys.path.insert(0,sys.argv[1])
sys.path.insert(0,sys.argv[1]+'/tests')
from host_recovery import broker_history as history,broker_operations as operations,durable,mask_reload
from test_broker_history import original_inputs
from test_broker_operations import epoch
with durable.directory(sys.argv[2],private=True) as fd:
 journal=operations.OperationJournal(fd,binding=history.original_binding(original_inputs(),topology_sha256='c'*64),
     epoch={**epoch(),'boot_id':'boot-a'},clock=lambda:1050,boot_id=lambda:'boot-a')
 operation=journal.pending('contain_forward',target_sha256='d'*64,deadline=1100)
 names=mask_reload.record_names(operation['sequence'])
 pending={'schema':'host-recovery-mask-reload-pending-v1','operation_id':operation['operation_id'],'target_sha256':'e'*64}
 response={'schema':'host-recovery-mask-reload-return-v1','pending_sha256':durable.digest(durable.canonical(pending)),
     'manager_reload_returned':True,'effective_masks_observed':True,'pending_drained':False}
 def fault(point):
  if point=='directory-fsync':
   print('PUBLISHED',flush=True)
   signal.pause()
 if sys.argv[3]=='pending':journal.fault=fault
 journal._write(names[0],pending)
 journal.fault=fault
 journal._write(names[1],response)
'''


class MaskReloadHistoryTests(unittest.TestCase):
    setUp = fixture.BrokerHistoryTests.setUp
    inspect = fixture.BrokerHistoryTests.inspect
    pending = fixture.BrokerHistoryTests.pending
    write = fixture.BrokerHistoryTests.write
    records = fixture.BrokerHistoryTests.records
    closed = fixture.BrokerHistoryTests.closed

    def reload_records(self, operation, *, returned=True):
        prefix = 'operation-%02d-mask-reload-' % operation['sequence']
        pending = {'schema':'host-recovery-mask-reload-pending-v1',
            'operation_id':operation['operation_id'], 'target_sha256':'e'*64}
        response = {'schema':'host-recovery-mask-reload-return-v1',
            'pending_sha256':durable.digest(durable.canonical(pending)),
            'manager_reload_returned':True, 'effective_masks_observed':True, 'pending_drained':False}
        self.write(prefix+'pending.json', pending)
        if returned: self.write(prefix+'return.json', response)
        return prefix, pending, response

    def test_pending_and_returned_reload_are_read_only_unproven_history(self):
        operation = self.pending()
        prefix, _, response = self.reload_records(operation, returned=False)
        for expected in ('unreturned', 'returned_unproven'):
            before = self.records()
            report = self.inspect()
            self.assertEqual(report['operations'][0]['mask_reload']['classification'], expected)
            self.assertEqual(report['operations'][0]['classification'], 'unreturned')
            self.assertFalse(report['operations'][0]['mask_reload']['pending_drained'])
            self.closed(report)
            self.assertEqual(before, self.records())
            if expected == 'unreturned': self.write(prefix+'return.json', response)

    def test_reboot_and_changed_epoch_do_not_adopt_or_reissue_reload(self):
        self.reload_records(self.pending())
        before = self.records()
        for field, value in (('boot_id','boot-new'),
                             ('broker_invocation_id','44444444-4444-4444-8444-444444444444')):
            with self.subTest(field=field):
                report = self.inspect(current_epoch={**self.epoch, field:value})
                self.assertTrue(report['epoch_changed'])
                self.assertEqual(report['boot_changed'], field == 'boot_id')
                self.closed(report)
        self.assertEqual(before, self.records())
        from host_recovery.broker_operations import OperationJournal
        reopened = OperationJournal(self.fd, binding=self.binding, epoch=self.epoch,
            clock=lambda:1050, boot_id=lambda:'boot-a')
        with self.assertRaises(durable.Rejected):
            reopened.pending('contain_forward', target_sha256='d'*64, deadline=1100)
        self.assertEqual(before, self.records())

    def test_returned_outer_operation_cannot_hide_unreturned_reload(self):
        operation = self.pending()
        self.journal.returned(operation, result='returned')
        self.reload_records(operation, returned=False)
        before = self.records()
        with self.assertRaises(durable.Rejected): self.inspect()
        self.assertEqual(before, self.records())

    def test_complete_reload_composes_with_returned_operation_and_next_operation(self):
        operation = self.pending()
        # Outer bookkeeping is published first only to construct the final
        # synthetic history without adopting the new records into a live writer.
        self.journal.returned(operation, result='returned')
        second = self.pending('cold_quiesce_runtime')
        self.reload_records(operation)
        self.reload_records(second)
        report = self.inspect()
        self.closed(report)
        self.assertEqual(report['recorded_operation_count'], 2)
        self.assertEqual([row['mask_reload']['classification'] for row in report['operations']],
                         ['returned_unproven', 'returned_unproven'])
        self.assertEqual(report['operations'][1]['classification'], 'unreturned')

    def test_reload_for_noncontainment_method_is_not_a_supported_phase(self):
        for method in ('dispatch_recovery', 'restore_approved_baseline', 'verify_stopped_baseline', 'start_verified_old'):
            with self.subTest(method=method):
                self.setUp()
                self.reload_records(self.pending(method))
                with self.assertRaises(durable.Rejected): self.inspect()

    def test_unknown_or_orphan_reload_records_never_disappear_from_counts(self):
        operation = self.pending()
        prefix, pending, response = self.reload_records(operation)
        (self.path/(prefix+'pending.json')).unlink()
        with self.assertRaises(durable.Rejected): self.inspect()
        self.write(prefix+'pending.json', pending)
        (self.path/'operation-01-pending.json').unlink()
        with self.assertRaises(durable.Rejected): self.inspect()
        self.write('operation-01-pending.json', operation)
        self.write('operation-02-mask-reload-return.json', response)
        with self.assertRaises(durable.Rejected): self.inspect()

    def test_pending_binding_schema_pin_and_unknown_fields_are_strict(self):
        prefix, pending, _ = self.reload_records(self.pending(), returned=False)
        for field, value in (('schema','unknown'), ('operation_id','f'*64),
                             ('target_sha256','../bad'), ('target_sha256',True), ('unknown',True)):
            with self.subTest(field=field):
                self.write(prefix+'pending.json', {**pending, field:value})
                with self.assertRaises(durable.Rejected): self.inspect()
        missing = copy.deepcopy(pending)
        missing.pop('target_sha256')
        self.write(prefix+'pending.json', missing)
        with self.assertRaises(durable.Rejected): self.inspect()

    def test_return_binding_schema_flags_and_unknown_fields_are_strict(self):
        prefix, _, response = self.reload_records(self.pending())
        for field, value in (('schema','unknown'), ('pending_sha256','f'*64),
                             ('manager_reload_returned',False), ('manager_reload_returned',1),
                             ('effective_masks_observed',False), ('effective_masks_observed',1),
                             ('pending_drained',True), ('pending_drained',0), ('unknown',True)):
            with self.subTest(field=field, value=value):
                self.write(prefix+'return.json', {**response, field:value})
                with self.assertRaises(durable.Rejected): self.inspect()

    def test_noncanonical_and_staged_reload_publication_refuses_without_repair(self):
        prefix, pending, _ = self.reload_records(self.pending(), returned=False)
        path = self.path/(prefix+'pending.json')
        path.write_bytes(path.read_bytes()+b' ')
        before = self.records()
        with self.assertRaises(durable.Rejected): self.inspect()
        self.assertEqual(before, self.records())
        self.write(prefix+'pending.json', pending)
        self.write('.stage-'+prefix+'return.json', {})
        before = self.records()
        with self.assertRaises(durable.Rejected): self.inspect()
        self.assertEqual(before, self.records())

    def test_return_digest_cannot_be_reused_for_a_different_pending_reload(self):
        prefix, pending, _ = self.reload_records(self.pending())
        pending['target_sha256'] = 'f'*64
        self.write(prefix+'pending.json', pending)
        with self.assertRaises(durable.Rejected): self.inspect()

    def test_later_job_record_cannot_hide_unreturned_reload(self):
        from host_recovery.manager_jobs import record_names
        operation = self.pending()
        prefix, _, response = self.reload_records(operation, returned=False)
        name, _ = record_names(operation['sequence'], 'forward')
        self.write(name, {'schema':'host-recovery-manager-stop-pending-v1',
            'operation_id':operation['operation_id'], 'role':'forward', 'target_sha256':'f'*64,
            'manager_owner':':1.7', 'bus_id':'a'*32, 'unit':'fixed.service', 'invocation_id':'b'*32})
        with self.assertRaises(durable.Rejected): self.inspect()
        self.write(prefix+'return.json', response)
        report = self.inspect()
        self.assertEqual(report['operations'][0]['manager_jobs'][0]['classification'], 'submission_unreturned')
        self.closed(report)

    def test_sigkill_at_phase_publication_retains_only_historical_correspondence(self):
        # The child exercises real journal publication, not manager Reload.
        for phase in ('pending', 'return'):
            with self.subTest(phase=phase):
                path = self.root/phase
                path.mkdir(mode=0o700)
                process = subprocess.Popen([sys.executable, '-I', '-u', '-c', RELOAD_CHILD,
                    str(Path(__file__).resolve().parents[1]), str(path), phase],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    with selectors.DefaultSelector() as ready:
                        ready.register(process.stdout, selectors.EVENT_READ)
                        self.assertTrue(ready.select(10), 'child did not reach reload phase publication')
                    self.assertEqual(process.stdout.readline(), b'PUBLISHED\n')
                    process.kill()
                    _, stderr = process.communicate(timeout=10)
                    self.assertEqual(stderr, b'')
                    self.assertLess(process.returncode, 0)
                    before = {p.name:p.read_bytes() for p in path.iterdir()}
                    with durable.directory(str(path), private=True) as fd:
                        report = history.inspect_history(fd, inputs=self.inputs, topology_sha256='c'*64,
                            current_epoch={**self.epoch, 'boot_id':'boot-new'}, uid=os.geteuid(), gid=os.getegid())
                    self.assertEqual(report['operations'][0]['mask_reload']['classification'],
                                     'unreturned' if phase == 'pending' else 'returned_unproven')
                    self.closed(report)
                    self.assertTrue(report['boot_changed'])
                    self.assertEqual(before, {p.name:p.read_bytes() for p in path.iterdir()})
                finally:
                    if process.poll() is None: process.kill()
                    process.communicate(timeout=10)

    def test_complete_supported_history_fits_bounded_capture_without_omitting_records(self):
        from host_recovery import broker_operations, manager_jobs
        operations = []
        for method in sorted(broker_operations.METHODS):
            operation = self.pending(method)
            self.journal.returned(operation, result='returned')
            operations.append(operation)
        number = 40
        for operation in operations:
            roles = manager_jobs.roles_for_method(operation['method'])
            if not roles: continue
            self.reload_records(operation)
            for role in roles:
                number += 1
                names = manager_jobs.record_names(operation['sequence'], role)
                pending = {'schema':'host-recovery-manager-stop-pending-v1', 'operation_id':operation['operation_id'],
                    'role':role, 'target_sha256':'f'*64, 'manager_owner':':1.7', 'bus_id':'a'*32,
                    'unit':role+'.service', 'invocation_id':'b'*32}
                returned = {'schema':'host-recovery-manager-stop-return-v1',
                    'pending_sha256':durable.digest(durable.canonical(pending)), 'job_id':number,
                    'job_path':manager_jobs.JOB_PREFIX+str(number), 'retirement_proven':False}
                completion = {'schema':'host-recovery-manager-completion-v1',
                    'return_sha256':durable.digest(durable.canonical(returned)), 'bus_id':pending['bus_id'],
                    'manager_owner':pending['manager_owner'], 'job_id':number, 'job_path':returned['job_path'],
                    'unit':pending['unit'], 'result':'done', 'sender_cookie':number+100, 'retirement_proven':False}
                self.write(names[0], pending)
                self.write(names[1], returned)
                self.write(manager_jobs.completion_name(operation['sequence'], role), completion)
        before = self.records()
        self.assertEqual(len(before), 26)
        report = self.inspect()
        self.assertEqual(report['recorded_operation_count'], len(operations))
        self.closed(report)
        self.assertEqual(before, self.records())

    def test_report_contains_no_target_path_or_effective_runtime_claim(self):
        self.reload_records(self.pending())
        report = self.inspect()
        text = durable.canonical(report).decode()
        self.assertNotIn(str(self.path), text)
        self.assertNotIn('effective_masks_observed', text)
        self.assertNotIn('manager_reload_returned', text)
        self.closed(report)
