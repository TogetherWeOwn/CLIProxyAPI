"""Strict retained cancellation correspondence; no replay or live authority."""
import unittest

from host_recovery import durable, job_cancellation as cancellation
import test_broker_history as fixture
import test_mask_reload_history as reload_fixture


class CancellationHistoryTests(unittest.TestCase):
    setUp = fixture.BrokerHistoryTests.setUp
    inspect = fixture.BrokerHistoryTests.inspect
    pending = fixture.BrokerHistoryTests.pending
    write = fixture.BrokerHistoryTests.write
    records = fixture.BrokerHistoryTests.records
    closed = fixture.BrokerHistoryTests.closed
    reload_records = reload_fixture.MaskReloadHistoryTests.reload_records

    def cancel_records(self, operation, *, phase=2, role='forward', number=41):
        names = cancellation.record_names(operation['sequence'], role)
        pending = {'schema':'host-recovery-job-cancel-pending-v1', 'operation_id':operation['operation_id'],
            'role':role, 'target_sha256':'e'*64, 'bus_id':'a'*32, 'manager_owner':':1.7',
            'job':[number, 'fixed-'+role+'.service', 'start', 'waiting',
                   '/org/freedesktop/systemd1/job/'+str(number), '/org/freedesktop/systemd1/unit/fixed_service']}
        returned = {'schema':'host-recovery-job-cancel-return-v1',
            'pending_sha256':durable.digest(durable.canonical(pending)),
            'cancellation_returned':True, 'pending_drained':False}
        completed = {'schema':'host-recovery-job-cancel-completion-v1',
            'return_sha256':durable.digest(durable.canonical(returned)), 'job_id':number,
            'job_path':pending['job'][4], 'unit':pending['job'][1], 'result':'canceled', 'sender_cookie':10,
            'retirement_proven':False}
        values = (pending, returned, completed)
        for name, value in zip(names[:phase+1], values): self.write(name, value)
        return names, values

    def test_pending_return_and_canceled_completion_never_grant_retirement(self):
        for phase, expected in enumerate(('unreturned', 'return_without_completion', 'canceled_observed')):
            with self.subTest(phase=phase):
                self.setUp()
                self.cancel_records(self.pending(), phase=phase)
                before = self.records()
                report = self.inspect()
                item = report['operations'][0]['waiting_start_cancellations'][0]
                self.assertEqual(item['classification'], expected)
                self.assertFalse(item['retirement_proven'])
                self.closed(report)
                self.assertEqual(before, self.records())

    def test_later_reload_or_outer_return_cannot_hide_uncertain_cancellation(self):
        for phase in (0, 1):
            for action in ('reload', 'outer'):
                with self.subTest(phase=phase, action=action):
                    self.setUp()
                    operation = self.pending()
                    if action == 'outer': self.journal.returned(operation, result='returned')
                    self.cancel_records(operation, phase=phase)
                    if action == 'reload': self.reload_records(operation)
                    with self.assertRaises(durable.Rejected): self.inspect()

    def test_completed_cancellation_composes_with_reload_without_replay(self):
        operation = self.pending()
        self.cancel_records(operation)
        self.reload_records(operation)
        before = self.records()
        report = self.inspect(current_epoch={**self.epoch, 'boot_id':'boot-new'})
        self.closed(report)
        self.assertTrue(report['boot_changed'])
        self.assertEqual(report['operations'][0]['mask_reload']['classification'], 'returned_unproven')
        self.assertEqual(before, self.records())

    def test_orphan_staged_or_noncanonical_records_are_retained_and_rejected(self):
        for action in ('orphan', 'stage', 'noncanonical'):
            with self.subTest(action=action):
                self.setUp()
                names, _ = self.cancel_records(self.pending())
                if action == 'orphan': (self.path/names[0]).unlink()
                elif action == 'stage': self.write('.stage-'+names[1], {})
                else: (self.path/names[0]).write_bytes((self.path/names[0]).read_bytes()+b' ')
                before = self.records()
                with self.assertRaises(durable.Rejected): self.inspect()
                self.assertEqual(before, self.records())

    def test_pending_return_completion_shapes_types_and_digest_links_are_strict(self):
        changes = ((0,'operation_id','f'*64), (0,'bus_id','wrong'), (0,'role','dockerd'),
                   (0,'target_sha256',True), (0,'manager_owner','manager'), (0,'extra',True),
                   (1,'pending_sha256','f'*64), (1,'cancellation_returned',1), (1,'pending_drained',0),
                   (2,'return_sha256','f'*64), (2,'job_id',True), (2,'result','done'),
                   (2,'sender_cookie',True), (2,'sender_cookie',0), (2,'retirement_proven',0))
        for index, field, value in changes:
            with self.subTest(index=index, field=field, value=value):
                self.setUp()
                names, values = self.cancel_records(self.pending())
                self.write(names[index], {**values[index], field:value})
                with self.assertRaises(durable.Rejected): self.inspect()

    def test_only_supported_containment_roles_and_exact_waiting_job_are_accepted(self):
        for action in ('method', 'role', 'state', 'kind', 'number', 'path'):
            with self.subTest(action=action):
                self.setUp()
                names, values = self.cancel_records(self.pending('dispatch_recovery' if action=='method' else 'contain_forward'),
                    role='dockerd' if action=='role' else 'forward')
                row = values[0]
                if action in ('state', 'kind', 'number', 'path'):
                    index, value = {'state':(3,'running'), 'kind':(2,'stop'), 'number':(0,True), 'path':(4,'/wrong')}[action]
                    row['job'][index] = value
                    self.write(names[0], row)
                with self.assertRaises(durable.Rejected): self.inspect()

    def test_two_runtime_roles_have_distinct_ids_and_no_effect_after_uncertainty(self):
        operation = self.pending('cold_quiesce_runtime')
        self.cancel_records(operation, role='containerd', number=41)
        self.cancel_records(operation, role='dockerd', number=42)
        report = self.inspect()
        self.assertEqual(len(report['operations'][0]['waiting_start_cancellations']), 2)
        self.closed(report)
        self.setUp()
        operation = self.pending('cold_quiesce_runtime')
        self.cancel_records(operation, role='containerd', phase=1, number=41)
        self.cancel_records(operation, role='dockerd', number=42)
        with self.assertRaises(durable.Rejected): self.inspect()

    def test_full_supported_history_including_all_cancellations_fits_bound(self):
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
                self.cancel_records(operation, role=role, number=number)
                names = manager_jobs.record_names(operation['sequence'], role)
                pending = {'schema':'host-recovery-manager-stop-pending-v1', 'operation_id':operation['operation_id'],
                    'role':role, 'target_sha256':'f'*64, 'manager_owner':':1.7', 'bus_id':'a'*32,
                    'unit':'fixed-'+role+'.service', 'invocation_id':'b'*32}
                returned = {'schema':'host-recovery-manager-stop-return-v1',
                    'pending_sha256':durable.digest(durable.canonical(pending)), 'job_id':number+100,
                    'job_path':manager_jobs.JOB_PREFIX+str(number+100), 'retirement_proven':False}
                completed = {'schema':'host-recovery-manager-completion-v1',
                    'return_sha256':durable.digest(durable.canonical(returned)), 'bus_id':pending['bus_id'],
                    'manager_owner':pending['manager_owner'], 'job_id':number+100, 'job_path':returned['job_path'],
                    'unit':pending['unit'], 'result':'done', 'sender_cookie':number+200, 'retirement_proven':False}
                self.write(names[0], pending)
                self.write(names[1], returned)
                self.write(manager_jobs.completion_name(operation['sequence'], role), completed)
        report = self.inspect()
        self.closed(report)
        self.assertEqual(len(self.records()), 35)
        self.assertEqual(sum(len(item.get('waiting_start_cancellations', [])) for item in report['operations']), 3)
