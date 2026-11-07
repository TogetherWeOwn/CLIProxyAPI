"""Synthetic retained kill histories, not cold recovery or process-death proof."""
import unittest

from host_recovery import durable, manager_jobs, runtime_kill
import test_broker_history as fixture
import test_mask_reload_history as reload_fixture


class RuntimeKillHistoryTests(unittest.TestCase):
    setUp = fixture.BrokerHistoryTests.setUp
    inspect = fixture.BrokerHistoryTests.inspect
    pending = fixture.BrokerHistoryTests.pending
    write = fixture.BrokerHistoryTests.write
    records = fixture.BrokerHistoryTests.records
    closed = fixture.BrokerHistoryTests.closed
    reload_records = reload_fixture.MaskReloadHistoryTests.reload_records

    def prepare(self, *, phase=2, forward=True, method='cold_quiesce_runtime', version=1):
        if forward:
            previous = self.pending('contain_forward')
            self.journal.returned(previous, result='returned')
        operation = self.pending(method)
        self.reload_records(operation)
        completions = {}
        for number, role in enumerate(('dockerd', 'containerd'), 41):
            names = manager_jobs.record_names(operation['sequence'], role)
            pending = {'schema':'host-recovery-manager-stop-pending-v1', 'operation_id':operation['operation_id'],
                'role':role, 'target_sha256':'f'*64, 'manager_owner':':1.7', 'bus_id':'a'*32,
                'unit':'fixed-'+role+'.service', 'invocation_id':'b'*32}
            returned = {'schema':'host-recovery-manager-stop-return-v1',
                'pending_sha256':durable.digest(durable.canonical(pending)), 'job_id':number,
                'job_path':manager_jobs.JOB_PREFIX+str(number), 'retirement_proven':False}
            completed = {'schema':'host-recovery-manager-completion-v1',
                'return_sha256':durable.digest(durable.canonical(returned)), 'bus_id':pending['bus_id'],
                'manager_owner':pending['manager_owner'], 'job_id':number, 'job_path':returned['job_path'],
                'unit':pending['unit'], 'result':'done', 'sender_cookie':number+100, 'retirement_proven':False}
            self.write(names[0], pending)
            self.write(names[1], returned)
            self.write(manager_jobs.completion_name(operation['sequence'],role), completed)
            completions[role] = durable.digest(durable.canonical(completed))
        pending = {'schema':'host-recovery-runtime-kill-pending-v1', 'operation_id':operation['operation_id'],
            'domain_sha256':'e'*64, 'stop_completions_sha256':completions}
        returned = {'schema':'host-recovery-runtime-kill-return-v1',
            'pending_sha256':durable.digest(durable.canonical(pending)),
            'recursive_domain_kill_returned':True, 'pending_drained':False}
        empty = {'schema':'host-recovery-runtime-kill-empty-v1',
            'return_sha256':durable.digest(durable.canonical(returned)), 'domain_empty_observed':True,
            'runtime_containment_coverage_proven':False}
        if version >= 2:
            pending.update(schema='host-recovery-runtime-kill-pending-v%d'%version, domain_freeze_required=True)
            if version >= 3: pending['domain_descendants_seal_required'] = True
            returned.update(schema='host-recovery-runtime-kill-return-v%d'%version, domain_frozen_observed=True,
                            pending_sha256=durable.digest(durable.canonical(pending)))
            if version >= 3: returned['domain_descendants_sealed_observed'] = True
            empty.update(schema='host-recovery-runtime-kill-empty-v%d'%version, domain_frozen_observed=True,
                         return_sha256=durable.digest(durable.canonical(returned)))
            if version >= 3: empty['domain_descendants_sealed_observed'] = True
        names, values = runtime_kill.record_names(operation['sequence']), (pending, returned, empty)
        for name,value in zip(names[:phase+1],values): self.write(name,value)
        return operation, names, values

    def test_sealed_v3_history_keeps_each_phase_uncertain_without_authority(self):
        for phase, expected in enumerate(('unreturned','returned_without_empty_observation','empty_observed_unproven')):
            with self.subTest(phase=phase):
                self.setUp()
                self.prepare(version=3, phase=phase)
                before = self.records()
                report = self.inspect()
                self.assertEqual(report['operations'][1]['runtime_kill']['classification'], expected)
                self.closed(report)
                self.assertEqual(before, self.records())

    def test_sealed_history_requires_literal_flags_and_exact_version_links(self):
        for index,field in ((0,'domain_descendants_seal_required'),(1,'domain_descendants_sealed_observed'),
                            (2,'domain_descendants_sealed_observed')):
            for action in ('missing','integer','false','version'):
                with self.subTest(index=index,action=action):
                    self.setUp()
                    _, names, values = self.prepare(version=3)
                    if action == 'missing': values[index].pop(field)
                    elif action == 'version': values[index]['schema'] = values[index]['schema'].replace('-v3','-v2')
                    else: values[index][field] = 1 if action == 'integer' else False
                    values[1]['pending_sha256'] = durable.digest(durable.canonical(values[0]))
                    values[2]['return_sha256'] = durable.digest(durable.canonical(values[1]))
                    for name,value in zip(names,values): self.write(name,value)
                    with self.assertRaises(durable.Rejected): self.inspect()

    def test_legacy_histories_cannot_smuggle_descendant_seal_claims(self):
        for version in (1,2):
            for index,field in ((0,'domain_descendants_seal_required'),(1,'domain_descendants_sealed_observed'),
                                (2,'domain_descendants_sealed_observed')):
                with self.subTest(version=version,index=index):
                    self.setUp()
                    _, names, values = self.prepare(version=version)
                    values[index][field] = True
                    values[1]['pending_sha256'] = durable.digest(durable.canonical(values[0]))
                    values[2]['return_sha256'] = durable.digest(durable.canonical(values[1]))
                    for name,value in zip(names,values): self.write(name,value)
                    with self.assertRaises(durable.Rejected): self.inspect()

    def test_freezer_v2_history_retains_each_uncertain_phase_without_authority(self):
        for phase, expected in enumerate(('unreturned','returned_without_empty_observation','empty_observed_unproven')):
            with self.subTest(phase=phase):
                self.setUp()
                self.prepare(version=2, phase=phase)
                before = self.records()
                report = self.inspect()
                self.assertEqual(report['operations'][1]['runtime_kill']['classification'],expected)
                self.closed(report)
                self.assertEqual(before,self.records())

    def test_freezer_history_flags_are_literal_and_mixed_versions_refuse(self):
        for index,field in ((0,'domain_freeze_required'),(1,'domain_frozen_observed'),(2,'domain_frozen_observed')):
            for action in ('missing','integer','false','version'):
                with self.subTest(index=index,action=action):
                    self.setUp()
                    _, names, values = self.prepare(version=2)
                    changed = dict(values[index])
                    if action == 'missing': changed.pop(field)
                    elif action == 'version': changed['schema'] = changed['schema'].replace('-v2','-v1')
                    else: changed[field] = 1 if action == 'integer' else False
                    values[index].clear(); values[index].update(changed)
                    # Keep digest links valid so each negative reaches schema/flag validation.
                    values[1]['pending_sha256'] = durable.digest(durable.canonical(values[0]))
                    values[2]['return_sha256'] = durable.digest(durable.canonical(values[1]))
                    for name,value in zip(names,values): self.write(name,value)
                    with self.assertRaises(durable.Rejected): self.inspect()

    def test_kill_only_v1_history_cannot_smuggle_a_freezer_claim(self):
        for index,field in ((0,'domain_freeze_required'),(1,'domain_frozen_observed'),(2,'domain_frozen_observed')):
            with self.subTest(index=index):
                self.setUp()
                _, names, values = self.prepare()
                values[index][field] = True
                values[1]['pending_sha256'] = durable.digest(durable.canonical(values[0]))
                values[2]['return_sha256'] = durable.digest(durable.canonical(values[1]))
                for name,value in zip(names,values): self.write(name,value)
                with self.assertRaises(durable.Rejected): self.inspect()

    def test_each_phase_is_read_only_and_never_reconstructs_authority(self):
        for phase, expected in enumerate(('unreturned','returned_without_empty_observation','empty_observed_unproven')):
            with self.subTest(phase=phase):
                self.setUp()
                self.prepare(phase=phase)
                before = self.records()
                report = self.inspect()
                self.assertEqual(report['operations'][1]['runtime_kill']['classification'], expected)
                self.assertFalse(report['operations'][1]['runtime_kill']['pending_drained'])
                self.closed(report)
                self.assertEqual(before, self.records())

    def test_cross_boot_history_never_renews_original_deadline(self):
        self.prepare()
        before = self.records()
        report = self.inspect(current_epoch={**self.epoch,'boot_id':'new-boot'})
        self.assertEqual(report['state'], 'cross_boot_continuation_required')
        self.closed(report)
        self.assertEqual(before, self.records())

    def test_orphan_staged_or_noncanonical_records_are_retained_and_rejected(self):
        for action in ('pending','return','stage','noncanonical'):
            with self.subTest(action=action):
                self.setUp()
                _, names, _ = self.prepare()
                if action in ('pending','return'): (self.path/names[int(action=='return')]).unlink()
                elif action == 'stage': self.write('.stage-'+names[0], {})
                else: (self.path/names[2]).write_bytes((self.path/names[2]).read_bytes()+b' ')
                before = self.records()
                with self.assertRaises(durable.Rejected): self.inspect()
                self.assertEqual(before, self.records())

    def test_exact_shapes_literal_flags_and_digest_links_are_required(self):
        changes = ((0,'schema','other'), (0,'schema',[]), (0,'operation_id','f'*64), (0,'domain_sha256',True),
            (0,'stop_completions_sha256',{}), (0,'extra',True), (1,'pending_sha256','f'*64),
            (1,'recursive_domain_kill_returned',1), (1,'pending_drained',0), (1,'extra',True),
            (2,'return_sha256','f'*64), (2,'domain_empty_observed',1),
            (2,'runtime_containment_coverage_proven',0), (2,'extra',True))
        for index,field,value in changes:
            with self.subTest(index=index, field=field):
                self.setUp()
                _, names, values = self.prepare()
                self.write(names[index], {**values[index],field:value})
                with self.assertRaises(durable.Rejected): self.inspect()

    def test_both_matching_done_completions_must_precede_kill_history(self):
        for action in ('missing','changed','failed'):
            with self.subTest(action=action):
                self.setUp()
                operation, _, _ = self.prepare()
                name = manager_jobs.completion_name(operation['sequence'],'containerd')
                if action == 'missing': (self.path/name).unlink()
                else:
                    value = durable.decode((self.path/name).read_bytes())
                    value['result' if action=='failed' else 'sender_cookie'] = 'failed' if action=='failed' else 999
                    self.write(name, value)
                with self.assertRaises(durable.Rejected): self.inspect()

    def test_original_forward_return_and_runtime_method_are_required(self):
        self.prepare(forward=False)
        with self.assertRaises(durable.Rejected): self.inspect()
        self.setUp()
        self.prepare(method='dispatch_recovery')
        with self.assertRaises(durable.Rejected): self.inspect()

    def test_uncertain_reload_cannot_be_hidden_by_kill_records(self):
        operation, _, _ = self.prepare()
        (self.path/('operation-%02d-mask-reload-return.json'%operation['sequence'])).unlink()
        with self.assertRaises(durable.Rejected): self.inspect()

    def test_outer_return_cannot_hide_unreturned_kill_or_missing_empty(self):
        for phase in (0,1):
            with self.subTest(phase=phase):
                self.setUp()
                operation, _, _ = self.prepare(phase=phase)
                # Synthetic historical publication, not the live writer's return.
                self.write('operation-%02d-return.json'%operation['sequence'],
                    {'schema':'host-recovery-broker-return-v1', 'operation_id':operation['operation_id'],
                     'result':'returned', 'pending_drained':False})
                with self.assertRaises(durable.Rejected): self.inspect()

    def test_full_empty_history_is_still_unproven_after_outer_return(self):
        operation, _, _ = self.prepare()
        self.write('operation-%02d-return.json'%operation['sequence'],
                    {'schema':'host-recovery-broker-return-v1', 'operation_id':operation['operation_id'],
                     'result':'returned', 'pending_drained':False})
        report = self.inspect()
        self.assertEqual(report['operations'][1]['classification'], 'returned_unproven')
        self.assertEqual(report['operations'][1]['runtime_kill']['classification'], 'empty_observed_unproven')
        self.closed(report)
