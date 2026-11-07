"""Real synthetic peers/private records; SCRIPTED system-bus/manager boundaries.

These tests never connect to the host bus, stop services or cancel manager jobs.
Disappearance is intentionally not retirement, and every execution deny remains.
"""
import errno
import unittest
from unittest.mock import patch

from host_recovery import broker_history, durable, manager_jobs, topology
import test_broker_runtime as fixture


class RuntimeJobTrackingTests(unittest.TestCase):
    line = fixture.RuntimeContainmentTests.line
    connect = fixture.RuntimeContainmentTests.connect
    command = fixture.RuntimeContainmentTests.command
    write = fixture.RuntimeContainmentTests.write
    run_command = fixture.RuntimeContainmentTests.run_command
    make_engine = fixture.RuntimeContainmentTests.make_engine
    setUp = fixture.RuntimeContainmentTests.setUp
    make_adapter = fixture.RuntimeContainmentTests.make_adapter
    run_effect = fixture.RuntimeContainmentTests.run_effect
    contain = fixture.RuntimeContainmentTests.contain
    refused = fixture.RuntimeContainmentTests.refused

    def job_row(self, role='dockerd', number=41, kind='stop'):
        return [number, self.units[role].unit, kind, 'running', manager_jobs.JOB_PREFIX+str(number),
                manager_jobs.MANAGER_PATH+'/unit/fixture_service']

    def records(self):
        return {p.name:p.read_bytes() for p in self.state.iterdir()}

    def test_each_fixed_stop_retains_actual_job_identity_not_retirement(self):
        receipt = self.contain()
        for index, role in enumerate(topology.RUNTIME_ROLES):
            pending, returned = manager_jobs.record_names(2, role)
            value = durable.decode((self.state / pending).read_bytes())
            observed = durable.decode((self.state / returned).read_bytes())
            self.assertEqual(value['manager_owner'], ':1.7')
            self.assertEqual(value['bus_id'], self.bus_id)
            self.assertEqual(value['invocation_id'], self.units[role].invocation_id)
            self.assertEqual(observed['job_id'], 41+index)
            self.assertEqual(observed['job_path'], manager_jobs.JOB_PREFIX+str(41+index))
            self.assertIs(observed['retirement_proven'], False)
        self.assertFalse(receipt['manager_jobs_retired'])
        self.assertFalse(receipt['pending_drained'])
        self.assertTrue(all(x == 'absent_not_retired' for x in receipt['manager_job_observations'].values()))

    def test_known_pending_stop_is_observed_but_does_not_prove_runtime_empty(self):
        actual = self.run_effect
        def run(argv, *, deadline):
            raw = actual(argv, deadline=deadline)
            if 'StopUnit' in argv and argv[-2] == self.units['dockerd'].unit:
                self.rows['dockerd']['Job'] = '41'
                self.manager_rows = [self.job_row()]
            return raw
        self.transport.run = run
        receipt = self.contain()
        self.assertEqual(receipt['manager_job_observations']['dockerd'], 'pending_observed')
        self.assertFalse(receipt['runtime_empty_observed'])
        self.assertFalse(receipt['manager_jobs_retired'])
        self.assertEqual(self.kill_file.read_bytes(), b'1\n')

    def test_pending_listjobs_cannot_hide_behind_zero_unit_job_property(self):
        actual = self.run_effect
        def run(argv, *, deadline):
            raw = actual(argv, deadline=deadline)
            if 'StopUnit' in argv and argv[-2] == self.units['dockerd'].unit:
                self.manager_rows = [self.job_row()]
            return raw
        self.transport.run = run
        receipt = self.contain()
        self.assertEqual(receipt['manager_job_observations']['dockerd'], 'pending_observed')
        self.assertFalse(receipt['runtime_empty_observed'])
        self.assertFalse(receipt['pending_drained'])

    def test_untracked_job_inventory_refuses_even_when_unit_job_is_zero(self):
        self.manager_rows = [self.job_row(number=88, kind='start')]
        self.refused()
        self.assertEqual(self.effects, [])
        self.assertFalse((self.state / 'operation-02-pending.json').exists())

    def test_unrelated_jobs_are_not_stopped_or_cancelled(self):
        row = self.job_row(number=88, kind='start')
        row[1] = 'unrelated.socket'
        self.manager_rows = [row]
        self.contain()
        self.assertEqual(len(self.effects), 2)
        self.assertFalse(any('Cancel' in str(call) or 'unrelated.socket' in call for call in self.bus_calls))

    def test_manager_name_replacement_after_stop_prevents_every_later_effect(self):
        self.effect_hook = lambda: setattr(self, 'manager_owner', ':1.8')
        self.refused()
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.kill_file.read_bytes(), b'')
        self.assertTrue((self.state / 'operation-02-job-01-return.json').exists())

    def test_bus_restart_with_reused_unique_name_is_not_adopted(self):
        self.effect_hook = lambda: setattr(self, 'bus_id', 'b'*32)
        self.refused()
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_name_or_bus_drift_at_pending_fsync_prevents_stop(self):
        for kind in ('name', 'bus'):
            with self.subTest(kind=kind):
                self.setUp()
                reached = []
                def change(point):
                    if point == 'readback' and (self.state / 'operation-02-job-01-pending.json').exists():
                        reached.append(point)
                        if kind == 'name': self.manager_owner = ':1.8'
                        else: self.bus_id = 'b'*32
                self.operations.fault = change
                self.refused()
                self.assertEqual(reached, ['readback'])
                self.assertEqual(self.effects, [])

    def test_original_peer_or_lock_loss_in_bus_read_prevents_stop(self):
        for action in ('close', 'unlock'):
            with self.subTest(action=action):
                self.setUp()
                reached = []
                def lose():
                    if self.bus_calls[-1][8] == 'ListJobs' and not reached:
                        reached.append(action)
                        self.command(self.child, action)
                self.bus_hook = lose
                self.refused()
                self.assertEqual(reached, [action])
                self.assertEqual(self.effects, [])

    def test_reused_job_id_on_another_unit_or_kind_refuses(self):
        for mismatch in ('unit', 'kind'):
            with self.subTest(mismatch=mismatch):
                self.setUp()
                actual = self.run_effect
                def run(argv, *, deadline):
                    raw = actual(argv, deadline=deadline)
                    if 'StopUnit' in argv:
                        row = self.job_row()
                        if mismatch == 'unit': row[1] = 'other.service'
                        else: row[2] = 'start'
                        self.manager_rows = [row]
                    return raw
                self.transport.run = run
                self.refused()
                self.assertEqual(len(self.effects), 1)
                self.assertEqual(self.manager_rows[0][0], 41)
                self.assertTrue((self.state / 'operation-02-job-01-return.json').exists())
                self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_same_job_id_returned_for_second_unit_is_unresolved(self):
        actual = self.run_effect
        def run(argv, *, deadline):
            raw = actual(argv, deadline=deadline)
            if 'StopUnit' in argv: return durable.canonical({'type':'o', 'data':[manager_jobs.JOB_PREFIX+'41']})
            return raw
        self.transport.run = run
        self.refused()
        self.assertEqual(len(self.effects), 2)
        self.assertFalse((self.state / 'operation-02-job-02-return.json').exists())
        self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_job_pending_and_return_faults_reach_each_storage_boundary(self):
        for suffix in ('pending', 'return'):
            for point in ('create', 'write', 'file-fsync', 'rename', 'directory-fsync', 'readback'):
                for code in (errno.EIO, errno.ENOSPC):
                    with self.subTest(suffix=suffix, point=point, code=code):
                        self.setUp()
                        reached = []
                        actual = self.operations._write
                        def fail(here):
                            if here == point:
                                reached.append(here)
                                raise OSError(code, 'restricted')
                        def writing(name, value):
                            if name == 'operation-02-job-01-'+suffix+'.json': self.operations.fault = fail
                            return actual(name, value)
                        with patch.object(self.operations, '_write', side_effect=writing): self.refused()
                        self.assertEqual(reached, [point])
                        self.assertEqual(len(self.effects), 0 if suffix == 'pending' else 1)
                        self.assertEqual(self.kill_file.read_bytes(), b'')
                        self.assertTrue((self.state / 'operation-02-pending.json').exists())

    def test_job_return_is_not_a_replay_permit(self):
        self.contain()
        before = self.records()
        prior_effects = list(self.effects)
        self.adapter = self.make_adapter()
        self.refused()
        self.assertEqual(self.effects, prior_effects)
        self.assertEqual(self.records(), before)

    def test_malformed_stop_reply_keeps_unreturned_job_without_kernel_kill(self):
        for response in ({'type':'s','data':['not-a-job']}, {'type':'o','data':[manager_jobs.JOB_PREFIX+'0']},
                         {'type':'o','data':[manager_jobs.JOB_PREFIX+'4294967296']}):
            with self.subTest(response=response):
                self.setUp()
                actual = self.run_effect
                def run(argv, *, deadline):
                    raw = actual(argv, deadline=deadline)
                    return durable.canonical(response) if 'StopUnit' in argv else raw
                self.transport.run = run
                self.refused()
                self.assertEqual(len(self.effects), 1)
                self.assertTrue((self.state / 'operation-02-job-01-pending.json').exists())
                self.assertFalse((self.state / 'operation-02-job-01-return.json').exists())
                self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_expiry_after_bus_reply_has_no_new_allowance(self):
        reached = []
        def expire():
            if self.bus_calls[-1][8] == 'ListJobs':
                reached.append('ListJobs')
                self.now = 1090.
        self.bus_hook = expire
        self.refused()
        self.assertEqual(reached, ['ListJobs'])
        self.assertEqual(self.effects, [])

    def test_helper_path_drift_during_bus_read_prevents_stop(self):
        self.bus_hook = lambda: setattr(self.adapter.jobs, 'busctl', '/different/busctl')
        self.refused()
        self.assertEqual(self.effects, [])

    def test_unit_invocation_drift_in_last_bus_read_prevents_stop(self):
        reached = []
        def change():
            if self.bus_calls[-1][8] == 'ListJobs' and (self.state / 'operation-02-job-01-pending.json').exists():
                reached.append('ListJobs')
                self.rows['dockerd']['InvocationID'] = 'b'*32
        self.bus_hook = change
        self.refused()
        self.assertEqual(reached, ['ListJobs'])
        self.assertEqual(self.effects, [])
        self.assertTrue((self.state / 'operation-02-job-01-pending.json').exists())

    def test_helper_byte_pin_drift_is_not_a_path_only_match(self):
        self.adapter.jobs.read_helper_hash = lambda _: 'e'*64
        self.refused()
        self.assertEqual(self.effects, [])
        self.assertEqual(self.bus_calls, [])

    def test_missing_or_different_topology_helper_pin_refuses(self):
        value = self.topology.manifest()
        value['tools'].pop('busctl')
        with self.assertRaises(durable.Rejected): topology.Topology(durable.canonical(value))
        self.adapter.jobs.busctl_sha256 = 'e'*64
        with self.assertRaises(durable.Rejected): self.make_adapter(jobs=self.adapter.jobs)

    def test_history_classifies_submitted_jobs_without_grant(self):
        self.contain()
        records = broker_history._capture(self.operations.fd, uid=self.operations._owner[0], gid=self.operations._owner[1])
        epoch, operations = broker_history._classify(records, binding=self.binding)
        self.assertEqual(epoch, self.epoch)
        jobs = operations[-1]['manager_jobs']
        self.assertEqual([x['job_id'] for x in jobs], [41, 42])
        self.assertTrue(all(x['classification'] == 'submitted_unproven' and not x['retirement_proven'] for x in jobs))

    def test_history_preserves_lost_job_reply_as_unreturned(self):
        actual = self.run_effect
        def run(argv, *, deadline):
            raw = actual(argv, deadline=deadline)
            if 'StopUnit' in argv: raise OSError(errno.EIO, 'restricted')
            return raw
        self.transport.run = run
        self.refused()
        _, operations = broker_history._classify(self.records(), binding=self.binding)
        self.assertEqual(operations[-1]['manager_jobs'], [dict(role='dockerd', classification='submission_unreturned',
                                                             job_id=None, retirement_proven=False)])

    def test_history_refuses_conflicting_bus_job_identity_or_outer_return(self):
        self.contain()
        original = self.records()
        for name, key, value in (
            ('operation-02-job-02-pending.json','manager_owner',':1.9'),
            ('operation-02-job-02-pending.json','bus_id','b'*32),
            ('operation-02-job-02-return.json','job_id',99),
            ('operation-02-job-02-return.json','retirement_proven',True)):
            with self.subTest(key=key):
                records = dict(original)
                row = durable.decode(records[name]); row[key] = value
                records[name] = durable.canonical(row)
                with self.assertRaises(durable.Rejected): broker_history._classify(records, binding=self.binding)
        records = dict(original)
        records.pop('operation-02-job-01-return.json')
        with self.assertRaises(durable.Rejected): broker_history._classify(records, binding=self.binding)


class ManagerJobReplyTests(unittest.TestCase):
    def job_row(self):
        return [41, 'fixture.service', 'stop', 'running', manager_jobs.JOB_PREFIX+'41',
                manager_jobs.MANAGER_PATH+'/unit/fixture_2eservice']

    def test_typed_listjobs_accepts_bounded_unique_waiting_and_running_rows(self):
        row = self.job_row()
        for state in ('waiting','running'):
            row[3] = state
            value = manager_jobs.jobs_reply(durable.canonical({'type':'a(usssoo)', 'data':[[row]]}))
            self.assertEqual(value, {41:tuple(row)})

    def test_malformed_duplicate_unknown_or_overflowed_inventory_refuses(self):
        for index, value in ((0,True),(0,0),(0,4294967296),(1,'bad\nservice'),(2,'StopUnit'),(3,'done'),
                             (4,manager_jobs.JOB_PREFIX+'42'),(5,'/other/unit')):
            with self.subTest(index=index, value=value):
                row = self.job_row(); row[index] = value
                with self.assertRaises(durable.Rejected):
                    manager_jobs.jobs_reply(durable.canonical({'type':'a(usssoo)', 'data':[[row]]}))
        for rows in ([self.job_row(), self.job_row()], [self.job_row()]*(manager_jobs.MAX_JOBS+1)):
            with self.assertRaises(durable.Rejected):
                manager_jobs.jobs_reply(durable.canonical({'type':'a(usssoo)', 'data':[rows]}))

    def test_wrong_signature_extra_fields_duplicate_keys_and_raw_limits_refuse(self):
        for raw in (b'{"type":"o","data":[[]]}', b'{"type":"a(usssoo)","data":[]}',
                    b'{"type":"a(usssoo)","data":[[]],"extra":1}',
                    b'{"type":"a(usssoo)","data":[[]],"data":[[]]}', b'x'*65537):
            with self.subTest(raw_size=len(raw)):
                with self.assertRaises(durable.Rejected): manager_jobs.jobs_reply(raw)
