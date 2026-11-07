"""Original peer/flock/private files; SCRIPTED manager, native ABI and cgroups.

No host bus, systemd, daemon, activation exclusion or recovery qualification.
"""
from dataclasses import replace
import errno
import unittest
from unittest.mock import Mock, patch

from host_recovery import broker_containment, broker_history, durable, manager_bus, manager_jobs
from host_recovery.protected_file import ProtectedFile
import test_broker_containment as fixture
from test_manager_bus import ScriptedConnection


class ForwardCompletionTests(unittest.TestCase):
    line = fixture.ForwardContainmentTests.line
    connect = fixture.ForwardContainmentTests.connect
    command = fixture.ForwardContainmentTests.command
    write = fixture.ForwardContainmentTests.write
    run_command = fixture.ForwardContainmentTests.run_command
    make_engine = fixture.ForwardContainmentTests.make_engine
    make_adapter = fixture.ForwardContainmentTests.make_adapter
    run_effect = fixture.ForwardContainmentTests.run_effect
    read_group = fixture.ForwardContainmentTests.read_group
    contain = fixture.ForwardContainmentTests.contain
    refused = fixture.ForwardContainmentTests.refused
    assert_denies = fixture.ForwardContainmentTests.assert_denies

    def setUp(self):
        fixture.ForwardContainmentTests.setUp(self)
        self.stop_quiet = True
        self.library = Mock(spec=ProtectedFile)
        self.library.uid = self.library.gid = 0; self.library.fd = 99
        self.library.checksum.return_value = 'a'*64
        outer = self
        class Connection(ScriptedConnection):
            def call(self, destination, interface, method, signature, args, response, **kwargs):
                if method == 'StopUnit':
                    outer.assertEqual(args, (outer.forward.unit, 'fail'))
                    name, _ = manager_jobs.record_names(1, 'forward')
                    pending = durable.decode((outer.state/name).read_bytes())
                    outer.assertEqual(pending['unit'], outer.forward.unit)
                    outer.assertEqual(pending['role'], 'forward')
                    outer.assertFalse((outer.state/'operation-01-return.json').exists())
                    outer.effects.append(('native-stop', args[0]))
                    if outer.stop_quiet:
                        outer.forward_row.update(ActiveState='inactive', SubState='dead', MainPID='0', Job='0')
                    outer.effect_hook()
                return super().call(destination, interface, method, signature, args, response, **kwargs)
        def connection(library, address):
            value = Connection(library, address)
            value.job_units = {'forward': self.forward}
            self.connection = value
            return value
        for patcher in (patch.object(manager_bus, '_Library', return_value=object()),
                        patch.object(manager_bus, '_Connection', side_effect=connection)):
            patcher.start(); self.addCleanup(patcher.stop)
        self.session = manager_bus.ManagerJobSession(library=self.library, library_sha256='a'*64,
            units={'forward': self.forward}, deadline=1090., clock=lambda:self.now,
            check=lambda:self.engine.observe(deadline=1090.))
        self.addCleanup(self.session.close)
        self.jobs = self.make_jobs()
        self.adapter = self.make_adapter(jobs=self.jobs)

    def make_jobs(self, **overrides):
        args = dict(journal=self.operations, units={'forward':self.forward}, busctl='/accepted/busctl',
                    busctl_sha256='d'*64, commands=self.transport, read_helper_hash=lambda _:'d'*64,
                    session=self.session)
        args.update(overrides)
        return manager_jobs.ForwardStopJobs(**args)

    def records(self):
        return {p.name:p.read_bytes() for p in self.state.iterdir()}

    def test_forward_stop_retains_pending_return_and_completion_before_operation_return(self):
        receipt = self.contain()
        self.assertEqual(self.effects, [('native-stop', self.forward.unit)])
        self.assertTrue(receipt['forward_stopped_observed'])
        self.assertEqual(receipt['manager_job_observations'], {'forward':'completion_done_observed'})
        self.assert_denies(receipt)
        self.assertFalse(receipt['manager_jobs_retired'])
        self.assertFalse(receipt['activation_exclusion_proven'])
        pending_name, return_name = manager_jobs.record_names(1, 'forward')
        pending = durable.decode((self.state/pending_name).read_bytes())
        returned = durable.decode((self.state/return_name).read_bytes())
        event = durable.decode((self.state/manager_jobs.completion_name(1,'forward')).read_bytes())
        self.assertEqual(pending['invocation_id'], self.forward.invocation_id)
        self.assertEqual(event['return_sha256'], durable.digest(durable.canonical(returned)))
        self.assertEqual((returned['job_id'], event['job_id']), (41,41))
        self.assertEqual(len([call for call in self.connection.calls if call[1]=='StopUnit']), 1)

    def test_missing_signal_is_not_completion_even_when_unit_and_inventory_are_empty(self):
        self.connection.mode = 'absent'
        receipt = self.contain()
        self.assertEqual(receipt['manager_job_observations'], {'forward':'absent_not_retired'})
        self.assertFalse(receipt['forward_stopped_observed'])
        self.assertFalse(any('completion' in name for name in self.records()))
        self.assert_denies(receipt)

    def test_failed_canceled_and_dependency_results_stay_non_authorizing(self):
        for result in ('failed','canceled','dependency'):
            with self.subTest(result=result):
                self.setUp(); self.connection.result = result
                receipt = self.contain()
                self.assertEqual(receipt['manager_job_observations'], {'forward':'completion_'+result+'_observed'})
                self.assertFalse(receipt['forward_stopped_observed'])
                self.assert_denies(receipt)
                self.assertEqual(self.effects, [('native-stop',self.forward.unit)])

    def test_pending_job_property_allows_only_own_stop_and_still_kills_whole_unit(self):
        self.stop_quiet = False
        self.connection.mode = 'absent'
        def pending(): self.forward_row['Job'] = '41'
        self.effect_hook = pending
        receipt = self.contain()
        self.assertEqual(len(self.effects),2)
        self.assertIn('--kill-whom=all',self.effects[1])
        self.assertFalse(receipt['forward_stopped_observed'])
        self.assert_denies(receipt)

    def test_unknown_job_property_refuses_before_pending_or_effect(self):
        self.forward_row['Job'] = '99'
        self.refused()
        self.assertEqual(self.effects,[])
        self.assertFalse((self.state/'operation-01-pending.json').exists())

    def test_untracked_start_in_inventory_refuses_before_pending_or_effect(self):
        self.connection.inventory = [[99,self.forward.unit,'start','waiting',manager_jobs.JOB_PREFIX+'99',
                                      manager_jobs.MANAGER_PATH+'/unit/fixture_service']]
        self.refused()
        self.assertEqual(self.effects,[])
        self.assertFalse((self.state/'operation-01-pending.json').exists())

    def test_known_completion_conflicting_with_inventory_refuses_before_kill(self):
        self.stop_quiet = False
        def conflict():
            self.connection.inventory = [[41,self.forward.unit,'stop','running',manager_jobs.JOB_PREFIX+'41',
                                          manager_jobs.MANAGER_PATH+'/unit/fixture_service']]
        self.effect_hook = conflict
        self.refused()
        self.assertEqual(self.effects,[('native-stop',self.forward.unit)])
        self.assertFalse((self.state/'operation-01-return.json').exists())

    def test_reached_job_publication_faults_never_reissue_or_fall_back(self):
        for kind in ('pending','return','completion'):
            for point in ('create','write','file-fsync','rename','directory-fsync','readback'):
                for code in (errno.EIO,errno.ENOSPC):
                    with self.subTest(kind=kind,point=point,code=code):
                        self.setUp(); reached=[]
                        names = (*manager_jobs.record_names(1,'forward'),manager_jobs.completion_name(1,'forward'))
                        target = names[('pending','return','completion').index(kind)]
                        original = self.operations._write
                        def fault(here):
                            if here==point:
                                reached.append(here); raise OSError(code,'restricted')
                        def write(name,value):
                            if name==target: self.operations.fault=fault
                            return original(name,value)
                        with patch.object(self.operations,'_write',side_effect=write): self.refused()
                        self.assertEqual(reached,[point])
                        self.assertEqual(len(self.effects),0 if kind=='pending' else 1)
                        self.assertFalse((self.state/'operation-01-return.json').exists())
                        before=list(self.effects)
                        with self.assertRaises(durable.Rejected): self.contain()
                        self.assertEqual(before,self.effects)

    def test_peer_loss_during_session_inventory_refuses_before_effect(self):
        reached=[]
        def lose(method):
            if method=='ListJobs' and not reached:
                reached.append(method); self.command(self.child,'close')
        self.connection.call_hook=lose
        self.refused()
        self.assertEqual(reached,['ListJobs'])
        self.assertEqual(self.effects,[])

    def test_original_lock_loss_at_job_pending_readback_prevents_native_stop(self):
        reached=[]
        name,_ = manager_jobs.record_names(1,'forward')
        def lose(point):
            if point=='readback' and (self.state/name).exists():
                reached.append(point); self.command(self.child,'unlock')
        self.operations.fault=lose
        self.refused()
        self.assertEqual(reached,['readback'])
        self.assertEqual(self.effects,[])

    def test_replacement_invocation_after_native_stop_is_not_killed(self):
        self.stop_quiet=False
        self.effect_hook=lambda:self.forward_row.update(InvocationID='b'*32)
        self.refused()
        self.assertEqual(self.effects,[('native-stop',self.forward.unit)])

    def test_duplicate_event_after_operation_return_revokes_receipt(self):
        reached=[]
        def duplicate(point):
            if point=='readback' and (self.state/'operation-01-return.json').exists():
                reached.append(point)
                self.connection.queue.append(lambda:self.connection.event(role='forward'))
        self.operations.fault=duplicate
        self.refused()
        self.assertEqual(reached,['readback'])
        self.assertTrue((self.state/'operation-01-return.json').exists())
        self.assertEqual(self.effects,[('native-stop',self.forward.unit)])

    def test_history_classifies_forward_without_reviving_session_or_granting_drain(self):
        self.contain()
        records=broker_history._capture(self.operations.fd,uid=self.operations._owner[0],gid=self.operations._owner[1])
        _,operations=broker_history._classify(records,binding=self.binding)
        self.assertEqual(operations[0]['manager_jobs'][0]['classification'],'completion_done_observed')
        self.assertEqual(operations[0]['manager_jobs'][0]['role'],'forward')
        self.session.close()
        with self.assertRaises(durable.Rejected):self.jobs.observe(deadline=1090.,check=lambda:None)
        self.assertEqual(self.records(),records)

    def test_history_rejects_forward_records_on_wrong_method_or_orphan_completion(self):
        self.contain(); records=self.records()
        name='operation-01-pending.json'
        operation=durable.decode(records[name]);operation['method']='cold_quiesce_runtime'
        operation['operation_id']=durable.digest(durable.canonical({k:v for k,v in operation.items() if k!='operation_id'}))
        records[name]=durable.canonical(operation)
        returned=durable.decode(records['operation-01-return.json']);returned['operation_id']=operation['operation_id']
        records['operation-01-return.json']=durable.canonical(returned)
        pending_name,_=manager_jobs.record_names(1,'forward')
        pending=durable.decode(records[pending_name]);pending['operation_id']=operation['operation_id']
        records[pending_name]=durable.canonical(pending)
        with self.assertRaises(durable.Rejected):broker_history._classify(records,binding=self.binding)
        records=self.records();records.pop(manager_jobs.record_names(1,'forward')[1])
        with self.assertRaises(durable.Rejected):broker_history._classify(records,binding=self.binding)

    def test_forward_helper_requires_original_session_and_exact_single_forward_role(self):
        for overrides in (dict(session=None),dict(units={'dockerd':self.forward}),
                          dict(units={'forward':replace(self.forward,unit='other.service')})):
            with self.subTest(overrides=overrides),self.assertRaises(durable.Rejected):self.make_jobs(**overrides)
        with self.assertRaises(durable.Rejected):
            self.make_adapter(jobs=self.make_jobs(busctl_sha256='e'*64))

    def test_inactive_forward_does_not_invent_job_or_completion(self):
        self.forward_row.update(ActiveState='inactive',SubState='dead',MainPID='0',Job='0')
        receipt=self.contain()
        self.assertTrue(receipt['forward_stopped_observed'])
        self.assertEqual(receipt['manager_job_observations'],{})
        self.assertEqual(self.effects,[])
        self.assertFalse(any('-job-' in name for name in self.records()))
        self.assert_denies(receipt)

    def test_deadline_loss_after_job_pending_readback_prevents_native_stop(self):
        reached=[];name,_=manager_jobs.record_names(1,'forward')
        def expire(point):
            if point=='readback' and (self.state/name).exists():
                reached.append(point);self.now=1090.
        self.operations.fault=expire
        self.refused()
        self.assertEqual(reached,['readback'])
        self.assertEqual(self.effects,[])

    def test_unsupported_or_mixed_role_sets_never_open_a_bus(self):
        for values in ({},{'forward':self.forward,'dockerd':self.forward},
                       {'recovery':self.forward},{'arbitrary':self.forward}):
            with self.subTest(roles=set(values)), patch.object(manager_bus,'_Connection') as connect:
                with self.assertRaises(durable.Rejected):
                    manager_bus.ManagerJobSession(library=self.library,library_sha256='a'*64,units=values,
                        deadline=1090.,clock=lambda:self.now,check=lambda:None)
                connect.assert_not_called()
