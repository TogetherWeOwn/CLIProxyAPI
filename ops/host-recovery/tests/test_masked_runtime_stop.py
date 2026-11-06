"""Owned masks/journal; scripted manager and cgroup domain, not cold recovery."""
from dataclasses import replace
import errno
import os
import select
import signal
import unittest
from unittest.mock import Mock, patch

from host_recovery import durable, manager_bus as bus
from host_recovery.broker_operations import OperationJournal
from host_recovery.broker_runtime import RuntimeDomain
from host_recovery.manager_jobs import RuntimeStopJobs, completion_name, record_names
from host_recovery.masked_runtime_stop import MaskedRuntimeStop
from host_recovery.runtime_kill import record_names as kill_names
from host_recovery.unit_masks import PersistentUnitMasks
from test_broker_operations import binding, epoch
from test_manager import binding as unit_binding, observed
from test_manager_bus import ScriptedConnection
import test_manager_bus as session_fixture
import test_unit_masks as mask_fixture


class MaskedRuntimeStopTests(unittest.TestCase):
    make = mask_fixture.PersistentUnitMaskTests.make

    def setUp(self):
        mask_fixture.PersistentUnitMaskTests.setUp(self)
        session_fixture.ManagerSessionTests.setUp(self)
        self.units = {role: unit_binding(observed(role+'.service', 'd'*32, '/runtime.slice/'+role+'.service'))
                      for role in ('dockerd', 'containerd')}
        self.masks = PersistentUnitMasks(directory=self.directory, units=self.units)
        self.session = bus.ManagerJobSession(library=self.library, library_sha256='a'*64,
            units=self.units, deadline=1090., clock=lambda:self.now, check=lambda:self.check_hook())
        self.addCleanup(self.session.close)
        self.connection.job_units = self.units
        self.path_state = self.root / 'runtime-state'
        self.path_state.mkdir(mode=0o700)
        fd = os.open(self.path_state, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        original = binding()
        original.update(original_arm=990., failure_monotonic=990., recovery_deadline=1090.)
        self.journal = OperationJournal(fd, binding=original, epoch=epoch(), clock=lambda:self.now,
                                        boot_id=lambda:'boot-original')
        self.forward = self.journal.pending('contain_forward', target_sha256='e'*64, deadline=1090.)
        self.journal.returned(self.forward, result='returned')
        self.jobs = RuntimeStopJobs(journal=self.journal, units=self.units, busctl='/synthetic/busctl',
            busctl_sha256='b'*64, commands=None, read_helper_hash=lambda path:'b'*64, session=self.session)
        self.domain = Mock(spec=RuntimeDomain)
        self.domain.cgroup = '/runtime.slice'
        self.domain.configuration.return_value = durable.canonical({'synthetic_domain':True})
        self.domain.populated.return_value = False
        def kill(*, check):
            self.effects.append(('slice-kill', None))
            check()
        self.domain.kill.side_effect = kill
        self.witness = Mock(count=6)
        self.witness.require_dead.side_effect = lambda *,check:check()
        patcher = patch('host_recovery.masked_runtime_stop.RuntimeProcessWitness.capture',
                        side_effect=lambda **kwargs:self.witness)
        self.capture_witness = patcher.start(); self.addCleanup(patcher.stop)
        self.sequence = self.make_sequence()
        self.operation = self.journal.pending('cold_quiesce_runtime', target_sha256=self.sequence.target_sha256,
                                               deadline=1090.)
        self.effects, self.hook = [], lambda method, role:None
        self.stop_signals = {'dockerd':True, 'containerd':True}
        self.stop_results = {'dockerd':'done', 'containerd':'done'}
        self.early, self.event_cookie = False, 100
        self.rows = {role:dict(Id=unit.unit, LoadState='masked', FragmentPath='/dev/null', DropInPaths=[],
            ActiveState='active', SubState='running', InvocationID=bytes.fromhex(unit.invocation_id),
            ControlGroup=unit.cgroup, MainPID=123, Job=(0, '/'), ExecMainStartTimestampMonotonic=2**40)
            for role,unit in self.units.items()}
        for row in self.rows.values():
            row.update({key: [] for key in ('ExecCondition', 'ExecStartPre', 'ExecStartPost', 'ExecReload', 'ExecStop', 'ExecStopPost')})
            row['ControlPID'] = 0
        self.numbers = {'containerd':41, 'dockerd':42}
        self.connection.inventory = [[number, self.units[role].unit, 'start', 'waiting', bus.JOB_PREFIX+str(number),
            bus.MANAGER_PATH+'/unit/'+role] for role,number in self.numbers.items()]
        original_call = ScriptedConnection.call
        def call(connection, destination, interface, method, signature, args, response, **kwargs):
            if (method not in ('Cancel','Reload','StopUnit','KillUnit','GetUnit','Get')
                    or method == 'Get' and args[1] == 'Refs'):
                return original_call(connection, destination, interface, method, signature, args, response, **kwargs)
            connection.calls.append((destination, method, args))
            role = None
            if method == 'Cancel':
                role = next(r for r,n in self.numbers.items() if kwargs['path'] == bus.JOB_PREFIX+str(n))
            elif method in ('StopUnit','KillUnit','GetUnit'):
                role = next(r for r,u in self.units.items() if u.unit == args[0])
            elif method == 'Get': role = kwargs['path'].rsplit('/',1)[1]
            if method in ('Cancel','Reload','StopUnit','KillUnit'): self.effects.append((method, role))
            self.hook(method, role)
            result = []
            def event(number, outcome):
                connection.inventory = [row for row in connection.inventory if row[0] != number]
                self.event_cookie += 1
                connection.number, connection.result, connection.cookie = number, outcome, self.event_cookie
                if outcome == 'done': self.rows[role].update(ActiveState='inactive', SubState='dead', MainPID=0, ControlGroup='')
                connection.event(role=role)
            if method == 'Cancel':
                connection.queue.append(lambda:event(self.numbers[role], 'canceled'))
                value = []
            elif method == 'StopUnit':
                number = self.numbers[role]+10
                connection.inventory.append([number, self.units[role].unit, 'stop', 'running',
                    bus.JOB_PREFIX+str(number), bus.MANAGER_PATH+'/unit/'+role])
                def admission():
                    self.event_cookie += 1
                    connection.admission(role=role, number=number, cookie=self.event_cookie)
                connection.queue.append(admission)
                if self.early and self.stop_signals[role]:
                    connection.queue.append(lambda:event(number, self.stop_results[role]))
                value = [bus.JOB_PREFIX+str(number)]
            elif method == 'KillUnit':
                self.assertEqual((signature,args,response), ('ssi',(self.units[role].unit,'all',9),''))
                if self.stop_signals[role]:
                    connection.queue.append(lambda:event(self.numbers[role]+10, self.stop_results[role]))
                value = []
            else:
                value = ([] if method == 'Reload' else [bus.MANAGER_PATH+'/unit/'+role]
                         if method == 'GetUnit' else [self.rows[role][args[1]]])
            connection.queue.append(lambda:result.append(value))
            return result, None, None
        patcher = patch.object(ScriptedConnection, 'call', call)
        patcher.start(); self.addCleanup(patcher.stop)

    def make_sequence(self, **overrides):
        args = dict(journal=self.journal, masks=self.masks, jobs=self.jobs, domain=self.domain)
        args.update(overrides)
        return MaskedRuntimeStop(**args)

    def apply(self):
        return self.sequence.stop(operation=self.operation)

    def test_auxiliary_commands_in_either_runtime_role_prevent_all_effects(self):
        for role in ('dockerd', 'containerd'):
            for key in ('ExecCondition', 'ExecStartPre', 'ExecStartPost', 'ExecReload', 'ExecStop', 'ExecStopPost'):
                with self.subTest(role=role, key=key):
                    self.setUp()
                    self.rows[role][key] = ['synthetic configured command']
                    with self.assertRaises(durable.Rejected): self.apply()
                    self.assertEqual(self.effects, [])
                    self.domain.kill.assert_not_called()
                    self.assertFalse(self.masks.published)
                    self.assertNotIn('cold_quiesce_runtime', self.journal._returned)

    def test_control_process_after_recursive_kill_prevents_empty_record(self):
        reached = []
        def kill(*, check):
            reached.append('kill')
            check()
            self.rows['containerd']['ControlPID'] = 456
        self.domain.kill.side_effect = kill
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['kill'])
        self.assertFalse((self.path_state/'operation-02-runtime-kill-empty.json').exists())
        self.assertFalse(self.sequence.completed)
        self.assertNotIn('cold_quiesce_runtime', self.journal._returned)
        self.witness.close.assert_called_once()

    def test_both_fixed_completions_precede_one_recursive_domain_kill(self):
        reached = []
        def kill(*, check):
            reached.append('kill')
            self.assertEqual(self.effects, [('Cancel','containerd'),('Cancel','dockerd'),('Reload',None),
                ('StopUnit','dockerd'),('KillUnit','dockerd'),('StopUnit','containerd'),('KillUnit','containerd')])
            for role in self.units:
                saved = durable.decode((self.path_state/completion_name(2,role)).read_bytes())
                self.assertEqual(saved['result'], 'done')
                self.assertTrue((self.path/self.units[role].unit).is_symlink())
            check()
        self.domain.kill.side_effect = kill
        result = self.apply()
        self.assertEqual(reached, ['kill'])
        self.assertEqual(result['runtime_stop_completion_count'], 2)
        self.assertEqual(result['canceled_waiting_start_count'], 2)
        self.assertTrue(result['recursive_domain_kill_returned'] and result['domain_empty_observed'])
        for key,value in result.items():
            if key.endswith(('allowed','proven','retired','drained','acceptance')): self.assertIs(value, False)
        self.assertNotIn(str(self.root), str(result))
        self.assertNotIn('cold_quiesce_runtime', self.journal._returned)
        self.assertFalse((self.path_state/'operation-02-return.json').exists())
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['kill'])

    def test_inactive_units_still_get_two_completions_and_recursive_kill(self):
        self.connection.inventory = []
        self.early = True
        for row in self.rows.values(): row.update(ActiveState='inactive', SubState='dead', MainPID=0, ControlGroup='')
        result = self.apply()
        self.assertEqual(self.effects, [('Reload',None),('StopUnit','dockerd'),('StopUnit','containerd'),('slice-kill',None)])
        self.assertFalse(result['whole_unit_kill_returned'])
        self.assertEqual(self.domain.kill.call_count, 1)

    def test_domain_pins_scope_and_original_forward_are_required(self):
        for action in ('missing-forward','unreturned-forward','different-slice','foreign-unit'):
            with self.subTest(action=action):
                self.setUp()
                if action == 'missing-forward': self.journal._pending.pop('contain_forward')
                elif action == 'unreturned-forward': self.journal._returned.remove('contain_forward')
                elif action == 'different-slice': self.domain.cgroup = '/different.slice'
                else: self.jobs.units['containerd'] = replace(self.units['containerd'], cgroup='/elsewhere')
                with self.assertRaises(durable.Rejected): self.make_sequence()
                self.assertEqual(self.effects, [])

    def test_original_target_deadline_or_boundaries_cannot_be_replaced(self):
        for action in ('target','deadline','domain','roles','method','jobs','session','masks'):
            with self.subTest(action=action):
                self.setUp()
                if action == 'target': self.operation['target_sha256'] = 'f'*64
                elif action == 'deadline': self.session.deadline = 1091.
                elif action == 'roles': self.sequence.roles = ('dockerd',)
                elif action == 'method': self.sequence.method = 'contain_forward'
                else: setattr(self.sequence, action, object())
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.effects, [])
                self.domain.kill.assert_not_called()

    def test_each_publication_fault_is_reached_and_skips_later_effects(self):
        # Six cancel, two reload and six stop phase records, after original pending.
        expected = [[], [('Cancel','containerd')], [('Cancel','containerd')], [('Cancel','containerd')],
            [('Cancel','containerd'),('Cancel','dockerd')], [('Cancel','containerd'),('Cancel','dockerd')]]
        canceled = [('Cancel','containerd'),('Cancel','dockerd')]
        expected += [canceled, canceled+[('Reload',None)], canceled+[('Reload',None)],
            canceled+[('Reload',None),('StopUnit','dockerd')],
            canceled+[('Reload',None),('StopUnit','dockerd'),('KillUnit','dockerd')]]
        first = expected[-1]
        expected += [first, first+[('StopUnit','containerd')], first+[('StopUnit','containerd'),('KillUnit','containerd')]]
        self.assertEqual(len(expected), 14)
        for phase in range(14):
            for point in ('create','write','file-fsync','rename','directory-fsync','readback'):
                for code in (errno.EIO, errno.ENOSPC):
                    with self.subTest(phase=phase, point=point, code=code):
                        self.setUp()
                        reached, writes = [], []
                        def fault(actual):
                            if actual == 'create': writes.append(actual)
                            if len(writes) == phase+1 and actual == point:
                                reached.append(actual)
                                raise OSError(code, 'synthetic')
                        self.journal.fault = fault
                        with self.assertRaises(durable.Rejected): self.apply()
                        self.assertEqual(reached, [point])
                        self.assertEqual(self.effects, expected[phase])
                        self.domain.kill.assert_not_called()
                        self.assertTrue(self.sequence.failed and self.journal._failed and self.session.failed)

    def test_first_runtime_failure_prevents_second_stop_and_domain_kill(self):
        for outcome in ('failed','canceled','timeout','dependency'):
            with self.subTest(outcome=outcome):
                self.setUp()
                self.stop_results['dockerd'] = outcome
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertNotIn(('StopUnit','containerd'), self.effects)
                self.domain.kill.assert_not_called()

    def test_second_job_disappearance_cannot_replace_completion(self):
        self.stop_signals['containerd'] = False
        def hook(method, role):
            if (method,role) == ('KillUnit','containerd'): self.connection.inventory = []
        self.hook = hook
        self.connection.wait_hook = lambda:setattr(self,'now',1090.)
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertIn(('KillUnit','containerd'), self.effects)
        self.domain.kill.assert_not_called()
        self.assertFalse((self.path_state/completion_name(2,'containerd')).exists())

    def test_domain_kill_failure_is_sticky_and_never_retried(self):
        def kill(*,check):
            check()
            raise OSError(errno.EIO, 'synthetic')
        self.domain.kill.side_effect = kill
        with self.assertRaises(durable.Rejected): self.apply()
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.domain.kill.call_count, 1)
        self.assertFalse(self.sequence.completed)

    def test_populated_unknown_or_missing_domain_after_kill_is_not_empty(self):
        for value in (True,None,0):
            with self.subTest(value=value):
                self.setUp()
                self.domain.populated.return_value = value
                self.connection.wait_hook = lambda:setattr(self,'now',1090.)
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.domain.kill.call_count, 1)
                self.assertFalse(self.sequence.completed)
        self.setUp()
        self.domain.populated.side_effect = FileNotFoundError('synthetic')
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.domain.kill.call_count, 1)

    def test_trailing_repopulation_after_empty_read_refuses(self):
        self.domain.populated.side_effect = [False,False,False,True]
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.domain.populated.call_count, 4)
        self.assertFalse(self.sequence.completed)

    def test_peer_loss_at_domain_kill_refuses_before_acknowledgment(self):
        reached = []
        def kill(*,check):
            reached.append('kill')
            self.check_hook = lambda:(_ for _ in ()).throw(durable.Rejected('lost'))
            check()
        self.domain.kill.side_effect = kill
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['kill'])
        self.assertFalse(self.sequence.completed)

    def test_second_completion_persistence_loss_prevents_domain_kill(self):
        reached = []
        def fault(point):
            if point == 'directory-fsync' and ('KillUnit','containerd') in self.effects:
                reached.append(point)
                self.check_hook = lambda:(_ for _ in ()).throw(durable.Rejected('lost'))
        self.journal.fault = fault
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['directory-fsync'])
        self.assertTrue((self.path_state/completion_name(2,'containerd')).exists())
        self.domain.kill.assert_not_called()

    def test_mask_removed_after_first_stop_prevents_later_effects(self):
        def hook(method,role):
            if (method,role) == ('StopUnit','dockerd'): (self.path/'containerd.service').unlink()
        self.hook = hook
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertNotIn(('KillUnit','dockerd'), self.effects)
        self.assertNotIn(('StopUnit','containerd'), self.effects)
        self.domain.kill.assert_not_called()

    def test_domain_kill_records_bind_original_stops_and_do_not_grant_drain(self):
        from host_recovery import runtime_kill, broker_history
        reached = []
        names = kill_names(2)
        def kill(*, check):
            check()
            reached.append('kill')
            self.assertTrue((self.path_state/names[0]).exists())
            self.assertFalse((self.path_state/names[1]).exists())
        self.domain.kill.side_effect = kill
        self.apply()
        records = {p.name:p.read_bytes() for p in self.path_state.iterdir()}
        completions = {role:durable.digest(records[completion_name(2,role)]) for role in self.units}
        self.assertEqual(runtime_kill.classify_records(*(records[name] for name in names),
            operation=self.operation, completions=completions), 'empty_observed_unproven')
        _, operations = broker_history._classify(records, binding=durable.decode(self.journal._binding))
        self.assertEqual(operations[1]['runtime_kill']['classification'], 'empty_observed_unproven')
        self.assertEqual(reached, ['kill'])
        self.assertNotIn('cold_quiesce_runtime', self.journal._returned)

    def test_each_domain_publication_fault_is_reached_and_never_retries(self):
        for phase, name in enumerate(kill_names(2)):
            for point in ('create','write','file-fsync','rename','directory-fsync','readback'):
                for code in (errno.EIO, errno.ENOSPC):
                    with self.subTest(phase=phase, point=point, code=code):
                        self.setUp()
                        reached = []
                        def fault(actual):
                            # _write supplies the phase filename to atomic_write;
                            # count completed earlier phase publications instead
                            # of guessing which repeated hook failed.
                            prior = kill_names(2)[:phase]
                            if (all(item in self.journal._records for item in prior)
                                    and all(completion_name(2,role) in self.journal._records for role in self.units)
                                    and name not in self.journal._records and actual == point):
                                reached.append(actual)
                                raise OSError(code, 'synthetic')
                        self.journal.fault = fault
                        with self.assertRaises(durable.Rejected): self.apply()
                        self.assertEqual(reached, [point])
                        self.assertEqual(self.domain.kill.call_count, int(phase > 0))
                        with self.assertRaises(durable.Rejected): self.apply()
                        self.assertEqual(self.domain.kill.call_count, int(phase > 0))
                        self.assertFalse(self.sequence.completed)
                        self.assertFalse((self.path_state/'operation-02-return.json').exists())

    def test_empty_publication_repopulation_or_peer_loss_refuses_live_result(self):
        for action in ('repopulate', 'peer', 'deadline'):
            with self.subTest(action=action):
                self.setUp()
                reached = []
                def fault(point):
                    if point == 'directory-fsync' and (self.path_state/kill_names(2)[2]).exists():
                        reached.append(point)
                        if action == 'repopulate': self.domain.populated.return_value = True
                        elif action == 'deadline': self.now = 1090.
                        else: self.check_hook = lambda:(_ for _ in ()).throw(durable.Rejected('lost'))
                self.journal.fault = fault
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(reached, ['directory-fsync'])
                self.assertTrue((self.path_state/kill_names(2)[2]).exists())
                self.assertFalse(self.sequence.completed)
                self.assertEqual(self.domain.kill.call_count, 1)

    def test_kill_exception_retains_pending_without_return_or_empty(self):
        self.domain.kill.side_effect = OSError(errno.EIO, 'synthetic')
        with self.assertRaises(durable.Rejected): self.apply()
        names = kill_names(2)
        self.assertTrue((self.path_state/names[0]).exists())
        self.assertFalse(any((self.path_state/name).exists() for name in names[1:]))
        reopened = OperationJournal(self.journal.fd, binding=durable.decode(self.journal._binding),
            epoch=durable.decode(self.journal._epoch), clock=lambda:self.now, boot_id=lambda:'boot-original')
        with self.assertRaises(durable.Rejected):
            reopened.pending('cold_quiesce_runtime', target_sha256=self.sequence.target_sha256, deadline=1090.)
        self.assertEqual(self.domain.kill.call_count, 1)

    def test_sigkill_at_each_domain_publication_retains_nonreplayable_history(self):
        from host_recovery import broker_history
        phases = ('unreturned','returned_without_empty_observation','empty_observed_unproven')
        for phase, name in enumerate(kill_names(2)):
            with self.subTest(phase=phase):
                self.setUp()
                read_fd, write_fd = os.pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(read_fd)
                    try:
                        def fault(point):
                            if point == 'directory-fsync' and (self.path_state/name).exists():
                                os.write(write_fd, b'P')
                                signal.pause()
                        self.journal.fault = fault
                        self.apply()
                    except BaseException:
                        os.write(write_fd, b'E')
                    finally:
                        os._exit(1)
                os.close(write_fd)
                try:
                    self.assertTrue(select.select([read_fd], [], [], 5.)[0], 'child publication not reached')
                    self.assertEqual(os.read(read_fd,1), b'P')
                finally:
                    os.kill(pid, signal.SIGKILL)
                    _, status = os.waitpid(pid, 0)
                    os.close(read_fd)
                self.assertTrue(os.WIFSIGNALED(status))
                self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                records = {p.name:p.read_bytes() for p in self.path_state.iterdir()}
                _, operations = broker_history._classify(records, binding=durable.decode(self.journal._binding))
                self.assertEqual(operations[1]['runtime_kill']['classification'], phases[phase])
                reopened = OperationJournal(self.journal.fd, binding=durable.decode(self.journal._binding),
                    epoch=durable.decode(self.journal._epoch), clock=lambda:self.now, boot_id=lambda:'boot-original')
                with self.assertRaises(durable.Rejected):
                    reopened.pending('cold_quiesce_runtime', target_sha256=self.sequence.target_sha256, deadline=1090.)
                self.assertEqual(records, {p.name:p.read_bytes() for p in self.path_state.iterdir()})

    def test_process_capture_precedes_masks_and_every_manager_effect(self):
        def capture(**kwargs):
            self.assertEqual(self.effects, [])
            self.assertFalse(self.masks.attempted)
            self.assertEqual(kwargs['domain'], self.domain)
            kwargs['check']()
            return self.witness
        self.capture_witness.side_effect = capture
        result = self.apply()
        self.assertEqual(result['observed_runtime_process_count'], 6)
        self.assertIs(result['observed_runtime_processes_dead'], True)
        self.assertGreaterEqual(self.witness.require_dead.call_count, 3)
        self.witness.close.assert_called_once_with()

    def test_process_capture_failure_permits_no_mask_or_manager_effect(self):
        self.capture_witness.side_effect = durable.Rejected('capture-uncertain')
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.effects, [])
        self.assertFalse(self.masks.attempted)
        self.domain.kill.assert_not_called()
        self.assertTrue(self.sequence.failed)

    def test_live_process_refuses_empty_receipt_even_when_domain_reports_empty(self):
        self.witness.require_dead.side_effect = durable.Rejected('process-live')
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.domain.kill.call_count, 1)
        self.assertFalse((self.path_state/kill_names(2)[2]).exists())
        self.assertFalse(self.sequence.completed)
        self.witness.close.assert_called_once_with()

    def test_late_witness_failure_does_not_acknowledge_saved_empty_record(self):
        reached = []
        def dead(*,check):
            check()
            reached.append('dead-check')
            if (self.path_state/kill_names(2)[2]).exists():
                raise durable.Rejected('late-witness-loss')
        self.witness.require_dead.side_effect = dead
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['dead-check', 'dead-check'])
        self.assertTrue((self.path_state/kill_names(2)[2]).exists())
        self.assertFalse(self.sequence.completed)
        self.witness.close.assert_called_once_with()

    def test_process_witness_is_closed_on_stop_or_persistence_failure(self):
        self.stop_results['dockerd'] = 'failed'
        with self.assertRaises(durable.Rejected): self.apply()
        self.witness.close.assert_called_once_with()
        self.setUp()
        self.journal.fault = lambda point:(_ for _ in ()).throw(OSError(errno.EIO, 'synthetic'))
        with self.assertRaises(durable.Rejected): self.apply()
        self.witness.close.assert_called_once_with()

    def test_both_runtime_execution_timestamps_are_observed_without_authority(self):
        result = self.apply()
        self.assertEqual(result['fixed_execution_timestamp_count'], 2)
        self.assertIs(result['fixed_execution_timestamps_unchanged'], True)
        self.assertEqual(durable.decode(self.sequence._execution_starts), {role:2**40 for role in self.units})
        self.assertFalse(result['activation_exclusion_proven'] or result['pending_drained'])

    def test_execution_drift_after_first_stop_prevents_second_stop_and_recursive_kill(self):
        reached = []
        def hook(method,role):
            if (method,role) == ('KillUnit','dockerd'):
                reached.append(role)
                self.rows['containerd']['ExecMainStartTimestampMonotonic'] += 1
        self.hook = hook
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['dockerd'])
        self.assertNotIn(('StopUnit','containerd'), self.effects)
        self.domain.kill.assert_not_called()
        self.witness.close.assert_called_once_with()

    def test_execution_drift_at_recursive_kill_refuses_even_with_empty_domain(self):
        reached = []
        def kill(*,check):
            check()
            reached.append('kill')
            self.rows['dockerd']['ExecMainStartTimestampMonotonic'] += 1
        self.domain.kill.side_effect = kill
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['kill'])
        self.assertFalse(self.sequence.completed)
        self.witness.close.assert_called_once_with()
        self.assertNotIn('cold_quiesce_runtime', self.journal._returned)

    def test_new_fixed_job_after_domain_kill_refuses_final_observation(self):
        def kill(*,check):
            check()
            self.connection.inventory = [[75,'containerd.service','start','waiting',bus.JOB_PREFIX+'75',
                                          bus.MANAGER_PATH+'/unit/containerd']]
        self.domain.kill.side_effect = kill
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertFalse(self.sequence.completed)
