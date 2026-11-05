"""Real private mask/journal files; scripted manager/effects, not a host fence."""
import errno
import os
import unittest
from unittest.mock import patch

from host_recovery import durable, manager_bus as bus
from host_recovery.broker_operations import OperationJournal
from host_recovery.manager_jobs import ForwardStopJobs, completion_name, record_names
from host_recovery.masked_forward_stop import MaskedForwardStop
from test_broker_operations import binding, epoch
from test_manager_bus import ScriptedConnection
import test_mask_reload as fixture


class MaskedForwardStopTests(unittest.TestCase):
    make = fixture.MaskReloadTests.make
    current = fixture.MaskReloadTests.current
    publish = fixture.MaskReloadTests.publish

    def setUp(self):
        fixture.MaskReloadTests.setUp(self)
        # Replace only this fixture's already-published synthetic mask. The new
        # sequence always receives a fresh publisher and a separate fresh journal.
        (self.path / self.units['forward'].unit).unlink()
        self.masks = self.make()
        path = self.root / 'sequence-state'
        path.mkdir(mode=0o700)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        original = binding()
        original.update(original_arm=990., failure_monotonic=990., recovery_deadline=1090.)
        self.journal = OperationJournal(fd, binding=original, epoch=epoch(), clock=lambda:self.now,
                                        boot_id=lambda:'boot-original')
        self.jobs = ForwardStopJobs(journal=self.journal, units=self.units, busctl='/synthetic/busctl',
            busctl_sha256='b'*64, commands=None, read_helper_hash=lambda path:'b'*64, session=self.session)
        self.sequence = MaskedForwardStop(journal=self.journal, masks=self.masks, jobs=self.jobs)
        self.operation = self.journal.pending('contain_forward', target_sha256=self.sequence.target_sha256,
                                               deadline=1090.)
        self.path_state = path
        self.row['ExecMainStartTimestampMonotonic'] = 2**40
        self.connection.job_units = self.units
        self.waiting = [41, self.units['forward'].unit, 'start', 'waiting', bus.JOB_PREFIX+'41',
                        bus.MANAGER_PATH+'/unit/forward_service']
        self.connection.inventory = [self.waiting]
        self.early_stop, self.stop_signal, self.stop_reply, self.kill_reply = False, True, True, True
        self.stop_result = 'done'
        self.hook = lambda method:None
        original_call = ScriptedConnection.call
        def call(connection, destination, interface, method, signature, args, response, **kwargs):
            if method not in ('Cancel', 'StopUnit', 'KillUnit'):
                return original_call(connection, destination, interface, method, signature, args, response, **kwargs)
            connection.calls.append((destination, method, args))
            self.hook(method)
            result = []
            def event(number, outcome):
                connection.number, connection.result, connection.cookie = number, outcome, number
                connection.inventory = []
                if outcome == 'done': self.row.update(ActiveState='inactive', SubState='dead', MainPID=0, ControlGroup='')
                connection.event(role='forward')
            if method == 'Cancel':
                self.assertEqual((signature, args, kwargs['path']), ('', (), bus.JOB_PREFIX+'41'))
                connection.queue.append(lambda:event(41, 'canceled'))
                connection.queue.append(lambda:result.append([]))
            elif method == 'StopUnit':
                self.assertEqual((signature, args), ('ss', (self.units['forward'].unit, 'fail')))
                connection.inventory = [[42, self.waiting[1], 'stop', 'running', bus.JOB_PREFIX+'42', self.waiting[5]]]
                if self.early_stop and self.stop_signal: connection.queue.append(lambda:event(42, self.stop_result))
                if self.stop_reply: connection.queue.append(lambda:result.append([bus.JOB_PREFIX+'42']))
            else:
                self.assertEqual((interface, signature, args, response),
                    (bus.MANAGER+'.Manager', 'ssi', (self.units['forward'].unit, 'all', 9), ''))
                if self.stop_signal: connection.queue.append(lambda:event(42, self.stop_result))
                if self.kill_reply: connection.queue.append(lambda:result.append([]))
            return result, None, None
        patcher = patch.object(ScriptedConnection, 'call', call)
        patcher.start(); self.addCleanup(patcher.stop)

    def apply(self):
        return self.sequence.stop(operation=self.operation)

    def effects(self):
        return [method for _, method, _ in self.connection.calls if method in ('Cancel','Reload','StopUnit','KillUnit')]

    def test_full_order_has_durable_pending_before_each_fixed_effect(self):
        reached = []
        def effect(method):
            reached.append(method)
            self.assertEqual(durable.decode((self.path_state/'operation-01-pending.json').read_bytes()), self.operation)
            self.assertTrue((self.path / self.units['forward'].unit).is_symlink())
            if method in ('StopUnit', 'KillUnit'):
                self.assertTrue((self.path_state/'operation-01-mask-reload-return.json').exists())
                self.assertTrue((self.path_state/record_names(1,'forward')[0]).exists())
            if method == 'KillUnit':
                self.assertTrue((self.path_state/record_names(1,'forward')[1]).exists())
                self.assertFalse((self.path_state/completion_name(1,'forward')).exists())
        self.hook = effect
        result = self.apply()
        self.assertEqual(self.effects(), ['Cancel','Reload','StopUnit','KillUnit'])
        self.assertEqual(reached, ['Cancel','StopUnit','KillUnit'])
        self.assertTrue(result['whole_unit_kill_returned'] and result['fixed_stop_completion_observed'])
        self.assertEqual(result['canceled_waiting_start_count'], 1)
        self.assertNotIn(str(self.root), str(result))
        for key, value in result.items():
            if key.endswith(('allowed','proven','retired','drained','acceptance')): self.assertIs(value, False)
        self.assertNotIn('contain_forward', self.journal._returned)
        self.assertFalse((self.path_state/'operation-01-return.json').exists())
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.effects(), ['Cancel','Reload','StopUnit','KillUnit'])

    def test_inactive_stop_uses_own_completion_without_a_kill(self):
        self.connection.inventory = []
        self.early_stop = True
        self.row.update(ActiveState='inactive', SubState='dead', MainPID=0, ControlGroup='')
        result = self.apply()
        self.assertEqual(self.effects(), ['Reload','StopUnit'])
        self.assertEqual(result['canceled_waiting_start_count'], 0)
        self.assertFalse(result['whole_unit_kill_returned'])
        self.assertTrue((self.path_state/completion_name(1,'forward')).exists())

    def test_original_target_deadline_or_boundary_replacement_refuses_before_publication(self):
        for action in ('target','deadline','session','jobs','masks'):
            with self.subTest(action=action):
                self.setUp()
                if action == 'target': self.operation['target_sha256'] = 'f'*64
                elif action == 'deadline': self.session.deadline = 1091.
                else: setattr(self.sequence, action, object())
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.effects(), [])
                self.assertFalse((self.path / self.units['forward'].unit).exists())

    def test_existing_publisher_or_stop_cannot_be_adopted(self):
        for action in ('mask','stop'):
            with self.subTest(action=action):
                self.setUp()
                if action == 'mask': self.masks.attempted = True
                else: self.jobs._attempted.add('forward')
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.effects(), [])

    def test_each_phase_publication_fault_is_reached_and_later_effects_are_skipped(self):
        # Three cancel records, two reload records and three stop records. The
        # original pending was durably written before installing this fault hook.
        expected = [[], ['Cancel'], ['Cancel'], ['Cancel'], ['Cancel','Reload'],
                    ['Cancel','Reload'], ['Cancel','Reload','StopUnit'], ['Cancel','Reload','StopUnit','KillUnit']]
        for phase in range(8):
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
                        self.assertEqual(self.effects(), expected[phase])
                        self.assertTrue(self.journal._failed and self.session.failed and self.sequence.failed)
                        with self.assertRaises(durable.Rejected): self.apply()
                        self.assertEqual(self.effects(), expected[phase])

    def test_mask_persistence_failure_never_cancels_reloads_or_stops(self):
        for point in ('create','directory-fsync','readback'):
            with self.subTest(point=point):
                self.setUp()
                reached = []
                def fault(actual):
                    if actual == point:
                        reached.append(actual)
                        raise OSError(errno.EIO, 'synthetic')
                self.masks.fault = fault
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(reached, [point])
                self.assertEqual(self.effects(), [])

    def test_authority_mask_or_deadline_loss_after_reload_prevents_stop(self):
        for action in ('peer','mask','clock'):
            with self.subTest(action=action):
                self.setUp()
                reached = []
                def fault(point):
                    if point == 'directory-fsync' and 'Reload' in self.effects():
                        reached.append(point)
                        if action == 'peer': self.check_hook = lambda:(_ for _ in ()).throw(durable.Rejected('lost'))
                        elif action == 'mask': (self.path / self.units['forward'].unit).unlink()
                        else: self.now = 1090.
                self.journal.fault = fault
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(reached, ['directory-fsync'])
                self.assertEqual(self.effects(), ['Cancel','Reload'])

    def test_stop_reply_or_kill_reply_loss_is_never_retried(self):
        for action in ('stop','kill'):
            with self.subTest(action=action):
                self.setUp()
                self.stop_reply = action != 'stop'
                self.kill_reply = action != 'kill'
                self.connection.wait_hook = lambda:setattr(self, 'now', 1090.)
                with self.assertRaises(durable.Rejected): self.apply()
                expected = ['Cancel','Reload','StopUnit'] + (['KillUnit'] if action == 'kill' else [])
                self.assertEqual(self.effects(), expected)
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.effects(), expected)

    def test_kill_return_and_job_disappearance_do_not_replace_completion(self):
        self.stop_signal = False
        self.hook = lambda method:self.connection.inventory.clear() if method == 'KillUnit' else None
        self.connection.wait_hook = lambda:setattr(self, 'now', 1090.)
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.effects(), ['Cancel','Reload','StopUnit','KillUnit'])
        self.assertFalse((self.path_state/completion_name(1,'forward')).exists())

    def test_failed_stop_completion_never_reports_stopped(self):
        for outcome in ('failed','canceled','timeout','dependency'):
            with self.subTest(outcome=outcome):
                self.setUp()
                self.stop_result = outcome
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertFalse(self.sequence.completed)
                self.assertNotIn('contain_forward', self.journal._returned)

    def test_completion_fsync_cannot_hide_peer_loss_or_active_unit(self):
        for action in ('peer','active'):
            with self.subTest(action=action):
                self.setUp()
                reached = []
                def fault(point):
                    if point == 'directory-fsync' and 'KillUnit' in self.effects():
                        reached.append(point)
                        if action == 'peer': self.check_hook = lambda:(_ for _ in ()).throw(durable.Rejected('lost'))
                        else: self.row.update(ActiveState='active', SubState='running', MainPID=123,
                                             ControlGroup=self.units['forward'].cgroup)
                self.journal.fault = fault
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(reached, ['directory-fsync'])
                self.assertTrue((self.path_state/completion_name(1,'forward')).exists())
                self.assertFalse(self.sequence.completed)

    def test_final_observation_rejects_a_new_fixed_job(self):
        def effect(method, args):
            if method == 'GetUnit' and 'KillUnit' in self.effects():
                self.connection.inventory = [[43,self.waiting[1],'start','waiting',bus.JOB_PREFIX+'43',self.waiting[5]]]
        self.effect_hook = effect
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertFalse(self.sequence.completed)

    def test_completed_sequence_history_remains_original_pending_and_read_only(self):
        from host_recovery import broker_history as history
        from test_broker_history import original_inputs
        inputs = original_inputs()
        saved_epoch = {**epoch(), 'boot_id':'boot-a'}
        path = self.root / 'history-state'
        path.mkdir(mode=0o700)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        self.now = 1050.
        journal = OperationJournal(fd, binding=history.original_binding(inputs, topology_sha256='c'*64),
            epoch=saved_epoch, clock=lambda:self.now, boot_id=lambda:'boot-a')
        jobs = ForwardStopJobs(journal=journal, units=self.units, busctl='/synthetic/busctl',
            busctl_sha256='b'*64, commands=None, read_helper_hash=lambda path:'b'*64, session=self.session)
        sequence = MaskedForwardStop(journal=journal, masks=self.masks, jobs=jobs)
        operation = journal.pending('contain_forward', target_sha256=sequence.target_sha256, deadline=self.session.deadline)
        sequence.stop(operation=operation)
        before = {p.name:p.read_bytes() for p in path.iterdir()}
        report = history.inspect_history(fd, inputs=inputs, topology_sha256='c'*64, current_epoch=saved_epoch,
            uid=os.geteuid(), gid=os.getegid())
        row = report['operations'][0]
        self.assertEqual(row['waiting_start_cancellations'][0]['classification'], 'canceled_observed')
        self.assertFalse(report['pending_drained'])
        self.assertNotIn('contain_forward', journal._returned)
        self.assertEqual(before, {p.name:p.read_bytes() for p in path.iterdir()})

    def test_kill_requires_same_session_stop_and_is_one_shot(self):
        with self.assertRaises(durable.Rejected):
            self.session._kill_stopping_unit('forward', check=lambda:None)
        self.assertEqual(self.effects(), [])
        self.setUp()
        self.apply()
        with self.assertRaises(durable.Rejected):
            self.session._kill_stopping_unit('forward', check=lambda:None)
        self.assertEqual(self.effects().count('KillUnit'), 1)

    def test_execution_timestamp_is_captured_before_masks_and_preserved_after_stop(self):
        result = self.apply()
        self.assertEqual(result['fixed_execution_timestamp_count'], 1)
        self.assertIs(result['fixed_execution_timestamps_unchanged'], True)
        self.assertEqual(durable.decode(self.sequence._execution_starts), {'forward':2**40})
        self.assertFalse(result['activation_exclusion_proven'] or result['manager_jobs_retired'])
        self.assertNotIn('ExecMainStartTimestampMonotonic', str(result))

    def test_missing_or_invalid_execution_timestamp_refuses_before_masks(self):
        for value in (None, True, -1, 2**64-1, 2**64, '123', 1.5):
            with self.subTest(value=value):
                self.setUp()
                self.row['ExecMainStartTimestampMonotonic'] = value
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.effects(), [])
                self.assertFalse(self.masks.attempted)
                self.assertTrue(self.sequence.failed)
        self.setUp()
        del self.row['ExecMainStartTimestampMonotonic']
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.effects(), [])

    def test_execution_drift_during_initial_capture_refuses_before_masks(self):
        reached = []
        def read(method, args):
            if method == 'Get' and args[1] == 'ExecMainStartTimestampMonotonic':
                reached.append('timestamp')
                self.row['ExecMainStartTimestampMonotonic'] += 1
        self.effect_hook = read
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['timestamp','timestamp'])
        self.assertEqual(self.effects(), [])
        self.assertFalse(self.masks.attempted)

    def test_execution_drift_at_effect_boundaries_prevents_later_effects(self):
        for method, expected in (('Cancel',['Cancel']), ('StopUnit',['Cancel','Reload','StopUnit']),
                                  ('KillUnit',['Cancel','Reload','StopUnit','KillUnit'])):
            with self.subTest(method=method):
                self.setUp()
                reached = []
                def hook(actual):
                    if actual == method:
                        reached.append(actual)
                        self.row['ExecMainStartTimestampMonotonic'] += 1
                self.hook = hook
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(reached, [method])
                self.assertEqual(self.effects(), expected)
                self.assertFalse(self.sequence.completed)
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.effects(), expected)

    def test_exited_between_samples_execution_cannot_hide_inactive_projection(self):
        reached = []
        def fault(point):
            if point == 'directory-fsync' and (self.path_state/completion_name(1,'forward')).exists():
                reached.append(point)
                self.row['ExecMainStartTimestampMonotonic'] += 1
                self.assertEqual((self.row['ActiveState'],self.row['MainPID']), ('inactive',0))
        self.journal.fault = fault
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['directory-fsync'])
        self.assertTrue((self.path_state/completion_name(1,'forward')).exists())
        self.assertFalse(self.sequence.completed)

    def test_zero_timestamp_is_only_an_observed_value_not_execution_exclusion(self):
        self.row.update(ExecMainStartTimestampMonotonic=0, ActiveState='inactive', SubState='dead', MainPID=0, ControlGroup='')
        self.connection.inventory = []
        self.early_stop = True
        result = self.apply()
        self.assertTrue(result['fixed_execution_timestamps_unchanged'])
        self.assertFalse(result['activation_exclusion_proven'])
