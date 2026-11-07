"""Private mask/journal components with scripted manager effects, not a fence."""
import errno
import os
import unittest
from unittest.mock import patch

from host_recovery import durable, manager_bus as bus
from host_recovery.job_cancellation import WaitingStartCancellation, record_names
from test_manager_bus import ScriptedConnection
import test_mask_reload as fixture


class WaitingStartCancellationTests(unittest.TestCase):
    make = fixture.MaskReloadTests.make
    current = fixture.MaskReloadTests.current
    publish = fixture.MaskReloadTests.publish

    def setUp(self):
        fixture.MaskReloadTests.setUp(self)
        self.canceler = WaitingStartCancellation(journal=self.journal, masks=self.masks, session=self.session)
        self.waiting = [41, self.units['forward'].unit, 'start', 'waiting', bus.JOB_PREFIX+'41',
                        bus.MANAGER_PATH+'/unit/forward_service']
        self.connection.inventory = [self.waiting]
        self.connection.job_units = self.units
        self.connection.result = 'canceled'
        self.cancel_hook = lambda: None
        self.cancel_signal, self.cancel_reply = True, True
        self.cancel_late = False
        original_call = ScriptedConnection.call
        def call(connection, destination, interface, method, signature, args, response, **kwargs):
            if method != 'Cancel':
                return original_call(connection, destination, interface, method, signature, args, response, **kwargs)
            self.assertEqual((destination, interface, signature, args, response, kwargs['path']),
                (self.session.owner, bus.MANAGER+'.Job', '', (), '', bus.JOB_PREFIX+'41'))
            connection.calls.append((destination, method, args))
            self.cancel_hook()
            result = []
            def event():
                connection.inventory = []
                connection.event(role='forward')
            if self.cancel_reply and self.cancel_late: connection.queue.append(lambda:result.append([]))
            if self.cancel_signal: connection.queue.append(event)
            if self.cancel_reply and not self.cancel_late: connection.queue.append(lambda:result.append([]))
            return result, None, None
        patcher = patch.object(ScriptedConnection, 'call', call)
        patcher.start(); self.addCleanup(patcher.stop)

    def apply(self):
        return self.canceler.cancel(operation=self.operation)

    def count(self):
        return sum(method == 'Cancel' for _, method, _ in self.connection.calls)

    def test_pending_precedes_exact_cancel_return_and_authenticated_completion_are_separate(self):
        reached = []
        names = record_names(1, 'forward')
        def effect():
            reached.append('cancel')
            pending = durable.decode((self.path_state/names[0]).read_bytes())
            self.assertEqual(pending['job'], self.waiting)
            self.assertEqual(pending['operation_id'], self.operation['operation_id'])
            self.assertFalse((self.path_state/names[1]).exists())
            self.assertFalse((self.path_state/names[2]).exists())
        self.cancel_hook = effect
        result = self.apply()
        self.assertEqual(reached, ['cancel'])
        self.assertEqual(self.count(), 1)
        self.assertEqual(result['canceled_waiting_start_count'], 1)
        self.assertNotIn(str(self.path), str(result))
        for key, value in result.items():
            if key.endswith(('proven', 'allowed', 'acceptance', 'drained', 'retired')): self.assertIs(value, False)
        self.assertTrue(all((self.path_state/name).exists() for name in names))
        self.assertNotIn('contain_forward', self.journal._returned)
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.count(), 1)

    def test_late_completion_is_retained_on_same_connection(self):
        self.cancel_late = True
        self.assertEqual(self.apply()['canceled_waiting_start_count'], 1)
        self.assertEqual(self.count(), 1)

    def test_no_fixed_job_does_not_issue_cancel_or_claim_retirement(self):
        self.connection.inventory = []
        result = self.apply()
        self.assertEqual(result['canceled_waiting_start_count'], 0)
        self.assertEqual(self.count(), 0)
        self.assertFalse(result['manager_jobs_retired'])

    def test_running_start_stop_and_unknown_job_types_refuse_before_effect(self):
        for kind, state in (('start','running'), ('stop','waiting'), ('restart','waiting')):
            with self.subTest(kind=kind, state=state):
                self.setUp()
                self.waiting[2:4] = kind, state
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.count(), 0)

    def test_wrong_original_operation_unpublished_mask_or_replaced_session_refuses(self):
        for action in ('operation', 'mask', 'session'):
            with self.subTest(action=action):
                self.setUp()
                if action == 'operation': self.operation['target_sha256'] = 'f'*64
                elif action == 'mask': self.masks.published = False
                else: self.canceler.session = object()
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.count(), 0)

    def test_complete_snapshot_drift_never_redirects_cancellation(self):
        reached = []
        def fault(point):
            if point == 'directory-fsync':
                reached.append(point)
                self.connection.inventory = [[42, self.waiting[1], 'start', 'waiting', bus.JOB_PREFIX+'42', self.waiting[5]]]
        self.journal.fault = fault
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['directory-fsync'])
        self.assertEqual(self.count(), 0)

    def test_signal_before_cancel_is_not_adopted_as_our_completion(self):
        reached = []
        def fault(point):
            if point == 'directory-fsync':
                reached.append(point)
                self.connection.queue.append(lambda:self.connection.event(role='forward'))
        self.journal.fault = fault
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['directory-fsync'])
        self.assertEqual(self.count(), 0)

    def test_return_or_disappearance_without_matching_signal_never_completes(self):
        for disappear in (False, True):
            with self.subTest(disappear=disappear):
                self.setUp()
                self.cancel_signal = False
                self.cancel_hook = lambda: self.connection.inventory.clear() if disappear else None
                self.connection.wait_hook = lambda:setattr(self, 'now', 1090.)
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.count(), 1)
                self.assertFalse((self.path_state/record_names(1,'forward')[2]).exists())

    def test_done_failed_or_dependency_result_is_not_canceled(self):
        for result in ('done', 'failed', 'dependency'):
            with self.subTest(result=result):
                self.setUp()
                self.connection.result = result
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.count(), 1)
                self.assertFalse((self.path_state/record_names(1,'forward')[2]).exists())

    def test_each_storage_fault_is_reached_without_replaying_cancel(self):
        for phase in range(3):
            for point in ('create', 'write', 'file-fsync', 'rename', 'directory-fsync', 'readback'):
                for code in (errno.EIO, errno.ENOSPC):
                    with self.subTest(phase=phase, point=point, code=code):
                        self.setUp()
                        reached, writes = [], []
                        def fault(actual):
                            if actual == 'create': writes.append(actual)
                            if len(writes) == phase + 1 and actual == point:
                                reached.append(actual)
                                raise OSError(code, 'synthetic')
                        self.journal.fault = fault
                        with self.assertRaises(durable.Rejected): self.apply()
                        self.assertEqual(reached, [point])
                        self.assertEqual(self.count(), int(phase > 0))
                        self.assertTrue(self.journal._failed and self.session.failed and self.canceler.failed)
                        with self.assertRaises(durable.Rejected): self.apply()
                        self.assertEqual(self.count(), int(phase > 0))

    def test_pending_fsync_peer_or_mask_loss_refuses_before_cancel(self):
        for action in ('peer', 'mask'):
            with self.subTest(action=action):
                self.setUp()
                reached = []
                def fault(point):
                    if point == 'directory-fsync':
                        reached.append(point)
                        if action == 'peer': self.check_hook = lambda:(_ for _ in ()).throw(durable.Rejected('lost'))
                        else: (self.path/self.units['forward'].unit).unlink()
                self.journal.fault = fault
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(reached, ['directory-fsync'])
                self.assertEqual(self.count(), 0)

    def test_ambiguous_cancel_return_is_never_retried(self):
        self.cancel_reply = False
        self.connection.wait_hook = lambda:setattr(self, 'now', 1090.)
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.count(), 1)
        self.assertFalse((self.path_state/record_names(1,'forward')[1]).exists())
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.count(), 1)

    def test_cancellation_then_reload_and_distinct_stop_keep_completions_separate(self):
        self.apply()
        self.assertTrue(self.reload.reload(operation=self.operation)['effective_masks_observed'])
        self.connection.number = self.connection.reply_number = 42
        self.connection.cookie = 11
        self.connection.result = 'done'
        self.assertEqual(self.session.stop('forward'), bus.JOB_PREFIX+'42')
        self.assertEqual(self.session.completions()['forward']['result'], 'done')
        self.assertEqual(self.session._cancellation('forward')['result'], 'canceled')
        self.assertEqual(self.count(), 1)

    def test_actual_writer_records_compose_with_original_history_without_replay(self):
        from host_recovery import broker_history as history
        from host_recovery.broker_operations import OperationJournal
        from test_broker_history import original_inputs
        from test_broker_operations import epoch
        inputs = original_inputs()
        saved_epoch = {**epoch(), 'boot_id':'boot-a'}
        path = self.root/'cancel-history-original'
        path.mkdir(mode=0o700)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        self.now = 1050.
        journal = OperationJournal(fd, binding=history.original_binding(inputs, topology_sha256='c'*64),
            epoch=saved_epoch, clock=lambda:self.now, boot_id=lambda:'boot-a')
        canceler = WaitingStartCancellation(journal=journal, masks=self.masks, session=self.session)
        operation = journal.pending('contain_forward', target_sha256=durable.digest(canceler.configuration()),
                                    deadline=self.session.deadline)
        canceler.cancel(operation=operation)
        before = {p.name:p.read_bytes() for p in path.iterdir()}
        report = history.inspect_history(fd, inputs=inputs, topology_sha256='c'*64, current_epoch=saved_epoch,
            uid=os.geteuid(), gid=os.getegid())
        self.assertEqual(report['operations'][0]['waiting_start_cancellations'][0]['classification'], 'canceled_observed')
        self.assertFalse(report['pending_drained'])
        self.assertEqual(before, {p.name:p.read_bytes() for p in path.iterdir()})

    def test_duplicate_or_wrong_sender_signal_revokes_original_session(self):
        for action in ('duplicate', 'sender'):
            with self.subTest(action=action):
                self.setUp()
                if action == 'duplicate':
                    self.apply()
                    self.connection.cookie = 11
                    self.connection.queue.append(lambda:self.connection.event(role='forward'))
                    with self.assertRaises(durable.Rejected): self.session.identity()
                else:
                    self.cancel_signal = False
                    self.cancel_hook = lambda:self.connection.queue.append(
                        lambda:self.connection.event(role='forward', sender=':1.8'))
                    with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.count(), 1)
                self.assertTrue(self.session.failed)
