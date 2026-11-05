"""Actual private masks/journal; scripted authenticated manager/authority only."""
import errno
import os
from unittest.mock import patch
import unittest

from host_recovery import durable, manager_bus as bus
from host_recovery.broker_operations import OperationJournal
from host_recovery.mask_reload import ManagerMaskReload
from test_broker_operations import binding, epoch
from test_manager_bus import ScriptedConnection
import test_manager_bus as session_fixture
import test_unit_masks as mask_fixture


class MaskReloadTests(unittest.TestCase):
    make = mask_fixture.PersistentUnitMaskTests.make
    current = mask_fixture.PersistentUnitMaskTests.current
    publish = mask_fixture.PersistentUnitMaskTests.publish

    def setUp(self):
        mask_fixture.PersistentUnitMaskTests.setUp(self)
        session_fixture.ManagerSessionTests.setUp(self)
        self.session = bus.ManagerJobSession(library=self.library, library_sha256='a'*64,
            units=self.units, deadline=1090., clock=lambda:self.now, check=lambda:self.check_hook())
        self.addCleanup(self.session.close)
        path = self.root / 'state'
        path.mkdir(mode=0o700)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        original = binding()
        original.update(original_arm=990., failure_monotonic=990., recovery_deadline=1090.)
        self.journal = OperationJournal(fd, binding=original, epoch=epoch(), clock=lambda:self.now,
                                        boot_id=lambda:'boot-original')
        self.reload = ManagerMaskReload(journal=self.journal, masks=self.masks, session=self.session)
        self.operation = self.journal.pending('contain_forward', target_sha256=durable.digest(self.reload.configuration()),
                                               deadline=1090.)
        self.publish()
        self.path_state = path
        self.row = dict(Id=self.units['forward'].unit, LoadState='masked', FragmentPath='/dev/null',
            DropInPaths=[], ActiveState='active', SubState='running', InvocationID=bytes.fromhex('a'*32),
            ControlGroup=self.units['forward'].cgroup, MainPID=123, Job=(0, '/'))
        self.effect_hook = lambda method, args:None
        original_call = ScriptedConnection.call
        def call(connection, destination, interface, method, signature, args, response, **kwargs):
            if method not in ('Reload', 'GetUnit', 'Get'):
                return original_call(connection, destination, interface, method, signature, args, response, **kwargs)
            connection.calls.append((destination, method, args))
            self.effect_hook(method, args)
            value = ([] if method == 'Reload' else [bus.MANAGER_PATH+'/unit/forward_service']
                     if method == 'GetUnit' else [self.row[args[1]]])
            result = []
            connection.queue.append(lambda:result.append(value))
            return result, None, None
        patcher = patch.object(ScriptedConnection, 'call', call)
        patcher.start();self.addCleanup(patcher.stop)

    def apply(self):
        return self.reload.reload(operation=self.operation)

    def reload_count(self):
        return sum(method == 'Reload' for _, method, _ in self.connection.calls)

    def test_original_pending_and_reload_pending_precede_exact_native_call(self):
        reached = []
        def effect(method, args):
            if method == 'Reload':
                reached.append(method)
                self.assertEqual(args, ())
                self.assertTrue((self.path_state/'operation-01-pending.json').exists())
                pending = durable.decode((self.path_state/'operation-01-mask-reload-pending.json').read_bytes())
                self.assertEqual(pending['operation_id'], self.operation['operation_id'])
                self.assertEqual(pending['target_sha256'], durable.digest(self.reload.configuration()))
                self.assertFalse((self.path_state/'operation-01-mask-reload-return.json').exists())
        self.effect_hook = effect
        receipt = self.apply()
        self.assertEqual(reached, ['Reload'])
        self.assertEqual(self.reload_count(), 1)
        self.assertTrue(receipt['effective_masks_observed'])
        self.assertEqual(receipt['active_unit_count'], 1)
        self.assertNotIn(str(self.path), str(receipt))
        for key in ('activation_exclusion_proven', 'manager_jobs_retired', 'pending_drained', 'complete_fence_proven',
                    'recovery_execution_allowed', 'start_allowed', 'settlement_allowed', 'production_acceptance'):
            self.assertIs(receipt[key], False)
        self.assertEqual(receipt, self.reload.observe())
        self.assertNotIn('contain_forward', self.journal._returned)
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.reload_count(), 1)

    def test_supported_inactive_mask_projection_never_means_quiescence(self):
        self.row.update(ActiveState='inactive', SubState='dead', InvocationID=bytes(16), ControlGroup='', MainPID=0,
                        FragmentPath=str(self.path/self.units['forward'].unit))
        receipt = self.apply()
        self.assertEqual(receipt['active_unit_count'], 0)
        self.assertFalse(receipt['pending_drained'])

    def test_wrong_original_pending_or_already_returned_operation_refuses_before_reload(self):
        for action in ('tampered', 'returned', 'wrong-method'):
            with self.subTest(action=action):
                self.setUp()
                if action == 'tampered': self.operation['target_sha256'] = 'e'*64
                elif action == 'returned': self.journal.returned(self.operation, result='returned')
                else: self.operation['method'] = 'cold_quiesce_runtime'
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.reload_count(), 0)

    def test_unpublished_removed_or_replaced_mask_never_reloads(self):
        for action in ('unpublished', 'removed', 'changed'):
            with self.subTest(action=action):
                self.setUp()
                if action == 'unpublished': self.masks.published = False
                else:
                    target = self.path/self.units['forward'].unit
                    target.unlink()
                    if action == 'changed': target.symlink_to('/other')
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.reload_count(), 0)

    def test_accepted_start_or_stop_is_not_silently_discarded_by_reload(self):
        for kind in ('start', 'stop'):
            with self.subTest(kind=kind):
                self.setUp()
                self.connection.inventory = [[41, self.units['forward'].unit, kind, 'waiting',
                    bus.JOB_PREFIX+'41', bus.MANAGER_PATH+'/unit/forward_service']]
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.reload_count(), 0)
                self.assertFalse((self.path_state/'operation-01-mask-reload-pending.json').exists())

    def test_each_pending_and_return_storage_fault_is_reached_and_never_replayed(self):
        for phase in ('pending', 'return'):
            for point in ('create', 'write', 'file-fsync', 'rename', 'directory-fsync', 'readback'):
                for code in (errno.EIO, errno.ENOSPC):
                    with self.subTest(phase=phase, point=point, code=code):
                        self.setUp()
                        reached = []
                        def fault(actual):
                            if actual == point and (phase == 'pending' or self.reload_count() == 1):
                                reached.append(actual)
                                raise OSError(code, 'synthetic')
                        self.journal.fault = fault
                        with self.assertRaises(durable.Rejected): self.apply()
                        self.assertEqual(reached, [point])
                        self.assertEqual(self.reload_count(), int(phase == 'return'))
                        self.assertTrue(self.reload.failed and self.journal._failed and self.session.failed)
                        with self.assertRaises(durable.Rejected): self.apply()
                        self.assertEqual(self.reload_count(), int(phase == 'return'))

    def test_lost_reply_or_owner_change_after_reload_keeps_unreturned_subphase(self):
        for action in ('lost', 'owner'):
            with self.subTest(action=action):
                self.setUp()
                def effect(method, args):
                    if method == 'Reload':
                        if action == 'lost': raise OSError('synthetic lost reply')
                        self.connection.owner = ':1.8'
                self.effect_hook = effect
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.reload_count(), 1)
                self.assertFalse((self.path_state/'operation-01-mask-reload-return.json').exists())

    def test_pending_fsync_authority_loss_skips_native_reload(self):
        reached = []
        def fault(point):
            if point == 'directory-fsync':
                reached.append(point)
                self.check_hook = lambda:(_ for _ in ()).throw(durable.Rejected('synthetic peer lost'))
        self.journal.fault = fault
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reached, ['directory-fsync'])
        self.assertEqual(self.reload_count(), 0)

    def test_expiry_during_property_read_never_publishes_reload_return(self):
        def effect(method, args):
            if method == 'Get': self.now = 1090.
        self.effect_hook = effect
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.reload_count(), 1)
        self.assertFalse((self.path_state/'operation-01-mask-reload-return.json').exists())

    def test_wrong_mask_unit_path_configuration_job_or_invocation_refuses(self):
        for key, value in (('Id','other.service'), ('LoadState','loaded'), ('FragmentPath','/unapproved'),
                           ('DropInPaths',['/unexpected.conf']), ('InvocationID',bytes.fromhex('b'*32)),
                           ('InvocationID','b'*32), ('InvocationID',bytes(15)),
                           ('ControlGroup','/other.slice'), ('MainPID',0), ('MainPID',True),
                           ('Job',(41,bus.JOB_PREFIX+'41')), ('Job',(False,'/')), ('Job',(0,'/other')),
                           ('ActiveState','deactivating'), ('SubState','exited')):
            with self.subTest(key=key, value=value):
                self.setUp()
                self.row[key] = value
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(self.reload_count(), 1)
                self.assertFalse((self.path_state/'operation-01-mask-reload-return.json').exists())

    def test_changed_projection_across_complete_reads_never_returns(self):
        reads = []
        def effect(method, args):
            if method == 'GetUnit':
                reads.append(method)
                if len(reads) == 2: self.row['MainPID'] = 124
        self.effect_hook = effect
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(reads, ['GetUnit','GetUnit'])
        self.assertFalse((self.path_state/'operation-01-mask-reload-return.json').exists())

    def test_return_fsync_cannot_hide_mask_or_effective_state_loss(self):
        for action in ('mask', 'state'):
            with self.subTest(action=action):
                self.setUp()
                reached = []
                def fault(point):
                    if point == 'directory-fsync' and self.reload_count() == 1:
                        reached.append(point)
                        if action == 'mask': (self.path/self.units['forward'].unit).unlink()
                        else: self.row['LoadState'] = 'loaded'
                self.journal.fault = fault
                with self.assertRaises(durable.Rejected): self.apply()
                self.assertEqual(reached, ['directory-fsync'])
                self.assertTrue((self.path_state/'operation-01-mask-reload-return.json').exists())
                self.assertFalse(self.reload.returned)

    def test_replaced_session_or_masks_cannot_redirect_call(self):
        self.reload.session = object()
        with self.assertRaises(durable.Rejected): self.apply()
        self.assertEqual(self.reload_count(), 0)

    def test_borrowed_operation_mutation_cannot_redirect_phase_record(self):
        original_id = self.operation['operation_id']
        self.check_hook = lambda:self.operation.update(sequence=6, operation_id='0'*64)
        self.apply()
        pending = durable.decode((self.path_state/'operation-01-mask-reload-pending.json').read_bytes())
        self.assertEqual(pending['operation_id'], original_id)
        self.assertFalse((self.path_state/'operation-06-mask-reload-pending.json').exists())
        self.assertEqual(self.reload_count(), 1)

    def test_actual_phase_records_compose_with_original_history_without_replaying_reload(self):
        from host_recovery import broker_history as history
        from test_broker_history import original_inputs
        inputs = original_inputs()
        saved_epoch = {**epoch(), 'boot_id':'boot-a'}
        path = self.root/'history-original'
        path.mkdir(mode=0o700)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        self.now = 1050.
        journal = OperationJournal(fd, binding=history.original_binding(inputs, topology_sha256='c'*64),
            epoch=saved_epoch, clock=lambda:self.now, boot_id=lambda:'boot-a')
        reloader = ManagerMaskReload(journal=journal, masks=self.masks, session=self.session)
        operation = journal.pending('contain_forward', target_sha256=durable.digest(reloader.configuration()),
                                    deadline=self.session.deadline)
        reloader.reload(operation=operation)
        before = {p.name:p.read_bytes() for p in path.iterdir()}
        report = history.inspect_history(fd, inputs=inputs, topology_sha256='c'*64, current_epoch=saved_epoch,
                                         uid=os.geteuid(), gid=os.getegid())
        self.assertEqual(report['operations'][0]['mask_reload']['classification'], 'returned_unproven')
        self.assertEqual(report['operations'][0]['classification'], 'unreturned')
        self.assertEqual(before, {p.name:p.read_bytes() for p in path.iterdir()})
        self.assertEqual(self.reload_count(), 1)
        for key in ('pending_drained', 'complete_fence_proven', 'recovery_execution_allowed',
                    'start_allowed', 'settlement_allowed', 'production_acceptance'):
            self.assertIs(report[key], False)

    def test_later_effective_drift_revokes_observer_without_retry(self):
        self.apply()
        self.row['InvocationID'] = 'b'*32
        with self.assertRaises(durable.Rejected): self.reload.observe()
        self.assertEqual(self.reload_count(), 1)
