"""Real synthetic original lock/peer, SCRIPTED manager/effects/cgroups only."""
from dataclasses import replace
import errno
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import broker_containment, broker_operations, commands, durable, manager, topology
import test_broker_authority as fixture
from test_manager import binding, encoded, observed
from test_topology import manifest


class ForwardContainmentTests(unittest.TestCase):
    line = fixture.BrokerAuthorityTests.line
    connect = fixture.BrokerAuthorityTests.connect
    command = fixture.BrokerAuthorityTests.command
    write = fixture.BrokerAuthorityTests.write
    run_command = fixture.BrokerAuthorityTests.run_command
    make_engine = fixture.BrokerAuthorityTests.make_engine

    def setUp(self):
        fixture.BrokerAuthorityTests.setUp(self)
        value = manifest()
        value['installation_id'] = self.binding['installation_id']
        value['roles']['supervisor'].update(unit=self.owner['unit'], uid=os.geteuid(), gid=os.getegid())
        role = value['roles']['forward']
        self.forward_row = observed(role['unit'], 'd'*32, '/fixture_forward.slice/forward.service')
        self.forward_row.update(User=str(role['uid']), Group=str(role['gid']))
        self.forward = binding(self.forward_row)
        role['effective_sha256'] = self.forward.properties_sha256
        self.topology = topology.Topology(durable.canonical(value))
        self.binding['topology_sha256'] = self.topology.sha256
        self.engine = self.make_engine()
        self.state = self.root / 'broker-state'
        self.state.mkdir(mode=0o700)
        fd = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        self.epoch = dict(boot_id=self.boot, broker_invocation_id='22222222-2222-4222-8222-222222222222',
                          runtime_epoch='33333333-3333-4333-8333-333333333333')
        self.operations = broker_operations.OperationJournal(fd, binding=self.binding, epoch=self.epoch,
            clock=lambda: self.now, boot_id=lambda: self.boot)
        self.effects, self.reads, self.effect_hook = [], [], lambda: None
        self.populated, self.group_hook, self.unit_hook = False, lambda: None, lambda: None
        self.transport = SimpleNamespace(run=self.run_effect)
        self.mutators = manager.SystemdMutators(systemctl='/accepted/systemctl', commands=self.transport,
            cgroups=SimpleNamespace(populated=self.read_group), forward=self.forward,
            recovery=binding(observed('restore.service', 'e'*32, '/fixture_recovery.slice/restore.service')),
            start_fence=lambda: self.fail('narrow containment must not pretend to prove a complete fence'),
            read_fragment_hash=lambda _: 'f'*64, clock=lambda: self.now)
        self.adapter = self.make_adapter()

    def make_adapter(self, **overrides):
        args = dict(authority=self.engine, journal=self.operations, mutators=self.mutators, topology=self.topology)
        args.update(overrides)
        return broker_containment.ForwardContainment(**args)

    def run_effect(self, argv, *, deadline):
        self.assertEqual(deadline, 1090.)
        self.assertEqual(argv[-1], self.forward.unit)
        if 'show' in argv:
            self.reads.append(argv)
            raw = encoded(self.forward_row)
            self.unit_hook()
            return raw
        # Each actual fixed submission must already have a durable read-back pending
        # record; assertions here detect an early refusal masquerading as coverage.
        record = durable.decode((self.state / 'operation-01-pending.json').read_bytes())
        self.assertEqual(record['method'], 'contain_forward')
        self.assertEqual(record['target_sha256'], self.adapter.target_sha256)
        self.assertFalse((self.state / 'operation-01-return.json').exists())
        self.effects.append(argv)
        self.effect_hook()
        if 'kill' in argv:
            self.forward_row.update(ActiveState='inactive', SubState='dead', MainPID='0', Job='0')
        return b''

    def read_group(self, path):
        self.assertEqual(path, self.forward.cgroup)
        value = self.populated
        self.group_hook()
        return value

    def contain(self, deadline=1090.):
        return self.adapter.contain_forward(deadline=deadline)

    def refused(self):
        with self.assertRaisesRegex(durable.Rejected, '^broker-containment-unconfirmed$'):
            self.contain()
        self.assertTrue(self.adapter.failed)
        self.assertEqual(self.operations.status()['state'], 'reconciliation_required')

    def assert_denies(self, receipt):
        for key in ('pending_drained', 'complete_fence_proven', 'recovery_execution_allowed',
                    'start_allowed', 'settlement_allowed', 'production_acceptance'):
            self.assertIs(receipt[key], False)

    def test_pending_precedes_exact_stop_and_whole_unit_kill_and_never_grants_restore(self):
        original = {p.name:p.read_bytes() for p in self.journal.iterdir()}
        receipt = self.contain()
        self.assertTrue(receipt['forward_stopped_observed'])
        self.assert_denies(receipt)
        self.assertEqual(self.effects, [('/accepted/systemctl', '--no-block', 'stop', '--', self.forward.unit),
            ('/accepted/systemctl', 'kill', '--kill-whom=all', '--signal=SIGKILL', '--', self.forward.unit)])
        returned = durable.decode((self.state / 'operation-01-return.json').read_bytes())
        self.assertEqual(returned['operation_id'], receipt['operation_id'])
        self.assertFalse(returned['pending_drained'])
        self.assertEqual(original, {p.name:p.read_bytes() for p in self.journal.iterdir()})
        self.assertFalse(any('start' in call or 'restore' in call for call in self.effects))

    def test_inactive_unit_records_one_return_without_reissuing_stop_or_kill(self):
        self.forward_row.update(ActiveState='inactive', SubState='dead', MainPID='0', Job='0')
        self.assertTrue(self.contain()['forward_stopped_observed'])
        self.assertEqual(self.effects, [])
        self.assertTrue((self.state / 'operation-01-return.json').exists())

    def test_duplicate_instance_and_second_adapter_cannot_repeat_effects(self):
        self.contain()
        before = list(self.effects)
        with self.assertRaisesRegex(durable.Rejected, '^broker-containment-exhausted$'):
            self.contain()
        self.adapter = self.make_adapter()
        self.refused()
        self.assertEqual(before, self.effects)

    def test_reopened_epoch_or_pending_is_not_a_fresh_containment_permit(self):
        self.operations.pending('contain_forward', target_sha256='a'*64, deadline=1090.)
        self.operations = broker_operations.OperationJournal(self.operations.fd, binding=self.binding, epoch=self.epoch,
            clock=lambda: self.now, boot_id=lambda: self.boot)
        self.adapter = self.make_adapter()
        self.refused()
        self.assertEqual(self.effects, [])

    def test_unreturned_other_method_blocks_before_containment_submission(self):
        self.operations.pending('cold_quiesce_runtime', target_sha256='a'*64, deadline=1090.)
        self.refused()
        self.assertEqual(self.effects, [])
        self.assertFalse((self.state / 'operation-02-pending.json').exists())

    def test_pending_persistence_faults_prevent_every_effect(self):
        for point in ('create', 'write', 'file-fsync', 'rename', 'directory-fsync', 'readback'):
            for code in (errno.EIO, errno.ENOSPC):
                with self.subTest(point=point, code=code):
                    self.setUp()
                    reached = []
                    def fail(actual):
                        if actual == point:
                            reached.append(actual)
                            raise OSError(code, 'restricted-detail')
                    self.operations.fault = fail
                    self.refused()
                    self.assertEqual(reached, [point])
                    self.assertEqual(self.effects, [])
                    self.assertFalse((self.state / 'operation-01-return.json').exists())

    def test_return_persistence_faults_preserve_pending_and_never_reissue(self):
        for point in ('create', 'write', 'file-fsync', 'rename', 'directory-fsync', 'readback'):
            for code in (errno.EIO, errno.ENOSPC):
                with self.subTest(point=point, code=code):
                    self.setUp()
                    reached = []
                    def fail(actual):
                        if actual == point and len(self.effects) == 2:
                            reached.append(actual)
                            raise OSError(code, 'restricted-detail')
                    self.operations.fault = fail
                    self.refused()
                    self.assertEqual(reached, [point])
                    self.assertEqual(len(self.effects), 2)
                    self.assertTrue((self.state / 'operation-01-pending.json').exists())
                    self.operations.fault = None
                    with self.assertRaises(durable.Rejected): self.contain()
                    self.assertEqual(len(self.effects), 2)

    def test_lost_stop_or_kill_reply_retains_pending_without_a_return(self):
        for count in (1, 2):
            with self.subTest(effect=count):
                self.setUp()
                def lost():
                    if len(self.effects) == count:
                        raise commands.CommandUncertain('restricted-detail')
                self.effect_hook = lost
                self.refused()
                self.assertEqual(len(self.effects), count)
                self.assertTrue((self.state / 'operation-01-pending.json').exists())
                self.assertFalse((self.state / 'operation-01-return.json').exists())

    def test_original_peer_or_lock_loss_after_stop_prevents_kill(self):
        for action in ('unlock', 'close'):
            with self.subTest(action=action):
                self.setUp()
                self.effect_hook = lambda: self.command(self.child, action)
                self.refused()
                self.assertEqual(len(self.effects), 1)
                self.assertFalse((self.state / 'operation-01-return.json').exists())

    def test_original_peer_loss_during_unit_read_prevents_any_submission(self):
        self.unit_hook = lambda: self.command(self.child, 'close')
        self.refused()
        self.assertEqual(self.effects, [])
        self.assertFalse((self.state / 'operation-01-pending.json').exists())

    def test_original_input_mutation_at_pending_barrier_prevents_stop(self):
        reached = []
        def change(point):
            if point == 'readback':
                reached.append(point)
                self.write('reconcile-request.json', b'{}')
        self.operations.fault = change
        self.refused()
        self.assertEqual(reached, ['readback'])
        self.assertTrue((self.state / 'operation-01-pending.json').exists())
        self.assertEqual(self.effects, [])

    def test_expired_regressed_or_changed_boot_after_stop_never_continues(self):
        for change in ('expiry', 'regression', 'boot'):
            with self.subTest(change=change):
                self.setUp()
                def drift():
                    if change == 'expiry': self.now = 1090.
                    elif change == 'regression': self.now = 1049.
                    else: self.boot = 'changed-boot'
                self.effect_hook = drift
                self.refused()
                self.assertEqual(len(self.effects), 1)

    def test_expiry_during_pending_readback_prevents_stop(self):
        def expire(point):
            if point == 'readback': self.now = 1090.
        self.operations.fault = expire
        self.refused()
        self.assertEqual(self.effects, [])
        self.assertTrue((self.state / 'operation-01-pending.json').exists())

    def test_replacement_forward_invocation_after_stop_is_not_killed(self):
        self.effect_hook = lambda: self.forward_row.update(InvocationID='a'*32)
        self.refused()
        self.assertEqual(len(self.effects), 1)

    def test_changed_command_fragment_owner_or_cgroup_refuses_before_pending(self):
        for update in ({'ExecStart':'unreviewed'}, {'ControlGroup':'/other'}, {'User':'0'}, {'Group':'0'},
                       {'Restart':'always'}, {'DropInPaths':'/other'}):
            with self.subTest(update=update):
                self.setUp()
                self.forward_row.update(update)
                self.refused()
                self.assertEqual(self.effects, [])
                self.assertFalse((self.state / 'operation-01-pending.json').exists())

    def test_mutated_adapter_configuration_cannot_redirect_kill(self):
        def redirect():
            self.mutators.forward = replace(self.forward, unit='other.service')
        self.effect_hook = redirect
        self.refused()
        self.assertEqual(len(self.effects), 1)
        self.assertTrue(all(call[-1] == self.forward.unit for call in self.effects))

    def test_populated_missing_or_integer_group_is_not_stopped_even_after_return(self):
        for value in (True, None, 0):
            with self.subTest(value=value):
                self.setUp()
                self.populated = value
                receipt = self.contain()
                self.assertFalse(receipt['forward_stopped_observed'])
                self.assert_denies(receipt)

    def test_pending_job_or_deactivating_unit_never_reports_stopped(self):
        for update in ({'Job':'17'}, {'MainPID':'999'}, {'ActiveState':'deactivating', 'SubState':'stop-sigkill'}):
            with self.subTest(update=update):
                self.setUp()
                actual = self.run_effect
                def run(argv, *, deadline):
                    raw = actual(argv, deadline=deadline)
                    if 'kill' in argv: self.forward_row.update(update)
                    return raw
                self.transport.run = run
                self.assertFalse(self.contain()['forward_stopped_observed'])
                self.assertEqual(len(self.effects), 2)

    def test_reactivation_during_group_observation_refuses(self):
        self.group_hook = lambda: self.forward_row.update(InvocationID='b'*32)
        self.refused()
        self.assertEqual(len(self.effects), 2)
        self.assertFalse((self.state / 'operation-01-return.json').exists())

    def test_return_fsync_cannot_hide_later_peer_loss(self):
        reached = []
        def close(point):
            if point == 'readback' and len(self.effects) == 2:
                reached.append(point)
                self.command(self.child, 'close')
        self.operations.fault = close
        self.refused()
        self.assertEqual(reached, ['readback'])
        self.assertTrue((self.state / 'operation-01-return.json').exists())

    def test_return_fsync_cannot_hide_later_group_population(self):
        reached = []
        def change(point):
            if point == 'readback' and len(self.effects) == 2:
                reached.append(point)
                self.populated = True
        self.operations.fault = change
        self.assertFalse(self.contain()['forward_stopped_observed'])
        self.assertEqual(reached, ['readback'])

    def test_deadline_expansion_boolean_and_nan_refuse_before_pending(self):
        for deadline in (1111., True, float('nan')):
            with self.subTest(deadline=deadline):
                self.setUp()
                with self.assertRaises(durable.Rejected): self.contain(deadline)
                self.assertEqual(self.effects, [])
                self.assertFalse((self.state / 'operation-01-pending.json').exists())

    def test_wrong_topology_or_forward_binding_cannot_construct_adapter(self):
        value = self.topology.manifest()
        value['installation_id'] = 'different'
        with self.assertRaises(durable.Rejected):
            self.make_adapter(topology=topology.Topology(durable.canonical(value)))
        self.mutators.forward = replace(self.forward, properties_sha256='0'*64)
        with self.assertRaises(durable.Rejected): self.make_adapter()

    def test_nested_runtime_or_supervisor_domains_cannot_be_containment_targets(self):
        runtime = self.topology.manifest()['runtime']['cgroup_path']
        for group in (runtime, runtime+'/child'):
            self.mutators.forward = replace(self.forward, cgroup=group)
            with self.subTest(group=group), self.assertRaises(durable.Rejected): self.make_adapter()
        self.mutators.forward = replace(self.forward, cgroup=self.group+'/child')
        self.adapter = self.make_adapter()
        self.refused()
        self.assertEqual(self.effects, [])

    def test_untyped_boundary_never_installs_a_callback_effect_handler(self):
        for key in ('authority', 'journal', 'mutators', 'topology'):
            with self.subTest(key=key), self.assertRaises(durable.Rejected):
                self.make_adapter(**{key: SimpleNamespace()})
