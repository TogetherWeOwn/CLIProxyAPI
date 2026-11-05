"""Synthetic peer/flock/files; SCRIPTED manager and cgroup2 mount qualification.

No host manager/daemon call or kernel cgroup kill occurs. The domain kernel mount
check is patched only in tests using ordinary disposable files, never in runners.
"""
import errno
import io
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import broker_operations, broker_runtime, commands, durable, manager_jobs, topology
import test_broker_authority as fixture
from test_manager import binding, encoded, observed
from test_topology import manifest


class RuntimeContainmentTests(unittest.TestCase):
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
        self.rows, self.units = {}, {}
        for index, role in enumerate(topology.RUNTIME_ROLES):
            unit = value['runtime']['units'][role]['unit']
            row = observed(unit, ('d' if index == 0 else 'e')*32, value['runtime']['cgroup_path']+'/'+unit)
            row.update(User='0', Group='0', Slice=value['runtime']['slice'], Delegate='yes')
            self.rows[role], self.units[role] = row, binding(row)
            value['runtime']['units'][role]['effective_sha256'] = self.units[role].properties_sha256
        self.topology = topology.Topology(durable.canonical(value))
        self.binding['topology_sha256'] = self.topology.sha256
        self.engine = self.make_engine()
        self.state = self.root / 'runtime-operations'
        self.state.mkdir(mode=0o700)
        fd = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        self.epoch = dict(boot_id=self.boot, broker_invocation_id='22222222-2222-4222-8222-222222222222',
                          runtime_epoch='33333333-3333-4333-8333-333333333333')
        self.operations = broker_operations.OperationJournal(fd, binding=self.binding, epoch=self.epoch,
            clock=lambda: self.now, boot_id=lambda: self.boot)
        # This prior bookkeeping return is NOT a forward-quiescence assertion.
        prior = self.operations.pending('contain_forward', target_sha256='a'*64, deadline=1090.)
        self.operations.returned(prior, result='returned')
        self.mount_root = self.root / 'cgroup-mount'
        self.group_path = self.mount_root / value['runtime']['cgroup_path'].lstrip('/')
        self.group_path.mkdir(parents=True)
        self.events = self.group_path / 'cgroup.events'
        self.events.write_bytes(b'populated 0\nfrozen 0\n')
        self.kill_file = self.group_path / 'cgroup.kill'
        self.kill_file.write_bytes(b'')
        domain_fd = os.open(self.group_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, domain_fd)
        self.mount_patch = patch.object(broker_runtime.RuntimeDomain, '_mount', return_value=None)
        self.mount_patch.start()
        self.addCleanup(self.mount_patch.stop)
        st = os.fstat(domain_fd)
        self.domain = broker_runtime.RuntimeDomain(fd=domain_fd, mount_root=str(self.mount_root),
            cgroup=value['runtime']['cgroup_path'], device=st.st_dev, inode=st.st_ino)
        self.effects, self.reads, self.effect_hook, self.unit_hook = [], [], lambda: None, lambda: None
        self.manager_owner, self.manager_rows, self.bus_calls = ':1.7', [], []
        self.bus_id = 'a'*32
        self.bus_hook = lambda: None
        self.transport = SimpleNamespace(run=self.run_effect)
        self.adapter = self.make_adapter()

    def make_adapter(self, **overrides):
        args = dict(authority=self.engine, journal=self.operations, topology=self.topology,
            units=self.units, domain=self.domain, systemctl='/accepted/systemctl', commands=self.transport,
            read_fragment_hash=lambda _: 'f'*64,
            jobs=manager_jobs.RuntimeStopJobs(journal=self.operations, units=self.units,
                busctl='/accepted/busctl', busctl_sha256='d'*64, commands=self.transport,
                read_helper_hash=lambda _: 'd'*64))
        args.update(overrides)
        return broker_runtime.RuntimeContainment(**args)

    def run_effect(self, argv, *, deadline):
        self.assertEqual(deadline, 1090.)
        if argv[0] == '/accepted/busctl':
            self.bus_calls.append(argv)
            self.bus_hook()
            if 'GetId' in argv:
                return durable.canonical({'type':'s', 'data':[self.bus_id]})
            if 'GetNameOwner' in argv:
                return durable.canonical({'type':'s', 'data':[self.manager_owner]})
            self.assertEqual(argv[5], self.manager_owner)
            if 'ListJobs' in argv:
                return durable.canonical({'type':'a(usssoo)', 'data':[self.manager_rows]})
            self.assertEqual(argv[8], 'StopUnit')
            self.assertEqual(argv[-3], 'ss')
            self.assertEqual(argv[-1], 'fail')
        target = argv[-2] if 'StopUnit' in argv else argv[-1]
        role = next(role for role in topology.RUNTIME_ROLES if self.units[role].unit == target)
        if 'show' in argv:
            self.reads.append(role)
            raw = encoded(self.rows[role])
            self.unit_hook()
            return raw
        pending = durable.decode((self.state / 'operation-02-pending.json').read_bytes())
        self.assertEqual(pending['method'], 'cold_quiesce_runtime')
        self.assertEqual(pending['target_sha256'], self.adapter.target_sha256)
        self.assertFalse((self.state / 'operation-02-return.json').exists())
        job_pending, job_return = manager_jobs.record_names(2, role)
        saved = durable.decode((self.state / job_pending).read_bytes())
        self.assertEqual(saved['operation_id'], pending['operation_id'])
        self.assertEqual(saved['unit'], self.units[role].unit)
        self.assertFalse((self.state / job_return).exists())
        self.effects.append(argv)
        self.effect_hook()
        self.rows[role].update(ActiveState='inactive', SubState='dead', MainPID='0', Job='0')
        number = 41 + topology.RUNTIME_ROLES.index(role)
        return durable.canonical({'type':'o', 'data':[manager_jobs.JOB_PREFIX+str(number)]})

    def contain(self):
        return self.adapter.contain_runtime(deadline=1090.)

    def refused(self):
        with self.assertRaisesRegex(durable.Rejected, '^runtime-containment-unconfirmed$'):
            self.contain()
        self.assertTrue(self.adapter.failed)
        self.assertEqual(self.operations.status()['state'], 'reconciliation_required')

    def test_dynamic_cgroup_event_timestamps_are_not_persistent_file_pins(self):
        original = os.fstat
        inode = self.events.stat().st_ino
        reached = []
        def changing(fd):
            info = original(fd)
            if info.st_ino != inode: return info
            reached.append(fd)
            fields = {key:getattr(info,key) for key in dir(info) if key.startswith('st_')}
            fields.update(st_mtime_ns=100+len(reached), st_ctime_ns=200+len(reached), st_size=0)
            return SimpleNamespace(**fields)
        with patch.object(os,'fstat',side_effect=changing):
            self.assertIs(self.domain.populated(), False)
        self.assertGreaterEqual(len(reached), 2)
        # Persistent regular-file reads deliberately retain the stricter contract.
        fd = os.open(self.group_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        with patch.object(os,'fstat',side_effect=changing):
            with self.assertRaises(durable.Rejected): durable.read_file(fd,'cgroup.events')

    def test_cgroup_event_inode_mode_owner_and_link_changes_still_refuse(self):
        original = os.fstat
        inode = self.events.stat().st_ino
        for field in ('st_ino','st_mode','st_uid','st_gid','st_nlink','st_dev'):
            with self.subTest(field=field):
                reached = []
                def changing(fd):
                    info = original(fd)
                    if info.st_ino != inode: return info
                    reached.append(fd)
                    fields = {key:getattr(info,key) for key in dir(info) if key.startswith('st_')}
                    if len(reached) == 2: fields[field] += 1
                    return SimpleNamespace(**fields)
                with patch.object(os,'fstat',side_effect=changing):
                    with self.assertRaises(durable.Rejected): self.domain.populated()
                self.assertEqual(len(reached), 2)

    def test_cgroup_event_read_is_bounded_and_trailing_path_replacement_refuses(self):
        self.events.write_bytes(b'populated 0\n'+b'x'*1024)
        with self.assertRaises(durable.Rejected): self.domain.populated()
        self.events.write_bytes(b'populated 0\nfrozen 0\n')
        original = os.read
        inode, reached = self.events.stat().st_ino, []
        def replace_after_read(fd,size):
            raw = original(fd,size)
            if os.fstat(fd).st_ino == inode and raw:
                reached.append(fd)
                self.events.unlink()
                self.events.write_bytes(b'populated 0\nfrozen 0\n')
            return raw
        with patch.object(os,'read',side_effect=replace_after_read):
            with self.assertRaises(durable.Rejected): self.domain.populated()
        self.assertEqual(len(reached), 1)

    def test_durable_pending_before_fixed_stops_and_descriptor_recursive_kill(self):
        original = {p.name:p.read_bytes() for p in self.journal.iterdir()}
        receipt = self.contain()
        self.assertEqual(self.effects, [('/accepted/busctl', '--system', '--json=short', '--no-pager', 'call',
            ':1.7', manager_jobs.MANAGER_PATH, manager_jobs.MANAGER+'.Manager', 'StopUnit', 'ss',
            self.units[r].unit, 'fail') for r in topology.RUNTIME_ROLES])
        self.assertEqual(receipt.pop('manager_job_observations'),
                         {role:'absent_not_retired' for role in topology.RUNTIME_ROLES})
        self.assertEqual(self.kill_file.read_bytes(), b'1\n')
        self.assertTrue(receipt.pop('runtime_empty_observed'))
        for key, value in receipt.items():
            if key not in ('schema', 'operation_id', 'return_sha256'):
                self.assertIs(value, False, key)
        self.assertEqual(original, {p.name:p.read_bytes() for p in self.journal.iterdir()})
        self.assertFalse(any('start' in call or 'cancel' in call for call in self.effects))

    def test_inactive_services_still_require_recursive_slice_kill(self):
        for row in self.rows.values():
            row.update(ActiveState='inactive', SubState='dead', MainPID='0', Job='0', InvocationID='', ControlGroup='')
        self.assertTrue(self.contain()['runtime_empty_observed'])
        self.assertEqual(self.effects, [])
        self.assertEqual(self.kill_file.read_bytes(), b'1\n')

    def test_repeated_adapter_or_new_instance_never_reissues(self):
        self.contain()
        before = list(self.effects)
        with self.assertRaisesRegex(durable.Rejected, '^runtime-containment-exhausted$'): self.contain()
        self.adapter = self.make_adapter()
        self.refused()
        self.assertEqual(before, self.effects)

    def test_pending_faults_prevent_both_stops_and_kernel_write(self):
        for point in ('create', 'write', 'file-fsync', 'rename', 'directory-fsync', 'readback'):
            for code in (errno.EIO, errno.ENOSPC):
                with self.subTest(point=point, code=code):
                    self.setUp()
                    reached = []
                    def fail(actual):
                        if actual == point:
                            reached.append(actual)
                            raise OSError(code, 'restricted')
                    self.operations.fault = fail
                    self.refused()
                    self.assertEqual(reached, [point])
                    self.assertEqual(self.effects, [])
                    self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_return_faults_preserve_pending_after_actual_scripted_effects(self):
        for point in ('create', 'write', 'file-fsync', 'rename', 'directory-fsync', 'readback'):
            for code in (errno.EIO, errno.ENOSPC):
                with self.subTest(point=point, code=code):
                    self.setUp()
                    reached = []
                    def fail(actual):
                        if actual == point and self.kill_file.read_bytes() == b'1\n':
                            reached.append(actual)
                            raise OSError(code, 'restricted')
                    self.operations.fault = fail
                    self.refused()
                    self.assertEqual(reached, [point])
                    self.assertEqual(len(self.effects), 2)
                    self.assertTrue((self.state / 'operation-02-pending.json').exists())

    def test_lost_stop_return_prevents_later_effects_without_replay(self):
        self.effect_hook = lambda: (_ for _ in ()).throw(commands.CommandUncertain('restricted'))
        self.refused()
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.kill_file.read_bytes(), b'')
        self.assertFalse((self.state / 'operation-02-return.json').exists())

    def test_original_peer_or_lock_loss_after_first_stop_prevents_second(self):
        for action in ('close', 'unlock'):
            with self.subTest(action=action):
                self.setUp()
                self.effect_hook = lambda: self.command(self.child, action)
                self.refused()
                self.assertEqual(len(self.effects), 1)
                self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_input_drift_at_pending_fsync_prevents_every_effect(self):
        reached = []
        def change(point):
            if point == 'readback':
                reached.append(point)
                self.write('reconcile-request.json', b'{}')
        self.operations.fault = change
        self.refused()
        self.assertEqual(reached, ['readback'])
        self.assertEqual(self.effects, [])
        self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_queued_job_or_unpinned_root_unit_denies_before_pending(self):
        for update in ({'Job':'12'}, {'Restart':'always'}, {'User':'1000'}, {'DropInPaths':'/unapproved'},
                       {'ControlGroup':'/outside'}, {'InvocationID':'b'*32}):
            with self.subTest(update=update):
                self.setUp()
                self.rows['dockerd'].update(update)
                self.refused()
                self.assertEqual(self.effects, [])
                self.assertFalse((self.state / 'operation-02-pending.json').exists())

    def test_new_manager_stop_job_does_not_masquerade_as_retirement(self):
        actual = self.run_effect
        def run(argv, *, deadline):
            raw = actual(argv, deadline=deadline)
            if 'StopUnit' in argv: self.rows['dockerd']['Job'] = '29'
            return raw
        self.transport.run = run
        self.refused()
        self.assertEqual(self.kill_file.read_bytes(), b'')
        self.assertFalse((self.state / 'operation-02-return.json').exists())

    def test_changed_runtime_invocation_is_not_killed(self):
        self.effect_hook = lambda: self.rows['containerd'].update(InvocationID='b'*32)
        self.refused()
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_kernel_write_barrier_checks_peer_after_open_before_write(self):
        actual = os.open
        reached = []
        def opening(path, flags, *args, **kwargs):
            fd = actual(path, flags, *args, **kwargs)
            if path == 'cgroup.kill':
                reached.append(path)
                self.command(self.child, 'close')
            return fd
        with patch.object(broker_runtime.os, 'open', side_effect=opening): self.refused()
        self.assertEqual(reached, ['cgroup.kill'])
        self.assertEqual(len(self.effects), 2)
        self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_failed_or_short_kernel_write_never_publishes_return(self):
        for fail in ('short', errno.EIO, errno.ENOSPC):
            with self.subTest(fail=fail):
                self.setUp()
                reached = []
                def writing(fd, raw):
                    reached.append(raw)
                    if fail == 'short': return 1
                    raise OSError(fail, 'restricted')
                # Pending persistence also uses os.write; install the fault only
                # at kill so this proves the exact kernel boundary.
                actual = self.domain.kill
                def kill(*, check):
                    with patch.object(broker_runtime.os, 'write', side_effect=writing): actual(check=check)
                with patch.object(self.domain, 'kill', side_effect=kill): self.refused()
                self.assertEqual(reached, [b'1\n'])
                self.assertFalse((self.state / 'operation-02-return.json').exists())

    def test_populated_slice_is_never_empty_or_a_drain_grant(self):
        self.events.write_bytes(b'populated 1\n')
        receipt = self.contain()
        self.assertFalse(receipt['runtime_empty_observed'])
        self.assertFalse(receipt['pending_drained'])
        self.assertFalse(receipt['complete_fence_proven'])

    def test_malformed_or_missing_recursive_events_cannot_return(self):
        for raw in (b'populated 0\npopulated 0\n', b'frozen 0\n', b'populated 00\n', b'populated 0\nextra 0\n'):
            with self.subTest(raw=raw):
                self.setUp()
                self.events.write_bytes(raw)
                self.refused()
                self.assertEqual(len(self.effects), 2)
                self.assertFalse((self.state / 'operation-02-return.json').exists())

    def test_symlink_kernel_kill_cannot_redirect_effect(self):
        target = self.root / 'unrelated'
        target.write_bytes(b'unchanged')
        self.kill_file.unlink()
        self.kill_file.symlink_to(target)
        self.refused()
        self.assertEqual(target.read_bytes(), b'unchanged')

    def test_slice_replacement_during_stop_refuses_before_recursive_kill(self):
        moved = self.group_path.with_name('retained.slice')
        def change():
            self.group_path.rename(moved)
            self.group_path.mkdir()
        self.effect_hook = change
        self.refused()
        self.assertEqual(len(self.effects), 1)
        self.assertEqual((moved / 'cgroup.kill').read_bytes(), b'')

    def test_expiry_regression_and_changed_boot_after_stop_never_continue(self):
        for change in ('expiry', 'regression', 'boot'):
            with self.subTest(change=change):
                self.setUp()
                def drift():
                    if change == 'expiry': self.now = 1090.
                    elif change == 'regression': self.now = 1049.
                    else: self.boot = 'different-boot'
                self.effect_hook = drift
                self.refused()
                self.assertEqual(len(self.effects), 1)
                self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_trailing_fsync_peer_loss_is_not_a_successful_return(self):
        reached = []
        def lose(point):
            if point == 'readback' and self.kill_file.read_bytes() == b'1\n':
                reached.append(point)
                self.command(self.child, 'close')
        self.operations.fault = lose
        self.refused()
        self.assertEqual(reached, ['readback'])
        self.assertTrue((self.state / 'operation-02-return.json').exists())

    def test_trailing_fsync_population_cannot_hide_behind_a_return_record(self):
        def change(point):
            if point == 'readback' and self.kill_file.read_bytes() == b'1\n':
                self.events.write_bytes(b'populated 1\n')
        self.operations.fault = change
        self.assertFalse(self.contain()['runtime_empty_observed'])

    def test_command_redirection_is_not_a_fixed_effect(self):
        self.effect_hook = lambda: setattr(self.adapter, 'systemctl', '/other/systemctl')
        self.refused()
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_missing_forward_return_refuses_before_effect(self):
        self.operations._returned.remove('contain_forward')
        self.refused()
        self.assertEqual(self.effects, [])
        self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_reopened_state_cannot_be_a_fresh_cold_permit(self):
        self.operations = broker_operations.OperationJournal(self.operations.fd, binding=self.binding, epoch=self.epoch,
            clock=lambda: self.now, boot_id=lambda: self.boot)
        self.adapter = self.make_adapter()
        self.refused()
        self.assertEqual(self.effects, [])

    def test_untyped_domain_or_wrong_slice_never_constructs(self):
        with self.assertRaises(durable.Rejected): self.make_adapter(domain=SimpleNamespace())
        self.domain.cgroup = '/different.slice'
        with self.assertRaises(durable.Rejected): self.make_adapter()

    def test_missing_cgroup_events_is_not_empty(self):
        self.events.unlink()
        self.refused()
        self.assertEqual(self.kill_file.read_bytes(), b'1\n')
        self.assertFalse((self.state / 'operation-02-return.json').exists())

    def test_calling_broker_inside_runtime_or_ambiguous_cgroup_refuses(self):
        actual = open
        for raw in (b'0::/fixture_runtime.slice/broker.service\n', b'0::/\n1:cpu:/\n', b'0::/\nextra'):
            with self.subTest(raw=raw):
                self.setUp()
                def opening(path, *args, **kwargs):
                    if path == '/proc/self/cgroup': return io.BytesIO(raw)
                    return actual(path, *args, **kwargs)
                with patch('builtins.open', side_effect=opening): self.refused()
                self.assertEqual(self.effects, [])
                self.assertEqual(self.kill_file.read_bytes(), b'')

    def test_runtime_cannot_contain_original_supervisor(self):
        self.engine._observed = durable.canonical({'cgroup':self.domain.cgroup+'/supervisor.service'})
        with patch.object(self.engine, 'observe'):
            self.refused()
        self.assertEqual(self.effects, [])


class RuntimeDomainMountTests(unittest.TestCase):
    def test_only_exact_cgroup2_mount_and_descriptor_mount_id_agree(self):
        # Exercise the real proc parser without any real cgroup write.
        domain = object.__new__(broker_runtime.RuntimeDomain)
        domain.fd, domain.mount_root = 99, '/fixture-cgroups'
        good = b'42 1 0:30 / /fixture-cgroups rw - cgroup2 cgroup rw\n'
        for mount, info, accepted in (
            (good, b'pos:\t0\nmnt_id:\t42\n', True),
            (good, b'mnt_id:\t43\n', False),
            (good+good, b'mnt_id:\t42\n', False),
            (good.replace(b'cgroup2', b'tmpfs'), b'mnt_id:\t42\n', False),
            (good.replace(b' / /fixture', b' /subtree /fixture'), b'mnt_id:\t42\n', False),
            (good, b'mnt_id:\t42\nmnt_id:\t42\n', False),
            (b'x'*(1024*1024+1), b'', False),
            (good, b'x'*4097, False)):
            with self.subTest(accepted=accepted, mount_size=len(mount)):
                def opening(path, mode):
                    self.assertEqual(mode, 'rb')
                    self.assertIn(path, ('/proc/self/mountinfo', '/proc/self/fdinfo/99'))
                    return io.BytesIO(mount if path.endswith('mountinfo') else info)
                with patch('builtins.open', side_effect=opening):
                    if accepted: domain._mount()
                    else:
                        with self.assertRaises(durable.Rejected): domain._mount()
