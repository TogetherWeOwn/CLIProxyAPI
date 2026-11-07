"""Owned synthetic directories only; no manager, daemon or host unit mutation."""
from dataclasses import replace
import errno
import os
from pathlib import Path
import select
import signal
import tempfile
import unittest

from fixture_home import fixture_home
from host_recovery import durable, installation, unit_masks
from test_installation import approve
from test_manager import binding, observed
import test_broker_containment as containment_fixture


class PersistentUnitMaskTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='.unit-mask-test-', dir=fixture_home())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / 'units'
        self.path.mkdir(mode=0o700)
        context = installation.open_approved_directory(approve(self.path))
        self.directory = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.units = {'forward': binding(observed('forward.service', 'a'*32, '/forward.slice/forward.service'))}
        self.calls = []
        self.masks = self.make()

    def make(self, **overrides):
        args = dict(directory=self.directory, units=self.units)
        args.update(overrides)
        return unit_masks.PersistentUnitMasks(**args)

    def current(self):
        self.calls.append('current')

    def publish(self):
        return self.masks.publish(current=self.current)

    def test_exact_fixed_link_fsync_readback_and_public_denies(self):
        unrelated = self.path / 'unrelated.service'
        unrelated.write_bytes(b'synthetic unrelated unit\n')
        original = unrelated.stat()
        receipt = self.publish()
        self.assertTrue(receipt['persistent_masks_published'])
        self.assertEqual(receipt['mask_count'], 1)
        self.assertEqual(receipt['target_sha256'], durable.digest(self.masks.configuration()))
        for key in ('manager_reload_performed', 'activation_exclusion_proven', 'manager_jobs_retired',
                    'pending_drained', 'complete_fence_proven', 'recovery_execution_allowed',
                    'start_allowed', 'settlement_allowed', 'production_acceptance'):
            self.assertIs(receipt[key], False)
        self.assertEqual(os.readlink(self.path / 'forward.service'), '/dev/null')
        self.assertEqual(unrelated.read_bytes(), b'synthetic unrelated unit\n')
        self.assertEqual(durable.signature(unrelated.stat()), durable.signature(original))
        self.assertNotIn(str(self.path), str(receipt))
        self.assertEqual(receipt, self.masks.observe(current=self.current))
        self.assertTrue(self.calls)

    def test_existing_file_mask_alias_dangling_link_or_directory_never_overwritten(self):
        for kind in ('file', 'mask', 'alias', 'dangling', 'directory'):
            with self.subTest(kind=kind):
                self.setUp()
                path = self.path / 'forward.service'
                if kind == 'file': path.write_bytes(b'preserve')
                elif kind == 'directory': path.mkdir()
                else: path.symlink_to({'mask':'/dev/null', 'alias':'other.service', 'dangling':'absent'}[kind])
                before = durable.signature(path.lstat())
                with self.assertRaises(durable.Rejected): self.make()
                with self.assertRaises(durable.Rejected): self.publish()
                self.assertEqual(before, durable.signature(path.lstat()))
                if kind == 'file': self.assertEqual(path.read_bytes(), b'preserve')

    def test_runtime_set_is_exact_and_partial_publication_never_adopted(self):
        self.units = {role: binding(observed(role+'.service', 'b'*32, '/runtime.slice/'+role+'.service'))
                      for role in ('dockerd', 'containerd')}
        self.masks = self.make()
        reached = []
        def fail(point):
            if point == 'create':
                reached.append(point)
                if len(reached) == 2: raise OSError(errno.EIO, 'restricted')
        self.masks.fault = fail
        with self.assertRaises(durable.Rejected): self.publish()
        self.assertEqual(reached, ['create', 'create'])
        self.assertEqual(sorted(p.name for p in self.path.iterdir()), ['containerd.service'])
        with self.assertRaises(durable.Rejected): self.make()
        with self.assertRaises(durable.Rejected): self.publish()
        self.assertFalse(self.masks.published)

    def test_runtime_set_publishes_both_without_caller_selected_names(self):
        self.units = {role: binding(observed(role+'.service', 'b'*32, '/runtime.slice/'+role+'.service'))
                      for role in ('dockerd', 'containerd')}
        self.masks = self.make()
        self.assertEqual(self.publish()['mask_count'], 2)
        self.assertEqual(sorted(p.name for p in self.path.iterdir()), ['containerd.service', 'dockerd.service'])

    def test_every_publication_fault_is_reached_sticky_and_preserves_partial_effect(self):
        for point in ('create', 'directory-fsync', 'readback'):
            for code in (errno.EIO, errno.ENOSPC):
                with self.subTest(point=point, code=code):
                    self.setUp()
                    reached = []
                    def fail(actual):
                        if actual == point:
                            reached.append(actual)
                            raise OSError(code, 'restricted')
                    self.masks.fault = fail
                    with self.assertRaisesRegex(durable.Rejected, '^unit-mask-publication-unconfirmed$'):
                        self.publish()
                    self.assertEqual(reached, [point])
                    self.assertTrue(self.masks.failed)
                    self.assertFalse(self.masks.published)
                    self.assertEqual(os.path.lexists(self.path / 'forward.service'), point != 'create')
                    with self.assertRaises(durable.Rejected): self.publish()
                    with self.assertRaises(durable.Rejected): self.masks.observe(current=self.current)

    def test_replacement_or_removal_after_publication_revokes_observation(self):
        for action in ('remove', 'same-target-replace', 'other-target', 'file'):
            with self.subTest(action=action):
                self.setUp()
                self.publish()
                path = self.path / 'forward.service'
                if action == 'same-target-replace':
                    replacement = self.path / 'replacement'
                    replacement.symlink_to('/dev/null')
                    self.assertNotEqual(replacement.lstat().st_ino, path.lstat().st_ino)
                    replacement.replace(path)
                else:
                    path.unlink()
                    if action == 'other-target': path.symlink_to('/not-a-mask')
                    elif action == 'file': path.write_bytes(b'/dev/null')
                with self.assertRaises(durable.Rejected): self.masks.observe(current=self.current)
                self.assertTrue(self.masks.failed)

    def test_directory_replacement_is_not_a_new_effect_destination(self):
        self.path.rename(self.root / 'old-units')
        self.path.mkdir(mode=0o700)
        with self.assertRaises(durable.Rejected): self.publish()
        self.assertEqual(list(self.path.iterdir()), [])
        self.assertEqual(list((self.root / 'old-units').iterdir()), [])
        # Expected validation failure is consumed here, not hidden at cleanup.
        self.path.rmdir()
        (self.root / 'old-units').rename(self.path)

    def test_expiry_or_authority_loss_during_fsync_keeps_mask_and_refuses(self):
        reached, expired = [], [False]
        def fail(point):
            if point == 'directory-fsync':
                reached.append(point)
                expired[0] = True
        def current():
            if expired[0]: raise durable.Rejected('synthetic-original-deadline')
        self.masks.fault = fail
        with self.assertRaises(durable.Rejected): self.masks.publish(current=current)
        self.assertEqual(reached, ['directory-fsync'])
        self.assertTrue((self.path / 'forward.service').is_symlink())
        self.assertFalse(self.masks.published)

    def test_late_collision_at_create_is_not_replaced(self):
        reached = []
        def collide(point):
            if point == 'create':
                reached.append(point)
                (self.path / 'forward.service').write_bytes(b'preserve')
        self.masks.fault = collide
        with self.assertRaises(durable.Rejected): self.publish()
        self.assertEqual(reached, ['create'])
        self.assertEqual((self.path / 'forward.service').read_bytes(), b'preserve')

    def test_configuration_changes_or_template_and_arbitrary_role_sets_refuse(self):
        for units in ({}, {'observer': self.units['forward']}, {'dockerd': self.units['forward']},
                      {'forward': replace(self.units['forward'], unit='forward@.service')}):
            with self.subTest(units=units):
                with self.assertRaises(durable.Rejected): self.make(units=units)
        self.masks.units['forward'] = replace(self.units['forward'], unit='other.service')
        with self.assertRaises(durable.Rejected): self.publish()
        self.assertEqual(list(self.path.iterdir()), [])

    def test_successful_publication_is_one_shot_and_reopened_masks_are_not_acknowledged(self):
        self.publish()
        before = durable.signature((self.path / 'forward.service').lstat())
        with self.assertRaises(durable.Rejected): self.publish()
        with self.assertRaises(durable.Rejected): self.make()
        self.assertEqual(before, durable.signature((self.path / 'forward.service').lstat()))

    def test_sigkill_after_fsync_before_ack_retains_mask_without_reopen_adoption(self):
        ready_r, ready_w = os.pipe()
        hold_r, hold_w = os.pipe()
        for fd in (ready_r, ready_w, hold_r, hold_w): self.addCleanup(os.close, fd)
        pid = os.fork()
        if pid == 0:
            try:
                def held(point):
                    if point == 'readback':
                        os.write(ready_w, b'fsynced')
                        os.read(hold_r, 1)
                self.masks.fault = held
                self.publish()
            finally:
                os._exit(2)
        try:
            poller = select.poll()
            poller.register(ready_r, select.POLLIN)
            self.assertTrue(poller.poll(5000), 'publication child did not reach fsync')
            self.assertEqual(os.read(ready_r, 7), b'fsynced')
        finally:
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFSIGNALED(status))
        self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
        self.assertEqual(os.readlink(self.path / 'forward.service'), '/dev/null')
        with self.assertRaises(durable.Rejected): self.make()


class ForwardPersistentMaskTests(unittest.TestCase):
    line = containment_fixture.ForwardContainmentTests.line
    connect = containment_fixture.ForwardContainmentTests.connect
    command = containment_fixture.ForwardContainmentTests.command
    write = containment_fixture.ForwardContainmentTests.write
    run_command = containment_fixture.ForwardContainmentTests.run_command
    make_engine = containment_fixture.ForwardContainmentTests.make_engine
    make_adapter = containment_fixture.ForwardContainmentTests.make_adapter
    run_effect = containment_fixture.ForwardContainmentTests.run_effect
    read_group = containment_fixture.ForwardContainmentTests.read_group
    contain = containment_fixture.ForwardContainmentTests.contain
    refused = containment_fixture.ForwardContainmentTests.refused
    assert_denies = containment_fixture.ForwardContainmentTests.assert_denies

    def setUp(self):
        containment_fixture.ForwardContainmentTests.setUp(self)
        self.mask_path = self.root / 'persistent-units'
        self.mask_path.mkdir(mode=0o700)
        context = installation.open_approved_directory(approve(self.mask_path))
        directory = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.masks = unit_masks.PersistentUnitMasks(directory=directory, units={'forward': self.forward})
        self.adapter = self.make_adapter(masks=self.masks)

    def test_outer_pending_binds_masks_before_any_creation_or_stop(self):
        reached = []
        def before_create(point):
            if point == 'create':
                reached.append(point)
                pending = durable.decode((self.state / 'operation-01-pending.json').read_bytes())
                self.assertEqual(pending['target_sha256'], self.adapter.target_sha256)
                self.assertEqual(self.effects, [])
                self.assertFalse((self.state / 'operation-01-return.json').exists())
        self.masks.fault = before_create
        self.effect_hook = lambda: self.assertEqual(os.readlink(self.mask_path / self.forward.unit), '/dev/null')
        receipt = self.contain()
        self.assertEqual(reached, ['create'])
        self.assertTrue(receipt['persistent_masks_published'])
        self.assertFalse(receipt['manager_reload_performed'])
        self.assert_denies(receipt)
        self.assertEqual(len(self.effects), 2)
        self.assertTrue(all('daemon-reload' not in call for call in self.effects))

    def test_pending_persistence_failure_never_writes_a_mask_or_stops(self):
        def fail(point):
            if point == 'directory-fsync': raise OSError(errno.EIO, 'restricted')
        self.operations.fault = fail
        self.refused()
        self.assertTrue((self.state / 'operation-01-pending.json').exists())
        self.assertEqual(list(self.mask_path.iterdir()), [])
        self.assertEqual(self.effects, [])

    def test_mask_persistence_fault_retains_pending_and_no_stop_or_return(self):
        reached = []
        def fail(point):
            if point == 'directory-fsync':
                reached.append(point)
                raise OSError(errno.ENOSPC, 'restricted')
        self.masks.fault = fail
        self.refused()
        self.assertEqual(reached, ['directory-fsync'])
        self.assertTrue((self.mask_path / self.forward.unit).is_symlink())
        self.assertTrue((self.state / 'operation-01-pending.json').exists())
        self.assertFalse((self.state / 'operation-01-return.json').exists())
        self.assertEqual(self.effects, [])

    def test_original_peer_loss_during_publication_never_submits_stop(self):
        reached = []
        def close(point):
            if point == 'readback':
                reached.append(point)
                self.command(self.child, 'close')
        self.masks.fault = close
        self.refused()
        self.assertEqual(reached, ['readback'])
        self.assertEqual(self.effects, [])
        self.assertTrue((self.mask_path / self.forward.unit).is_symlink())

    def test_mask_removed_after_stop_prevents_kill_and_return(self):
        self.effect_hook = lambda: (self.mask_path / self.forward.unit).unlink()
        self.refused()
        self.assertEqual(len(self.effects), 1)
        self.assertFalse((self.state / 'operation-01-return.json').exists())

    def test_changed_mask_object_after_pending_cannot_redirect_publication(self):
        reached = []
        def change(point):
            if point == 'readback':
                reached.append(point)
                self.adapter.masks = None
        self.operations.fault = change
        self.refused()
        self.assertEqual(reached, ['readback'])
        self.assertEqual(list(self.mask_path.iterdir()), [])
        self.assertEqual(self.effects, [])

    def test_loaded_configuration_drift_after_mask_never_weakens_existing_reader(self):
        reached = []
        def change(point):
            if point == 'readback':
                reached.append(point)
                self.forward_row['LoadState'] = 'masked'
        self.masks.fault = change
        self.refused()
        self.assertEqual(reached, ['readback'])
        self.assertEqual(self.effects, [])
        self.assertTrue((self.mask_path / self.forward.unit).is_symlink())
