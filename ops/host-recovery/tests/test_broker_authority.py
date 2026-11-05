"""Real synthetic lock-owning peers with SCRIPTED manager replies; no root/drill."""
from dataclasses import replace
import errno
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import bootstrap, broker_authority, broker_history, durable, jobs, loading, manager
from test_bootstrap import BOOT
from test_broker_history import original_inputs
import test_lock_observation as lock_fixture
from test_manager import encoded, observed


class BrokerAuthorityTests(unittest.TestCase):
    # Reuse only process/lock fixture helpers, not the other class's test methods.
    line = lock_fixture.OriginalLockObservationTests.line
    connect = lock_fixture.OriginalLockObservationTests.connect
    command = lock_fixture.OriginalLockObservationTests.command

    def setUp(self):
        lock_fixture.OriginalLockObservationTests.setUp(self)
        self.now, self.boot = 1050., BOOT
        source = original_inputs()
        value = source.intent
        value['owner']['boot_id'] = BOOT
        arm = durable.decode(source.arm_raw)
        arm['arm']['boot_id'] = BOOT
        arm['intent_sha256'] = durable.digest(durable.canonical(value))
        request = source.request
        request.update(owner=value['owner'].copy(), intent_sha256=arm['intent_sha256'], original_arm=arm['arm'].copy())
        request.pop('request_id')
        request['request_id'] = durable.digest(durable.canonical(request))
        self.inputs = loading.RecoveryInputs(durable.canonical(value), durable.canonical(request), durable.canonical(arm))
        self.owner = request['owner']
        for name, raw in (('intent.json', self.inputs.intent_raw), ('arm.json', self.inputs.arm_raw),
                          ('reconcile-request.json', self.inputs.request_raw)):
            self.write(name, raw)
        self.recovery = loading.RecoveryApproval(durable.digest(self.inputs.intent_raw), value['package_sha256'],
            value['manifest_sha256'], value['baseline_sha256'], value['policy_sha256'], value['installation_id'],
            value['attempt_id'], os.geteuid(), os.getegid())
        self.recovery_binding = jobs.RecoveryJobBinding(request['request_id'], '/synthetic/recovery.service', 'e'*64, 'f'*64)
        self.binding = broker_history.original_binding(self.inputs, topology_sha256='c'*64)
        self.lock, self.child, self.peer = self.connect()
        self.row = observed(self.owner['unit'], self.owner['invocation_id'], '/synthetic/supervisor.service')
        self.row.update(MainPID=str(self.child.pid), Restart='on-failure', User=str(os.geteuid()), Group=str(os.getegid()))
        self.calls, self.hook = [], lambda: None
        self.group, self.fragment = self.row['ControlGroup'], 'f'*64
        self.manager = bootstrap.SystemdSupervisorIdentity(systemctl='/accepted/systemctl',
            commands=SimpleNamespace(run=self.run_command),
            binding=bootstrap.SupervisorBinding(self.row['Id'], self.row['FragmentPath'], self.fragment,
                durable.digest(durable.canonical(manager.static_properties(self.row))), os.geteuid(), os.getegid()),
            clock=lambda: self.now, boot_id=lambda: self.boot,
            read_fragment_hash=lambda _: self.fragment, read_process_cgroup=lambda _: self.group)
        self.engine = self.make_engine()

    def write(self, name, raw):
        path = self.journal / name
        path.write_bytes(raw)
        path.chmod(0o600)

    def make_engine(self, **overrides):
        args = dict(lock=self.lock, manager=self.manager, approval=self.recovery,
            recovery_binding=self.recovery_binding, supervisor_owner=self.owner, binding=self.binding, deadline=1110.)
        args.update(overrides)
        return broker_authority.SupervisorPeerAuthority(**args)

    def run_command(self, argv, *, deadline):
        self.calls.append((argv, deadline))
        raw = encoded(self.row)
        self.hook()
        return raw

    def observe(self, deadline=1100.):
        return self.engine.observe(deadline=deadline)

    def refused(self):
        with self.assertRaisesRegex(durable.Rejected, '^broker-authority-observation-unconfirmed$'):
            self.observe()
        self.assertTrue(self.engine.failed)

    def test_original_peer_manager_lock_and_journal_compose_without_authority_grant(self):
        before = {p.name:p.read_bytes() for p in self.journal.iterdir()}
        result = self.observe()
        self.assertTrue(result['original_supervisor_observed'])
        self.assertTrue(result['original_lock_observed'])
        self.assertTrue(result['original_inputs_observed'])
        for field in ('pending_drained', 'complete_fence_proven', 'recovery_execution_allowed',
                      'start_allowed', 'settlement_allowed', 'production_acceptance'):
            self.assertIs(result[field], False)
        self.assertEqual(len(self.calls), 4)
        for argv, deadline in self.calls:
            self.assertEqual(argv, ('/accepted/systemctl', '--no-pager', 'show',
                '--property='+','.join(sorted(manager.PROPERTIES)), '--', self.owner['unit']))
            self.assertEqual(deadline, 1100.)
        self.assertEqual(before, {p.name:p.read_bytes() for p in self.journal.iterdir()})

    def test_original_owner_snapshots_are_not_borrowed_mutable_dictionaries(self):
        self.owner['invocation_id'] = 'b'*32
        self.binding['request_sha256'] = '0'*64
        self.observe()

    def test_wrong_unit_uid_gid_or_original_owner_refuses_construction(self):
        for change in ({'unit':'foreign.service'}, {'boot_id':'foreign'}, {'installation_id':'foreign'}):
            with self.subTest(change=change), self.assertRaises(durable.Rejected):
                self.make_engine(supervisor_owner={**self.owner, **change})
        with self.assertRaises(durable.Rejected):
            self.make_engine(approval=replace(self.recovery, uid=os.geteuid()+1))

    def test_stale_mainpid_or_invocation_never_authorizes_a_live_socket_peer(self):
        self.row['MainPID'] = str(self.child.pid+1)
        self.refused()
        self.row['MainPID'] = str(self.child.pid)
        self.refused()

    def test_replaced_invocation_with_same_mainpid_refuses(self):
        self.row['InvocationID'] = 'b'*32
        self.refused()

    def test_unit_fragment_or_command_drift_refuses(self):
        self.row['ExecStart'] = self.row['ExecStart'].replace('/accepted/helper', '/other/helper')
        self.refused()

    def test_process_cgroup_must_match_fresh_manager_observations(self):
        self.group = '/foreign/service'
        self.refused()

    def test_lock_loss_during_trailing_manager_queries_refuses(self):
        def unlock():
            if len(self.calls) == 4:
                self.command(self.child, 'unlock')
        self.hook = unlock
        self.refused()
        self.assertEqual(len(self.calls), 4)

    def test_peer_close_during_original_journal_read_refuses(self):
        actual = broker_authority.load_recovery
        reached = []
        def close(*args, **kwargs):
            value = actual(*args, **kwargs)
            reached.append(True)
            self.command(self.child, 'close')
            return value
        with patch.object(broker_authority, 'load_recovery', side_effect=close):
            self.refused()
        self.assertEqual(reached, [True])

    def test_request_bytes_changed_before_observation_refuse(self):
        self.write('reconcile-request.json', b'{}')
        self.refused()

    def test_ambiguous_staging_is_not_a_clean_original_journal(self):
        self.write('.stage-reconcile-request.json', b'partial')
        self.refused()

    def test_original_journal_replacement_refuses_even_while_old_inode_remains_locked(self):
        self.journal.rename(self.root / 'prior-journal')
        self.journal.mkdir(mode=0o700)
        self.refused()

    def test_original_deadline_and_boot_cannot_renew(self):
        self.now = 1180.
        self.refused()
        self.now, self.boot = 1050., 'other-boot'
        self.refused()

    def test_successfully_shortened_deadline_cannot_expand(self):
        self.observe(deadline=1075.)
        with self.assertRaises(durable.Rejected):
            self.observe(deadline=1100.)
        self.assertTrue(self.engine.failed)

    def test_clock_regression_during_manager_read_is_sticky(self):
        self.hook = lambda: setattr(self, 'now', 1049.)
        self.refused()
        self.hook, self.now = lambda: None, 1050.
        self.refused()

    def test_journal_read_eio_and_enospc_are_sanitized_and_revoke(self):
        for code in (errno.EIO, errno.ENOSPC):
            self.engine = self.make_engine()
            with self.subTest(code=code), patch.object(broker_authority, 'load_recovery',
                    side_effect=OSError(code, 'restricted-detail')) as read:
                self.refused()
                read.assert_called_once()

    def test_input_drift_during_trailing_manager_query_is_not_an_earlier_clean_prefix(self):
        def change():
            if len(self.calls) == 4:
                self.write('reconcile-request.json', b'{}')
        self.hook = change
        self.refused()
        self.assertEqual(len(self.calls), 4)

    def test_final_boot_read_cannot_return_an_expired_observation(self):
        actual = self.lock.observe
        calls = []
        def observe(*, deadline):
            result = actual(deadline=deadline)
            calls.append(True)
            if len(calls) == 2:
                def late_boot():
                    self.now = deadline
                    return self.boot
                self.manager.boot_id = late_boot
            return result
        with patch.object(self.lock, 'observe', side_effect=observe):
            self.refused()
        self.assertEqual(len(calls), 2)

    def test_boot_change_after_first_manager_reply_refuses(self):
        self.hook = lambda: setattr(self, 'boot', 'changed-boot')
        self.refused()
        self.assertEqual(len(self.calls), 1)
