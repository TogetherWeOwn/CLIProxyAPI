"""Real original flock/seqpacket/files; SCRIPTED manager/kernel/root broker.

These are connected component tests, not installed operational qualification.
"""
from dataclasses import replace
import errno
import json
import os
import unittest
from unittest.mock import patch

from host_recovery import containment_ipc as ipc, durable, manager_bus
from host_recovery.broker_operations import OperationJournal
from host_recovery.manager_jobs import ForwardStopJobs, RuntimeStopJobs
from host_recovery.masked_forward_stop import MaskedForwardStop
from host_recovery.masked_runtime_stop import MaskedRuntimeStop
from host_recovery.unit_masks import PersistentUnitMasks
import test_broker_client as client_fixture
import test_masked_forward_stop as forward_fixture
import test_masked_runtime_stop as runtime_fixture
import test_privileged_broker as peer_fixture
from test_persisted_policy import make_policy


class _ContainmentProtocolFixture(unittest.TestCase):
    runtime = False

    def setUp(self):
        self.peer = peer_fixture.BrokerProtocolTests()
        self.addCleanup(self.peer.doCleanups)
        self.peer.setUp()
        self.effects = (runtime_fixture.MaskedRuntimeStopTests() if self.runtime
                        else forward_fixture.MaskedForwardStopTests())
        self.addCleanup(self.effects.doCleanups)
        self.effects.setUp()
        fx = self.effects
        self.policy = None
        if self.runtime:
            fx.units = {role:replace(unit,unit='cpa-'+role+'.service',
                        cgroup='/runtime.slice/cpa-'+role+'.service') for role,unit in fx.units.items()}
            for role,unit in fx.units.items():fx.rows[role].update(Id=unit.unit,ControlGroup=unit.cgroup)
            fx.masks = PersistentUnitMasks(directory=fx.directory,units=fx.units)
            self.policy = make_policy(self,self.peer,units=fx.units)
        fx.session.close()
        fx.now = self.peer.now
        fx.session = manager_bus.ManagerJobSession(library=fx.library, library_sha256='a'*64, units=fx.units,
            deadline=1090., clock=lambda:fx.now, check=lambda:fx.check_hook(), authority=self.peer.engine)
        self.addCleanup(fx.session.close)
        fx.connection.job_units = fx.units
        fx.connection.inventory = []
        state = fx.root / 'connected-state'
        state.mkdir(mode=0o700)
        fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        fx.journal = OperationJournal(fd, binding=self.peer.binding, epoch=self.peer.epoch,
            clock=lambda:self.peer.now, boot_id=lambda:self.peer.boot)
        if self.runtime:
            forward = fx.journal.pending('contain_forward', target_sha256='e'*64, deadline=1090.)
            fx.journal.returned(forward, result='returned')
        kind = RuntimeStopJobs if self.runtime else ForwardStopJobs
        fx.jobs = kind(journal=fx.journal, units=fx.units, busctl='/synthetic/busctl', busctl_sha256='b'*64,
            commands=None, read_helper_hash=lambda path:'b'*64, session=fx.session)
        kwargs = dict(journal=fx.journal, masks=fx.masks, jobs=fx.jobs, authority=self.peer.engine)
        self.sequence = (MaskedRuntimeStop(**kwargs, domain=fx.domain, policy=self.policy.adapter)
                         if self.runtime else MaskedForwardStop(**kwargs))
        self.server = ipc.ContainmentServer(authority=self.peer.engine, sequence=self.sequence)
        self.state = state
        self.value = ipc.containment_request(method=self.sequence.method, target_sha256=self.sequence.target_sha256,
            binding_sha256=durable.digest(durable.canonical(self.peer.binding)),
            epoch_sha256=durable.digest(durable.canonical(self.peer.epoch)), nonce='a'*64, deadline=1090.)

    def queue(self, value=None, ack=None):
        self.peer.queue(value=self.value if value is None else value, ack=ack)

    def serve(self):
        return self.server.serve_once(deadline=1100.)

    def refused(self):
        with self.assertRaisesRegex(durable.Rejected, '^containment-protocol-unconfirmed$'):
            self.serve()
        self.assertTrue(self.server.failed and self.peer.engine.failed and self.effects.journal._failed)
        with self.assertRaisesRegex(durable.Rejected, '^containment-protocol-exhausted$'):
            self.serve()

    def effect_names(self):
        return [call[1] for call in self.effects.connection.calls
                if call[1] in ('Cancel','Reload','StopUnit','KillUnit')]


class ContainmentProtocolTests(_ContainmentProtocolFixture):
    def test_connected_submission_persists_original_pending_before_effect_and_return_before_reply(self):
        reached = []
        def effect(*args):
            reached.append(args[0])
            self.assertEqual(durable.decode((self.state/'operation-01-pending.json').read_bytes()),
                             ipc.operation_for(self.value))
            self.assertFalse((self.state/'operation-01-return.json').exists())
        self.effects.hook = effect
        self.queue()
        result = self.serve()
        self.assertEqual(result, ipc.containment_response(self.value))
        self.assertEqual(json.loads(self.peer.line(self.peer.child)), result)
        self.assertIn('StopUnit', reached)
        self.assertEqual(durable.decode((self.state/'operation-01-return.json').read_bytes()),
                         ipc.return_for(ipc.operation_for(self.value)))
        for field in ipc.DENIES:
            self.assertIs(result['observation'][field], False)
        self.assertEqual(self.effects.journal._returned, {'contain_forward'})
        with self.assertRaises(durable.Rejected): self.serve()
        self.assertEqual(self.effect_names().count('StopUnit'), 1)

    def test_packet_cannot_choose_method_target_epoch_unit_or_expanded_deadline(self):
        for change in ({'method':'start_verified_old'}, {'target_sha256':'f'*64}, {'epoch_sha256':'e'*64},
                       {'unit':'foreign.service'}, {'deadline':True}, {'deadline':1091.}):
            with self.subTest(change=change):
                self.setUp()
                self.queue({**self.value, **change})
                self.refused()
                self.assertEqual(self.effect_names(), [])
                self.assertEqual(sorted(p.name for p in self.state.iterdir()), ['epoch.json'])

    def test_wrong_ack_cannot_reissue_a_completed_submission(self):
        self.queue(ack={'schema':'host-recovery-broker-ack-v1','request_sha256':'f'*64})
        self.refused()
        self.assertTrue((self.state/'operation-01-return.json').exists())
        self.assertEqual(self.effect_names().count('StopUnit'), 1)
        self.assertEqual(json.loads(self.peer.line(self.peer.child)), ipc.containment_response(self.value))

    def test_disconnect_before_read_performs_no_effect(self):
        self.peer.command(self.peer.child, 'close')
        self.refused()
        self.assertEqual(self.effect_names(), [])
        self.assertFalse((self.state/'operation-01-pending.json').exists())

    def test_real_lock_loss_while_manager_reply_waits_prevents_stop_submission(self):
        reached = []
        self.queue()
        def waiting():
            reached.append(True)
            self.peer.command(self.peer.child, 'unlock')
        self.effects.connection.mode = 'stall'
        self.effects.connection.wait_hook = waiting
        self.refused()
        self.assertEqual(reached, [True])
        self.assertEqual(self.effect_names(), [])
        self.assertTrue((self.state/'operation-01-pending.json').exists())
        self.assertFalse((self.state/'operation-01-return.json').exists())

    def test_original_input_change_after_pending_prevents_any_manager_effect(self):
        self.queue()
        original = self.effects.journal.pending
        def pending(*args, **kwargs):
            value = original(*args, **kwargs)
            self.peer.write('reconcile-request.json', b'{}')
            return value
        with patch.object(self.effects.journal, 'pending', side_effect=pending): self.refused()
        self.assertEqual(self.effect_names(), [])
        self.assertTrue((self.state/'operation-01-pending.json').exists())

    def test_pending_storage_faults_are_reached_before_any_effect(self):
        for point in ('create','write','file-fsync','rename','directory-fsync','readback'):
            for code in (errno.EIO, errno.ENOSPC):
                with self.subTest(point=point, code=code):
                    self.setUp()
                    reached = []
                    def fault(actual):
                        if actual == point:
                            reached.append(actual)
                            raise OSError(code, 'synthetic storage fault')
                    self.effects.journal.fault = fault
                    self.queue()
                    self.refused()
                    self.assertEqual(reached, [point])
                    self.assertEqual(self.effect_names(), [])
                    self.assertFalse((self.state/'operation-01-return.json').exists())

    def test_return_reactivation_is_not_hidden_by_equal_execution_timestamp(self):
        self.queue()
        reached = []
        original = self.effects.journal.returned
        def returned(*args, **kwargs):
            value = original(*args, **kwargs)
            reached.append(True)
            self.effects.row.update(ActiveState='active', SubState='running', MainPID=123)
            return value
        with patch.object(self.effects.journal, 'returned', side_effect=returned): self.refused()
        self.assertEqual(reached, [True])
        self.assertEqual(self.effect_names().count('StopUnit'), 1)
        self.assertTrue((self.state/'operation-01-return.json').exists())

    def test_restart_policy_drift_after_return_durability_prevents_reply(self):
        self.queue()
        reached = []
        original = self.effects.journal.returned
        def returned(*args, **kwargs):
            value = original(*args, **kwargs)
            reached.append(True)
            self.effects.row['Restart'] = 'always'
            return value
        with patch.object(self.effects.journal, 'returned', side_effect=returned): self.refused()
        self.assertEqual(reached, [True])
        self.assertTrue((self.state/'operation-01-return.json').exists())
        self.assertEqual(self.effect_names().count('StopUnit'), 1)

    def test_activation_hook_after_reply_revokes_ack_without_reissuing_stop(self):
        self.queue()
        original = self.peer.peer.reply
        received = []
        def reply(*args):
            original(*args)
            received.append(json.loads(self.peer.line(self.peer.child)))
            self.effects.row['OnSuccess'] = ['late.service']
        with patch.object(self.peer.peer, 'reply', side_effect=reply): self.refused()
        self.assertEqual(received, [ipc.containment_response(self.value)])
        self.assertTrue((self.state/'operation-01-return.json').exists())
        self.assertEqual(self.effect_names().count('StopUnit'), 1)
        self.assertFalse(received[0]['observation']['start_allowed'])

    def test_auxiliary_writer_after_return_durability_prevents_reply(self):
        self.queue()
        reached = []
        original = self.effects.journal.returned
        def returned(*args, **kwargs):
            value = original(*args, **kwargs)
            reached.append(True)
            self.effects.row['ExecStopPost'] = ['synthetic writer']
            return value
        with patch.object(self.effects.journal, 'returned', side_effect=returned): self.refused()
        self.assertEqual(reached, [True])
        self.assertTrue((self.state/'operation-01-return.json').exists())
        self.assertEqual(self.effect_names().count('StopUnit'), 1)

    def test_control_process_after_reply_revokes_ack_without_reissuing_stop(self):
        self.queue()
        original = self.peer.peer.reply
        received = []
        def reply(*args):
            original(*args)
            received.append(json.loads(self.peer.line(self.peer.child)))
            self.effects.row['ControlPID'] = 321
        with patch.object(self.peer.peer, 'reply', side_effect=reply): self.refused()
        self.assertEqual(received, [ipc.containment_response(self.value)])
        self.assertTrue((self.state/'operation-01-return.json').exists())
        self.assertEqual(self.effect_names().count('StopUnit'), 1)
        self.assertFalse(received[0]['observation']['start_allowed'])

    def test_peer_loss_after_reply_keeps_return_without_settlement(self):
        self.queue()
        original = self.peer.peer.reply
        received = []
        def reply(*args):
            original(*args)
            received.append(json.loads(self.peer.line(self.peer.child)))
            self.peer.command(self.peer.child, 'unlock')
        with patch.object(self.peer.peer, 'reply', side_effect=reply): self.refused()
        self.assertEqual(received, [ipc.containment_response(self.value)])
        self.assertTrue((self.state/'operation-01-return.json').exists())

    def test_return_directory_fsync_fault_preserves_consumed_effect_without_reply(self):
        self.queue()
        reached = []
        original = self.effects.journal.returned
        def returned(*args, **kwargs):
            def fault(point):
                if point == 'directory-fsync':
                    reached.append(point)
                    raise OSError(errno.ENOSPC, 'synthetic storage fault')
            self.effects.journal.fault = fault
            return original(*args, **kwargs)
        with patch.object(self.effects.journal, 'returned', side_effect=returned): self.refused()
        self.assertEqual(reached, ['directory-fsync'])
        self.assertEqual(self.effect_names().count('StopUnit'), 1)
        self.assertTrue((self.state/'operation-01-return.json').exists())
        self.assertIsNone(self.sequence._returned_raw)

    def test_return_publication_cannot_hide_trailing_original_peer_loss(self):
        self.queue()
        reached = []
        original = self.effects.journal.returned
        def returned(*args, **kwargs):
            value = original(*args, **kwargs)
            reached.append(True)
            self.peer.command(self.peer.child, 'unlock')
            return value
        with patch.object(self.effects.journal, 'returned', side_effect=returned): self.refused()
        self.assertEqual(reached, [True])
        self.assertEqual(self.effect_names().count('StopUnit'), 1)
        self.assertTrue((self.state/'operation-01-return.json').exists())

    def test_lost_reply_preserves_return_and_never_retries_effect(self):
        self.queue()
        reached = []
        def lost(*args):
            reached.append(True)
            self.assertTrue((self.state/'operation-01-return.json').exists())
            raise BrokenPipeError()
        with patch.object(self.peer.peer, 'reply', side_effect=lost): self.refused()
        self.assertEqual(reached, [True])
        self.assertEqual(self.effect_names().count('StopUnit'), 1)

    def test_completed_adapter_cannot_be_replaced_with_an_unbound_or_reopened_one(self):
        self.queue()
        self.sequence.authority = None
        self.refused()
        self.assertEqual(self.effect_names(), [])
        with self.assertRaises(durable.Rejected):
            ipc.ContainmentServer(authority=self.peer.engine, sequence=self.effects.sequence)


class RuntimeContainmentProtocolTests(_ContainmentProtocolFixture):
    runtime = True
    def test_connected_runtime_retains_witness_through_return_and_ack_then_closes(self):
        reached = []
        def dead(*, check):
            self.assertFalse(self.effects.witness.close.called)
            if (self.state/'operation-02-return.json').exists(): reached.append('after-return')
            check()
        self.effects.witness.require_dead.side_effect = dead
        self.queue()
        result = self.serve()
        self.assertEqual(result, ipc.containment_response(self.value))
        self.assertTrue(reached)
        self.effects.witness.close.assert_called_once()
        self.assertEqual(self.effects.journal._returned, {'contain_forward','cold_quiesce_runtime'})
        self.assertEqual([item[0] for item in self.effects.effects].count('slice-kill'), 1)

    def test_runtime_thaw_during_return_durability_refuses_before_reply(self):
        self.queue()
        reached = []
        def fault(point):
            if point == 'directory-fsync' and (self.state/'operation-02-return.json').exists():
                reached.append(point)
                self.effects.domain.frozen.return_value = False
        self.effects.journal.fault = fault
        self.refused()
        self.assertEqual(reached, ['directory-fsync'])
        self.assertTrue((self.state/'operation-02-return.json').exists())
        self.effects.domain.freeze.assert_called_once()
        self.effects.domain.kill.assert_called_once()
        self.effects.witness.close.assert_called_once()

    def test_runtime_thaw_after_reply_prevents_ack_completion(self):
        self.queue()
        original = self.peer.peer.reply
        reached = []
        def reply(*args):
            result = original(*args)
            reached.append('reply')
            self.effects.domain.frozen.return_value = False
            return result
        with patch.object(self.peer.peer, 'reply', side_effect=reply): self.refused()
        self.assertEqual(reached, ['reply'])
        self.assertTrue((self.state/'operation-02-return.json').exists())
        self.effects.domain.freeze.assert_called_once()
        self.effects.domain.kill.assert_called_once()
        self.effects.witness.close.assert_called_once()

    def test_runtime_repopulation_after_return_refuses_and_closes_witness(self):
        self.queue()
        original = self.effects.journal.returned
        def returned(*args, **kwargs):
            value = original(*args, **kwargs)
            self.effects.domain.populated.return_value = True
            return value
        with patch.object(self.effects.journal, 'returned', side_effect=returned): self.refused()
        self.assertTrue((self.state/'operation-02-return.json').exists())
        self.effects.witness.close.assert_called_once()

    def test_runtime_protocol_requires_a_bound_policy_before_any_effect(self):
        fx=self.effects
        sequence=MaskedRuntimeStop(journal=fx.journal,masks=fx.masks,jobs=fx.jobs,domain=fx.domain,
                                   authority=self.peer.engine)
        with self.assertRaisesRegex(durable.Rejected,'^containment-runtime-persisted-policy-required$'):
            ipc.ContainmentServer(authority=self.peer.engine,sequence=sequence)
        self.assertEqual(self.effect_names(),[])

    def test_persisted_policy_failure_after_kill_prevents_outer_return_and_ack(self):
        path=self.policy.path/'hostconfig.json'
        path.write_bytes(durable.canonical({**self.policy.host,'RestartPolicy':{'Name':'always','MaximumRetryCount':0}}))
        self.queue();self.refused()
        self.assertEqual([item[0] for item in self.effects.effects].count('slice-kill'),1)
        self.assertFalse((self.state/'operation-02-return.json').exists())
        self.effects.witness.close.assert_called_once()

    def test_metadata_drift_during_outer_return_refuses_before_reply(self):
        self.queue();reached=[]
        original=self.effects.journal.returned
        def returned(*args,**kwargs):
            value=original(*args,**kwargs);reached.append(True)
            path=self.policy.path/'config.v2.json'
            path.write_bytes(durable.canonical({**self.policy.config,'Image':'sha256:'+'8'*64}))
            return value
        with patch.object(self.effects.journal,'returned',side_effect=returned):self.refused()
        self.assertEqual(reached,[True])
        self.assertTrue((self.state/'operation-02-return.json').exists())
        self.effects.witness.close.assert_called_once()

    def test_repopulation_during_policy_read_is_not_hidden_by_valid_metadata(self):
        from host_recovery import persisted_policy
        original=persisted_policy.read_file;reached=[]
        def read(*args,**kwargs):
            value=original(*args,**kwargs)
            if args[1]=='hostconfig.json' and not reached:
                reached.append(True);self.effects.domain.populated.return_value=True
            return value
        self.queue()
        with patch.object(persisted_policy,'read_file',side_effect=read):self.refused()
        self.assertEqual(reached,[True])
        self.assertFalse((self.state/'operation-02-return.json').exists())
        self.effects.witness.close.assert_called_once()

    def test_policy_storage_fault_is_reached_after_containment_without_return(self):
        from host_recovery import persisted_policy
        original=persisted_policy.read_file;reached=[]
        def read(*args,**kwargs):
            if args[1]=='hostconfig.json':
                reached.append(True);raise OSError(errno.EIO,'synthetic read failure')
            return original(*args,**kwargs)
        self.queue()
        with patch.object(persisted_policy,'read_file',side_effect=read):self.refused()
        self.assertEqual(reached,[True])
        self.assertEqual([item[0] for item in self.effects.effects].count('slice-kill'),1)
        self.assertFalse((self.state/'operation-02-return.json').exists())
        self.effects.witness.close.assert_called_once()


class ContainmentClientTests(unittest.TestCase):
    def setUp(self):
        self.fx = client_fixture.BrokerClientTests()
        self.fx.setUp()
        self.engine = ipc.ContainmentClient(broker=self.fx.broker, binding=self.fx.binding, epoch=self.fx.epoch,
            deadline=1100., method='contain_forward', target_sha256='e'*64)
        self.fx.session.receive.side_effect = lambda deadline:ipc.containment_response(self.fx.sent[0])

    def submit(self):
        return self.engine.submit(deadline=1090.)

    def refused(self):
        with self.assertRaisesRegex(durable.Rejected, '^containment-client-unconfirmed$'): self.submit()
        self.assertTrue(self.engine.failed and self.fx.broker.failed)
        with self.assertRaises(durable.Rejected): self.submit()

    def test_exact_method_target_return_and_literal_denies_checked_before_ack(self):
        result = self.submit()
        self.assertEqual(result, ipc.containment_response(self.fx.sent[0]))
        self.assertEqual(self.fx.sent[1], ipc.acknowledgment(self.fx.sent[0]))
        self.assertEqual(self.fx.broker.observe.call_count, 3)
        self.assertEqual(len(self.fx.sent), 2)
        for field in ipc.DENIES: self.assertIs(result['observation'][field], False)

    def test_wrong_target_return_nonce_or_integer_boolean_has_no_ack(self):
        for field in ('target_sha256','return_sha256','nonce','complete_fence_proven','start_allowed'):
            with self.subTest(field=field):
                self.setUp()
                def bad(deadline):
                    result = ipc.containment_response(self.fx.sent[0])
                    if field in result: result[field] = 'f'*64
                    else: result['observation'][field] = 0
                    return result
                self.fx.session.receive.side_effect = bad
                self.refused()
                self.assertEqual(len(self.fx.sent), 1)

    def test_reply_loss_is_one_send_without_retry(self):
        self.fx.session.receive.side_effect = BrokenPipeError()
        self.refused()
        self.assertEqual(len(self.fx.sent), 1)

    def test_peer_loss_after_reply_has_no_ack(self):
        self.fx.broker.observe.side_effect = [None, durable.Rejected('lost')]
        self.refused()
        self.assertEqual(len(self.fx.sent), 1)

    def test_expiry_during_ack_cannot_be_a_successful_return(self):
        self.fx.hook = lambda value:setattr(self.fx, 'now', 1090.) if value['schema'].endswith('-ack-v1') else None
        self.refused()
        self.assertEqual(len(self.fx.sent), 2)

    def test_noncontainment_methods_refuse_before_transport(self):
        for method in ('restore_approved_baseline','start_verified_old','dispatch_recovery','exec'):
            with self.subTest(method=method), self.assertRaises(durable.Rejected):
                ipc.ContainmentClient(broker=self.fx.broker, binding=self.fx.binding, epoch=self.fx.epoch,
                    deadline=1100., method=method, target_sha256='e'*64)
        self.assertEqual(self.fx.sent, [])


if __name__ == '__main__':
    unittest.main()
