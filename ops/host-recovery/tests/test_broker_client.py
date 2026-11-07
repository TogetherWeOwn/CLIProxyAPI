"""SCRIPTED broker identity/transport tests; no root-service or runtime proof."""
import copy
import unittest
from unittest.mock import Mock, patch

from host_recovery import broker_client, broker_identity, durable, privileged_broker as protocol
from test_bootstrap import BOOT
import test_broker_history as history


class BrokerClientTests(unittest.TestCase):
    def setUp(self):
        self.now = 1050.
        source = history.original_inputs()
        self.binding = history.history.original_binding(source, topology_sha256='c'*64)
        self.binding['original_boot_id'] = BOOT
        self.epoch = {'boot_id':BOOT, 'broker_invocation_id':'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
                      'runtime_epoch':'33333333-3333-4333-8333-333333333333'}
        self.session = Mock(spec=broker_identity.BrokerPeerSession)
        self.session._now.side_effect = lambda:self.now
        self.broker = Mock(spec=broker_identity.BrokerPeerIdentity)
        self.broker.session, self.broker.deadline, self.broker.failed = self.session, 1110., False
        self.broker.binding = broker_identity.BrokerBinding('fixed-broker.service','/accepted/broker.service',
            'f'*64,'e'*64,'b'*32,BOOT)
        self.sent, self.hook = [], lambda value:None
        def reply(value, deadline):
            self.sent.append(copy.deepcopy(value))
            self.hook(value)
        self.session.reply.side_effect = reply
        self.session.receive.side_effect = lambda deadline:protocol.response(self.sent[0])
        self.engine = self.client()

    def client(self, **overrides):
        args = dict(broker=self.broker, binding=self.binding, epoch=self.epoch, deadline=1100.)
        args.update(overrides)
        return broker_client.ObservationClient(**args)

    def observe(self, deadline=1090.):
        return self.engine.observe_installation(deadline=deadline)

    def refused(self):
        with self.assertRaisesRegex(durable.Rejected, '^broker-client-observation-unconfirmed$'):
            self.observe()
        self.assertTrue(self.engine.failed)
        self.assertTrue(self.broker.failed)
        with self.assertRaisesRegex(durable.Rejected, '^broker-client-exhausted$'):
            self.observe()

    def test_exact_response_and_post_reply_identity_precede_transport_ack(self):
        result = self.observe()
        self.assertEqual(result, protocol.response(self.sent[0]))
        self.assertEqual(self.sent[1], protocol.acknowledgment(self.sent[0]))
        self.assertEqual(self.broker.observe.call_count, 2)
        self.assertEqual(self.session.receive.call_args.kwargs, {})
        self.assertEqual(self.sent[0]['deadline'],1090.)
        self.assertEqual(len(self.sent[0]['nonce']),64)
        for key in ('pending_drained','complete_fence_proven','recovery_execution_allowed',
                    'start_allowed','settlement_allowed','production_acceptance'):
            self.assertIs(result['observation'][key],False)
        with self.assertRaises(durable.Rejected):
            self.observe()

    def test_foreign_request_epoch_nonce_or_extra_response_field_is_not_accepted(self):
        for field in ('request_sha256','binding_sha256','epoch_sha256','nonce','extra'):
            with self.subTest(field=field):
                self.setUp()
                def bad(deadline):
                    result = protocol.response(self.sent[0])
                    result[field]='d'*64
                    return result
                self.session.receive.side_effect = bad
                self.refused()
                self.assertEqual(len(self.sent),1)

    def test_true_integer_or_missing_denies_never_become_effect_authority(self):
        for field in ('start_allowed','complete_fence_proven','pending_drained','production_acceptance'):
            for value in (True,0,None):
                with self.subTest(field=field,value=value):
                    self.setUp()
                    def bad(deadline):
                        result=protocol.response(self.sent[0])
                        result['observation'][field]=value
                        return result
                    self.session.receive.side_effect=bad
                    self.refused()
                    self.assertEqual(len(self.sent),1)

    def test_identity_lost_after_reply_suppresses_ack(self):
        self.broker.observe.side_effect=[None,durable.Rejected('restricted-detail')]
        self.refused()
        self.assertEqual(len(self.sent),1)

    def test_no_send_follows_initial_identity_refusal(self):
        self.broker.observe.side_effect=durable.Rejected('restricted-detail')
        self.refused()
        self.assertEqual(self.sent,[])

    def test_lost_reply_is_not_retried_on_same_or_another_connection(self):
        self.session.receive.side_effect=OSError('restricted-detail')
        self.refused()
        self.assertEqual(len(self.sent),1)
        self.assertEqual(self.session.receive.call_count,1)

    def test_final_ack_send_must_not_hide_expiry(self):
        def late(value):
            if value['schema']=='host-recovery-broker-ack-v1':
                self.now=1090.
        self.hook=late
        self.refused()
        self.assertEqual(len(self.sent),2)

    def test_original_epoch_boot_or_broker_invocation_cannot_be_replaced(self):
        for epoch in ({**self.epoch,'boot_id':'foreign'},
                      {**self.epoch,'broker_invocation_id':'cccccccc-cccc-cccc-cccc-cccccccccccc'}):
            with self.subTest(epoch=epoch),self.assertRaises(durable.Rejected):
                self.client(epoch=epoch)
        with self.assertRaises(durable.Rejected):
            self.client(deadline=1180.)

    def test_binding_inputs_are_snapshots_not_mutable_borrowed_authority(self):
        self.binding['topology_sha256']='d'*64
        self.epoch['runtime_epoch']='44444444-4444-4444-8444-444444444444'
        self.observe()
        self.assertEqual(self.sent[0]['binding_sha256'],self.engine._binding_sha256)
        self.assertEqual(self.sent[0]['epoch_sha256'],self.engine._epoch_sha256)

    def test_each_exchange_uses_fresh_caller_nonce_not_peer_supplied_identity(self):
        with patch.object(broker_client.secrets,'token_hex',side_effect=['a'*64,'c'*64]) as nonce:
            self.observe()
            first=self.sent[0]['nonce']
            self.sent=[]
            self.engine=self.client()
            self.observe()
            self.assertNotEqual(self.sent[0]['nonce'],first)
            self.assertEqual(nonce.call_args_list[0].args,(32,))

    def test_deadline_expansion_is_consumed_and_refused_before_send(self):
        with self.assertRaises(durable.Rejected):
            self.observe(deadline=1101.)
        self.assertTrue(self.engine.failed)
        self.assertEqual(self.sent,[])
