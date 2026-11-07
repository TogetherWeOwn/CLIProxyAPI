"""Real lock-owning socket peer; SCRIPTED manager, no root broker/runtime drill."""
import json
import socket
import unittest
from unittest.mock import patch

from host_recovery import durable, privileged_broker as protocol
import test_broker_authority as fixture
import test_lock_observation as lock_fixture


CHILD = r'''
import fcntl,json,os,socket,sys
fd=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY)
fcntl.flock(fd,fcntl.LOCK_EX)
conn=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
conn.connect(sys.argv[1])
print(fd,flush=True)
for command in sys.stdin:
 if command.startswith('exchange '):
  value=json.loads(command[len('exchange '):])
  conn.send(json.dumps(value['request'],separators=(',',':')).encode())
  print('SENT',flush=True)
  raw=conn.recv(4096)
  if 'ack' in value: conn.send(json.dumps(value['ack'],separators=(',',':')).encode())
  print(raw.decode(),flush=True)
  continue
 if command.strip() == 'unlock': fcntl.flock(fd,fcntl.LOCK_UN)
 elif command.strip() == 'close': conn.close()
 print('ACK',flush=True)
'''


class BrokerProtocolTests(unittest.TestCase):
    line = fixture.BrokerAuthorityTests.line
    connect = fixture.BrokerAuthorityTests.connect
    command = fixture.BrokerAuthorityTests.command
    write = fixture.BrokerAuthorityTests.write
    run_command = fixture.BrokerAuthorityTests.run_command
    make_engine = fixture.BrokerAuthorityTests.make_engine

    def setUp(self):
        with patch.object(lock_fixture, 'CHILD', CHILD):
            fixture.BrokerAuthorityTests.setUp(self)
        self.peer.clock = lambda: self.now
        self.epoch = {'boot_id': self.boot, 'broker_invocation_id': '22222222-2222-4222-8222-222222222222',
                      'runtime_epoch': '33333333-3333-4333-8333-333333333333'}
        self.server = protocol.ObservationServer(authority=self.engine, epoch=self.epoch)
        self.value = protocol.request(binding_sha256=durable.digest(durable.canonical(self.binding)),
            epoch_sha256=durable.digest(durable.canonical(self.epoch)), nonce='a'*64, deadline=1090.)

    def queue(self, value=None, ack=None):
        value = self.value if value is None else value
        packet = {'request': value, 'ack': protocol.acknowledgment(value) if ack is None else ack}
        self.child.stdin.write(('exchange ' + json.dumps(packet) + '\n').encode())
        self.child.stdin.flush()
        self.assertEqual(self.line(self.child), b'SENT')

    def refused(self):
        with self.assertRaisesRegex(durable.Rejected, '^broker-protocol-observation-unconfirmed$'):
            self.server.serve_once(deadline=1100.)
        self.assertTrue(self.server.failed)
        self.assertTrue(self.engine.failed)

    def test_real_seqpacket_original_lock_and_manager_exchange_has_only_denies(self):
        before = {p.name:p.read_bytes() for p in self.journal.iterdir()}
        self.queue()
        value = self.server.serve_once(deadline=1100.)
        self.assertEqual(value, protocol.response(self.value))
        self.assertEqual(json.loads(self.line(self.child)), value)
        self.assertEqual(before, {p.name:p.read_bytes() for p in self.journal.iterdir()})
        self.assertEqual(len(self.calls), 12)
        for key in ('pending_drained', 'complete_fence_proven', 'recovery_execution_allowed',
                    'start_allowed', 'settlement_allowed', 'production_acceptance'):
            self.assertIs(value['observation'][key], False)
        with self.assertRaisesRegex(durable.Rejected, '^broker-protocol-exhausted$'):
            self.server.serve_once(deadline=1100.)

    def test_all_effect_methods_are_denied_without_pending_publication(self):
        # Use a fresh fixture for each consumed connection, not a reset server.
        for method in ('contain_forward', 'cold_quiesce_runtime', 'dispatch_recovery',
                       'restore_approved_baseline', 'verify_stopped_baseline', 'start_verified_old',
                       'create_approved_candidate', 'start_registered_candidate', 'exec'):
            with self.subTest(method=method):
                self.setUp()
                before = sorted(p.name for p in self.journal.iterdir())
                self.queue({**self.value, 'method': method})
                self.refused()
                self.assertEqual(before, sorted(p.name for p in self.journal.iterdir()))
                self.assertEqual(len(self.calls), 4)

    def test_wrong_binding_epoch_or_unknown_field_is_not_echoed_as_authority(self):
        for change in ({'binding_sha256': 'd'*64}, {'epoch_sha256': 'e'*64}, {'argv':['/bin/true']},
                       {'lock_descriptor': 0}, {'schema': 'old'}, {'nonce': 'unbounded'*1000}):
            with self.subTest(change=tuple(change)):
                self.setUp()
                self.queue({**self.value, **change})
                self.refused()

    def test_deadline_cannot_expand_from_original_request_or_exchange(self):
        self.queue({**self.value, 'deadline': 1101.})
        self.refused()
        self.assertEqual(len(self.calls), 4)

    def test_boolean_deadline_is_not_numeric_allowance(self):
        self.queue({**self.value, 'deadline': True})
        self.refused()

    def test_wrong_ack_refuses_after_reply_without_settlement(self):
        self.queue(ack={'schema':'host-recovery-broker-ack-v1', 'request_sha256':'f'*64})
        self.refused()
        self.assertEqual(json.loads(self.line(self.child)), protocol.response(self.value))
        self.assertEqual(len(self.calls), 8)

    def test_original_input_drift_after_request_never_returns_observation(self):
        self.queue()
        def change():
            if len(self.calls) == 5:
                self.write('reconcile-request.json', b'{}')
        self.hook = change
        self.refused()
        self.assertGreaterEqual(len(self.calls), 5)

    def test_expiry_after_reply_is_unresolved_even_if_client_saw_prefix(self):
        self.queue()
        actual = self.peer.reply
        def late(value, deadline):
            actual(value, deadline)
            self.now = deadline
        with patch.object(self.peer, 'reply', side_effect=late):
            self.refused()
        self.assertEqual(json.loads(self.line(self.child)), protocol.response(self.value))

    def test_message_credentials_are_required_not_just_socket_credentials(self):
        self.peer.sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 0)
        self.queue()
        self.refused()
        self.assertEqual(len(self.calls), 4)

    def test_lost_original_peer_before_read_revokes_without_a_reply(self):
        self.command(self.child, 'close')
        self.refused()
        self.assertFalse(self.peer.alive())

    def test_server_epoch_must_keep_original_boot(self):
        with self.assertRaises(durable.Rejected):
            protocol.ObservationServer(authority=self.make_engine(), epoch={**self.epoch,'boot_id':'other'})
