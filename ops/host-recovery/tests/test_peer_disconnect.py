"""Real seqpacket disconnects; SCRIPTED manager/authority, not a service drill."""
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import unittest

from host_recovery import durable, worker
import test_worker_recovery

ROOT = Path(__file__).resolve().parent.parent
SERVER = r'''
import json,os,socket,sys
sys.path.insert(0,sys.argv[1])
from host_recovery.durable import canonical
claim=json.loads(sys.argv[3])
with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as server:
 server.bind(sys.argv[2]);os.chmod(sys.argv[2],0o600);server.listen(1)
 print('READY',flush=True)
 conn,_=server.accept()
 request=json.loads(conn.recv(4096))
 claim['nonce']=request['nonce']
 conn.send(canonical(claim))
 sys.stdin.readline()
 conn.close()
 print('CLOSED_PROCESS_STILL_ALIVE',flush=True)
 sys.stdin.readline()
'''


class PeerDisconnectTests(unittest.TestCase):
    def pair(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        session = worker.PeerSession(left, uid=os.geteuid())
        self.addCleanup(session.close)
        self.assertTrue(session.alive())
        return session, right

    def test_closed_socket_is_not_live_merely_because_peer_process_survives(self):
        session, right = self.pair()
        right.close()
        self.assertFalse(session.alive())
        self.assertFalse(session.alive())

    def test_peer_write_half_shutdown_revokes_session(self):
        session, right = self.pair()
        right.shutdown(socket.SHUT_WR)
        self.assertFalse(session.alive())

    def test_queued_packet_does_not_conceal_peer_hangup(self):
        session, right = self.pair()
        right.send(b'buffered')
        right.close()
        self.assertFalse(session.alive())

    def test_live_queued_packet_is_not_consumed_by_liveness_check(self):
        session, right = self.pair()
        right.send(b'buffered')
        self.assertTrue(session.alive())
        self.assertEqual(session.sock.recv(4096), b'buffered')
        self.assertTrue(session.alive())

    def test_buffered_non_authorizing_terminal_receipt_does_not_revive_execution(self):
        session, right = self.pair()
        receipt = {"schema": "synthetic-terminal-receipt", "start_permission": False}
        right.send(durable.canonical(receipt))
        right.close()
        self.assertFalse(session.alive())
        self.assertTrue(session.process_alive())
        self.assertEqual(session.receive(deadline=session.clock() + 1), receipt)
        self.assertFalse(session.alive())

    def test_locally_closed_socket_refuses_without_throwing(self):
        session, right = self.pair()
        session.sock.close()
        self.assertFalse(session.alive())

    def test_live_supervisor_process_closing_claim_connection_blocks_recovery_before_authority(self):
        fixture = test_worker_recovery.WorkerRecoveryTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        path = fixture.root / 'peer.sock'
        child = subprocess.Popen([sys.executable, '-I', '-c', SERVER, str(ROOT), str(path), json.dumps(fixture.claim)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()
        self.addCleanup(cleanup)
        def line():
            with selectors.DefaultSelector() as wait:
                wait.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(wait.select(5), 'synthetic supervisor did not report')
            return child.stdout.readline()
        self.assertEqual(line(), b'READY\n')
        client = worker.WorkerClient(str(path), supervisor_uid=os.geteuid(), supervisor_pid=child.pid,
            supervisor_owner=fixture.request['owner'], request_id=fixture.binding.request_id,
            intent_sha256=fixture.approval.intent_sha256, clock=lambda: fixture.case.time,
            verify_identity=lambda **kw: fixture.claim['worker'].copy())
        reached = []
        def execute(claim, *, deadline, check):
            child.stdin.write(b'close\n');child.stdin.flush()
            self.assertEqual(line(), b'CLOSED_PROCESS_STILL_ALIVE\n')
            self.assertIsNone(child.poll())
            reached.append(True)
            fixture.case.claim = claim
            return fixture.engine(claim, deadline=deadline, check=check)
        with self.assertRaises((durable.Rejected, OSError)):
            client.claim(deadline=1100., recovery_provider=execute)
        self.assertEqual(reached, [True])
        self.assertEqual(fixture.boundary.calls, [])
        self.assertEqual(fixture.case.file.read_bytes(), b'partial-candidate')
        self.assertIsNone(client.result_receipt)
        self.assertTrue(fixture.notices)
        self.assertEqual(sorted(p.name for p in fixture.root.iterdir()), ['peer.sock'])
        self.assertIsNone(child.poll(), 'socket closure must be tested independently of process death')
