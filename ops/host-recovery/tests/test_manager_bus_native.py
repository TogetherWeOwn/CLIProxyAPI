"""Actions-only real libsystemd/private-bus tests against a synthetic manager.

Credential expectations and the socket address are patched ONLY in these tests.
They verify native ABI/signal ordering, not systemd/PID1, activation, cgroup or
privileged provisioning. No shared-host/system bus connection is possible here.
"""
import hashlib
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))
from host_recovery import durable, manager_bus as bus
from host_recovery.protected_file import ProtectedFile
from test_manager_bus import units

ENABLED = os.environ.get('CPA_RECOVERY_PRIVATE_BUS_TEST')=='1' and os.environ.get('GITHUB_ACTIONS')=='true'


@unittest.skipUnless(ENABLED,'private-bus matrix runs in its separate disposable Actions step')
class NativeManagerBusTests(unittest.TestCase):
    def line(self, peer):
        ready,_,_ = select.select([peer.stdout],[],[],5.)
        if not ready:
            raise AssertionError('private manager peer did not reply')
        value = peer.stdout.readline().strip()
        if not value:
            raise AssertionError('private manager peer exited: '+peer.stderr.read())
        return value

    def peer(self, mode):
        address = os.environ['DBUS_SESSION_BUS_ADDRESS']
        self.assertTrue(address.startswith('unix:'))
        self.assertNotEqual(address,bus.SYSTEM_ADDRESS.decode())
        path = next((p for p in (Path('/usr/lib/x86_64-linux-gnu/libsystemd.so.0'),
                                 Path('/lib/x86_64-linux-gnu/libsystemd.so.0')) if p.exists()),None)
        self.assertIsNotNone(path,'libsystemd runtime must be present on disposable Actions runner')
        peer = subprocess.Popen([sys.executable,'-I',str(ROOT/'tests/manager_bus_peer.py'),str(path),mode],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
            env={'DBUS_SESSION_BUS_ADDRESS':address,'PATH':os.defpath})
        def cleanup():
            if peer.poll() is None:
                peer.stdin.write('quit\n'); peer.stdin.flush()
                try: peer.wait(timeout=5.)
                except subprocess.TimeoutExpired: peer.kill(); peer.wait(timeout=5.)
            for stream in (peer.stdin,peer.stdout,peer.stderr): stream.close()
        self.addCleanup(cleanup)
        self.assertEqual(self.line(peer),'ready')
        return peer,path,address

    def session(self,mode='done',*,root_credentials=False):
        peer,path,address = self.peer(mode)
        library = Mock(spec=ProtectedFile)
        library.uid = library.gid = 0
        library.fd = os.open(path,os.O_RDONLY|os.O_CLOEXEC)
        self.addCleanup(os.close,library.fd)
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        library.checksum.return_value = checksum
        # Test-only supplied handle; this does not qualify root provisioning.
        address_patch = patch.object(bus,'SYSTEM_ADDRESS',address.encode())
        address_patch.start(); self.addCleanup(address_patch.stop)
        if not root_credentials:
            def credentials(session):
                uid = session._bus_call('GetConnectionUnixUser','s',(session.owner,),'u')[0]
                pid = session._bus_call('GetConnectionUnixProcessID','s',(session.owner,),'u')[0]
                if (uid,pid)!=(os.geteuid(),peer.pid):
                    raise durable.Rejected('wrong-private-manager-credentials')
            credential_patch = patch.object(bus.ManagerJobSession,'_credentials',credentials)
            credential_patch.start(); self.addCleanup(credential_patch.stop)
        session = bus.ManagerJobSession(library=library,library_sha256=checksum,units=units(),
            deadline=time.monotonic()+5.,clock=time.monotonic,check=lambda:None)
        self.addCleanup(session.close)
        return session,peer

    def count(self,peer):
        peer.stdin.write('counts\n');peer.stdin.flush()
        return int(self.line(peer))

    def test_real_signal_before_stop_reply_is_bound_and_not_lost(self):
        session,peer = self.session()
        self.assertEqual(session.stop('dockerd'),bus.JOB_PREFIX+'41')
        self.assertEqual(session.jobs(),{})
        event = session.completions()['dockerd']
        self.assertEqual((event['job_id'],event['result']),(41,'done'))
        self.assertGreater(event['sender_cookie'],0)
        session.stop('containerd')
        self.assertEqual(set(session.completions()),{'dockerd','containerd'})
        self.assertEqual(self.count(peer),2)

    def test_real_absent_inventory_without_signal_is_not_completion(self):
        session,peer = self.session('absent')
        session.stop('dockerd')
        self.assertEqual(session.jobs(),{})
        self.assertEqual(session.completions(),{})
        self.assertEqual(self.count(peer),1)

    def test_real_nonempty_typed_inventory_is_pending_not_completion(self):
        session,peer = self.session('pending')
        session.stop('dockerd')
        rows = session.jobs()
        self.assertEqual(rows[41][0:4],(41,'fixture-dockerd.service','stop','running'))
        self.assertEqual(session.completions(),{})
        self.assertEqual(self.count(peer),1)

    def test_real_failed_and_canceled_events_are_preserved(self):
        # Each session/peer owns a distinct name lifetime on the private bus.
        for result in ('failed','canceled'):
            with self.subTest(result=result):
                session,peer = self.session(result)
                session.stop('dockerd')
                self.assertEqual(session.completions()['dockerd']['result'],result)
                session.close()
                peer.stdin.write('quit\n');peer.stdin.flush();peer.wait(timeout=5.)

    def test_real_duplicate_completion_revokes_without_retry(self):
        session,peer = self.session('duplicate')
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertEqual(self.count(peer),1)
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertEqual(self.count(peer),1)

    def test_real_malformed_signature_revokes_without_fallback(self):
        session,peer = self.session('malformed')
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertEqual(self.count(peer),1)
        self.assertTrue(session.failed)

    def test_real_wrong_return_id_cannot_adopt_early_signal(self):
        session,peer = self.session('wrong-id')
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertEqual(self.count(peer),1)
        self.assertTrue(session.failed)

    def test_real_manager_name_loss_revokes_before_stop(self):
        session,peer = self.session()
        peer.stdin.write('release\n');peer.stdin.flush()
        self.assertEqual(self.line(peer),'released')
        with self.assertRaises(durable.Rejected): session.stop('dockerd')
        self.assertEqual(self.count(peer),0)

    def test_production_root_pid1_guard_rejects_private_peer(self):
        with self.assertRaises(durable.Rejected): self.session(root_credentials=True)


if __name__=='__main__':
    if not ENABLED:
        raise SystemExit('private-bus test requires explicit disposable Actions context')
    unittest.main(verbosity=2)
