"""Synthetic owned directory locks and real Linux peers; no manager/daemon drill."""
from dataclasses import replace
import fcntl
import os
from pathlib import Path
import pwd
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from host_recovery import durable, installation, lock_observation, worker

CHILD = r'''
import fcntl,os,socket,sys
fd = int(sys.argv[4]) if sys.argv[3] == 'inherited' else os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY)
if sys.argv[3] in ('exclusive', 'shared'):
 fcntl.flock(fd, fcntl.LOCK_EX if sys.argv[3] == 'exclusive' else fcntl.LOCK_SH)
conn=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
conn.connect(sys.argv[1])
print(fd,flush=True)
for command in sys.stdin:
 if command.strip() == 'unlock': fcntl.flock(fd,fcntl.LOCK_UN)
 elif command.strip() == 'relock': fcntl.flock(fd,fcntl.LOCK_EX)
 elif command.strip() == 'close': conn.close()
 print('ACK',flush=True)
'''


def info(pid=123, device=None, inode=456):
    device = os.makedev(0, 42) if device is None else device
    return (f'pos:\t0\nflags:\t02300000\nmnt_id:\t22\nino:\t{inode}\n'
            f'lock:\t1: FLOCK  ADVISORY  WRITE {pid} {os.major(device):02x}:{os.minor(device):02x}:{inode} 0 EOF\n').encode()


class FlockParserTests(unittest.TestCase):
    def check(self, raw):
        lock_observation.exclusive_flock(raw, pid=123, device=os.makedev(0, 42), inode=456)

    def test_exact_whole_directory_exclusive_flock(self):
        self.check(info())

    def test_alternate_lock_types_and_owner_or_inode_never_substitute(self):
        for old, new in ((b'FLOCK ', b'POSIX '), (b'FLOCK ', b'OFDLCK'), (b'WRITE', b'READ '),
                         (b'123 ', b'-1 '), (b'123 ', b'124 '), (b'00:2a:456', b'00:2b:456'),
                         (b'00:2a:456', b'01:2a:456'), (b'00:2a:456', b'00:2a:457'),
                         (b' 0 EOF', b' 1 EOF'), (b' 0 EOF', b' 0 100'),
                         (b'1: FLOCK', b'1: -> FLOCK')):
            with self.subTest(new=new), self.assertRaises(durable.Rejected):
                self.check(info().replace(old, new))

    def test_duplicate_missing_malformed_and_oversized_rows_refuse(self):
        row = info().splitlines()[-1] + b'\n'
        for raw in (b'', b'pos:\t0\n', info() + row, info() + b'lock: malformed\n',
                    info().replace(b'ino:\t456', b'ino:\t457'), info() + b'ino:\t456\n',
                    info() + b'x' * lock_observation.MAX_FDINFO, info().decode()):
            with self.subTest(raw_type=type(raw)), self.assertRaises(durable.Rejected):
                self.check(raw)


class OriginalLockObservationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='.recovery-lock-test-', dir=pwd.getpwuid(os.geteuid()).pw_dir)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.journal = self.root / 'journal'
        self.journal.mkdir(mode=0o700)
        st = self.journal.stat()
        self.approval = installation.DirectoryApproval(str(self.journal), st.st_dev, st.st_ino,
                                                       st.st_uid, st.st_gid, 0o700)
        self.now = time.monotonic()

    def line(self, child):
        with selectors.DefaultSelector() as wait:
            wait.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(wait.select(5), 'synthetic lock owner did not report')
        return child.stdout.readline().strip()

    def connect(self, mode='exclusive', path=None, inherited=None):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(listener.close)
        endpoint = self.root / ('peer-' + str(len(list(self.root.iterdir()))) + '.sock')
        listener.bind(str(endpoint))
        listener.listen(1)
        child = subprocess.Popen([sys.executable, '-I', '-c', CHILD, str(endpoint),
                                  str(path or self.journal), mode, str(inherited or 0)],
                                 pass_fds=() if inherited is None else (inherited,),
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()
        self.addCleanup(cleanup)
        fd = int(self.line(child))
        with selectors.DefaultSelector() as wait:
            wait.register(listener, selectors.EVENT_READ)
            self.assertTrue(wait.select(5), 'synthetic peer did not connect')
        conn, _ = listener.accept()
        self.addCleanup(conn.close)
        session = worker.PeerSession(conn, uid=os.geteuid(), pid=child.pid)
        self.addCleanup(session.close)
        observation = lock_observation.OriginalLockObservation(peer=session, journal=self.approval,
            descriptor=fd, deadline=self.now + 60, clock=lambda: self.now)
        return observation, child, session

    def command(self, child, value):
        child.stdin.write(value.encode() + b'\n')
        child.stdin.flush()
        self.assertEqual(self.line(child), b'ACK')

    def observe(self, observation):
        return observation.observe(deadline=self.now + 10)

    def test_real_foreign_flock_observed_without_acquiring_a_second_lock(self):
        observation, child, session = self.connect()
        before = sorted(p.name for p in self.journal.iterdir())
        value = self.observe(observation)
        self.assertTrue(value['exclusive_flock_observed'])
        self.assertFalse(value['start_allowed'])
        self.assertFalse(value['complete_fence_proven'])
        self.assertFalse(value['production_acceptance'])
        with durable.directory(str(self.journal)) as fd:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(sorted(p.name for p in self.journal.iterdir()), before)
        self.assertTrue(session.alive())
        self.assertIsNone(child.poll())

    def test_absent_shared_or_wrong_directory_lock_refuses(self):
        other = self.root / 'other'
        other.mkdir(mode=0o700)
        for mode, path in (('none', None), ('shared', None), ('exclusive', other)):
            with self.subTest(mode=mode):
                observation, child, session = self.connect(mode, path)
                with self.assertRaises(durable.Rejected):
                    self.observe(observation)
                self.assertTrue(observation.failed)

    def test_inherited_description_is_not_original_peer_lock_ownership(self):
        with durable.directory(str(self.journal)) as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            observation, child, session = self.connect('inherited', inherited=fd)
            with self.assertRaises(durable.Rejected):
                self.observe(observation)

    def test_unlock_then_relock_does_not_revive_a_revoked_observer(self):
        observation, child, session = self.connect()
        self.observe(observation)
        self.command(child, 'unlock')
        with self.assertRaises(durable.Rejected):
            self.observe(observation)
        self.command(child, 'relock')
        with self.assertRaises(durable.Rejected):
            self.observe(observation)

    def test_socket_closure_and_process_death_revoke(self):
        observation, child, session = self.connect()
        self.observe(observation)
        self.command(child, 'close')
        self.assertIsNone(child.poll())
        with self.assertRaises(durable.Rejected):
            self.observe(observation)
        other, process, _ = self.connect('none')
        process.send_signal(signal.SIGKILL)
        process.wait(timeout=5)
        with self.assertRaises(durable.Rejected):
            self.observe(other)

    def test_unpinned_path_replacement_refuses_even_with_original_inode_locked(self):
        observation, child, session = self.connect()
        self.journal.rename(self.root / 'old')
        self.journal.mkdir(mode=0o700)
        with self.assertRaises(durable.Rejected):
            self.observe(observation)

    def test_deadline_cannot_expand_or_reset_after_regression(self):
        observation, child, session = self.connect()
        with self.assertRaises(durable.Rejected):
            observation.observe(deadline=self.now + 61)
        other, _, _ = self.connect('none')
        self.now -= 1
        with self.assertRaises(durable.Rejected):
            self.observe(other)

    def test_fdinfo_error_revokes_without_lock_attempt_or_fallback(self):
        observation, child, session = self.connect()
        with patch.object(lock_observation, '_fdinfo', side_effect=PermissionError):
            with self.assertRaises(durable.Rejected):
                self.observe(observation)
        with self.assertRaises(durable.Rejected):
            self.observe(observation)

    def test_unlock_during_observation_is_caught_by_trailing_kernel_read(self):
        observation, child, session = self.connect()
        actual = lock_observation._fdinfo
        reached = []
        def unlock(proc, fd):
            raw = actual(proc, fd)
            if not reached:
                reached.append(True)
                self.command(child, 'unlock')
            return raw
        with patch.object(lock_observation, '_fdinfo', side_effect=unlock):
            with self.assertRaises(durable.Rejected):
                self.observe(observation)
        self.assertEqual(reached, [True])

    def test_noninteger_descriptor_and_wrong_journal_owner_refuse(self):
        observation, child, session = self.connect()
        for descriptor in (True, -1, 1048576, '4'):
            with self.subTest(descriptor=descriptor), self.assertRaises(durable.Rejected):
                lock_observation.OriginalLockObservation(peer=session, journal=self.approval,
                    descriptor=descriptor, deadline=self.now + 10)
        with self.assertRaises(durable.Rejected):
            lock_observation.OriginalLockObservation(peer=session, journal=replace(self.approval, uid=os.geteuid() + 1),
                descriptor=observation.descriptor, deadline=self.now + 10)
