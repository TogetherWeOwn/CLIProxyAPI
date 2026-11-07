"""SCRIPTED root credentials/manager, not a privileged installed-service proof."""
from dataclasses import replace
import errno
import os
import socket
import struct
import unittest
from unittest.mock import Mock

from host_recovery import broker_identity as identity, durable, manager, worker
from test_bootstrap import BOOT
from test_manager import encoded, observed


class BrokerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.now, self.boot = 1050., BOOT
        self.session = Mock(spec=identity.BrokerPeerSession)
        self.session.peer = {'pid':123, 'uid':0, 'gid':0}
        self.session.alive.return_value = True
        self.session._now.side_effect = lambda: self.now
        self.row = observed('fixed-broker.service', 'b'*32, '/broker.slice/fixed-broker.service')
        self.row.update(User='0', Group='0')
        self.group, self.fragment, self.hook = self.row['ControlGroup'], 'f'*64, lambda: None
        self.commands = Mock()
        def run(*args, **kwargs):
            raw = encoded(self.row)
            self.hook()
            return raw
        self.commands.run.side_effect = run
        self.binding = identity.BrokerBinding(self.row['Id'], self.row['FragmentPath'], 'f'*64,
            durable.digest(durable.canonical(manager.static_properties(self.row))), self.row['InvocationID'], BOOT)
        self.engine = identity.BrokerPeerIdentity(session=self.session, binding=self.binding,
            systemctl='/accepted/systemctl', commands=self.commands, deadline=1100., boot_id=lambda: self.boot,
            read_fragment_hash=lambda _:self.fragment, read_process_cgroup=lambda _:self.group)

    def observe(self, deadline=1090.):
        return self.engine.observe(deadline=deadline)

    def refused(self):
        with self.assertRaisesRegex(durable.Rejected, '^broker-identity-unconfirmed$'):
            self.observe()
        self.assertTrue(self.engine.failed)

    def test_two_fresh_manager_reads_are_not_a_start_or_runtime_receipt(self):
        self.assertIsNone(self.observe())
        self.assertEqual(self.commands.run.call_count, 2)
        for call in self.commands.run.call_args_list:
            self.assertEqual(call.args[0], ('/accepted/systemctl', '--no-pager', 'show',
                '--property='+','.join(sorted(manager.PROPERTIES)), '--', self.binding.unit))
            self.assertEqual(call.kwargs, {'deadline':1090.})

    def test_root_uid_without_pinned_mainpid_invocation_and_fragment_refuses(self):
        for key, value in (('MainPID','124'), ('InvocationID','c'*32), ('DropInPaths','/other.conf'),
                           ('User','root'), ('Group','root'), ('Job','12'), ('Restart','always')):
            with self.subTest(key=key):
                self.setUp()
                self.row[key] = value
                self.refused()

    def test_expired_or_expanded_deadline_and_boot_drift_are_sticky(self):
        self.observe(deadline=1075.)
        self.refused()
        self.setUp()
        self.boot = 'other-boot'
        self.refused()
        self.boot = BOOT
        self.refused()

    def test_peer_loss_during_final_manager_read_refuses(self):
        def close():
            if self.commands.run.call_count == 2:
                self.session.alive.return_value = False
        self.hook = close
        self.refused()
        self.assertEqual(self.commands.run.call_count, 2)

    def test_fragment_cgroup_and_command_changes_refuse(self):
        self.fragment = 'e'*64
        self.refused()
        self.setUp()
        self.group = '/other'
        self.refused()
        self.setUp()
        self.row['ExecStart'] = self.row['ExecStart'].replace('/accepted/helper','/other/helper')
        self.refused()

    def test_final_identity_reads_cannot_hide_expiry(self):
        calls = []
        def late_group(_):
            calls.append(True)
            if len(calls) == 3:
                self.now = 1090.
            return self.group
        self.engine.read_process_cgroup = late_group
        self.refused()
        self.assertEqual(len(calls), 3)

    def test_final_cgroup_observation_must_match_both_manager_rows(self):
        calls = []
        def changed(_):
            calls.append(True)
            return '/changed' if len(calls) == 3 else self.group
        self.engine.read_process_cgroup = changed
        self.refused()
        self.assertEqual(len(calls), 3)

    def test_manager_or_fragment_failures_are_sanitized(self):
        for code in (errno.EIO, errno.ENOSPC):
            with self.subTest(code=code):
                self.setUp()
                self.commands.run.side_effect = OSError(code, 'restricted-detail')
                self.refused()

    def test_binding_rejects_unpinned_or_template_identity(self):
        for change in ({'unit':'broker@.service'}, {'invocation_id':'untrusted'}, {'boot_id':'old'},
                       {'fragment_sha256':'bad'}, {'fragment_path':'/accepted/../other'}):
            with self.subTest(change=change), self.assertRaises(durable.Rejected):
                replace(self.binding, **change)


class BrokerKernelSessionTests(unittest.TestCase):
    def sock(self, credentials=(123,0,0), kind=socket.SOCK_SEQPACKET):
        fd, write = os.pipe()
        self.addCleanup(os.close, write)
        # The constructor owns fd only after obtaining SO_PEERPIDFD.
        expected = os.fstat(fd)
        def cleanup():
            try:
                actual = os.fstat(fd)
                if (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino):
                    os.close(fd)
            except OSError:
                pass
        self.addCleanup(cleanup)
        sock = Mock()
        sock.family = socket.AF_UNIX
        def get(level, option, *args):
            if option == socket.SO_TYPE: return kind
            if option == socket.SO_PEERCRED: return struct.pack('3i', *credentials)
            if option == 77: return struct.pack('i', fd)
            raise AssertionError(option)
        sock.getsockopt.side_effect = get
        return sock, fd

    def open_fd(self, fd):
        try:
            os.fstat(fd)
            return True
        except OSError:
            return False

    def test_only_broker_session_can_pin_explicit_root_peer(self):
        sock, fd = self.sock()
        session = identity.BrokerPeerSession(sock, pid=123)
        self.assertEqual(session.peer, {'pid':123,'uid':0,'gid':0})
        self.assertFalse(os.get_inheritable(fd))
        session.close()
        self.assertFalse(self.open_fd(fd))
        with self.assertRaises(durable.Rejected):
            worker.PeerSession(sock, uid=0, pid=123)

    def test_wrong_root_gid_uid_pid_or_socket_kind_never_falls_back(self):
        for creds, kind in (((123,0,1),socket.SOCK_SEQPACKET), ((123,1,0),socket.SOCK_SEQPACKET),
                            ((124,0,0),socket.SOCK_SEQPACKET), ((123,0,0),socket.SOCK_STREAM)):
            with self.subTest(creds=creds,kind=kind):
                sock, fd = self.sock(creds,kind)
                with self.assertRaises(durable.Rejected):
                    identity.BrokerPeerSession(sock, pid=123)
                self.assertFalse(any(call.args[1] == 77 for call in sock.getsockopt.call_args_list))

    def test_constructor_failure_closes_new_pidfd(self):
        sock, fd = self.sock()
        sock.setsockopt.side_effect = OSError(errno.EIO,'restricted-detail')
        with self.assertRaises(OSError):
            identity.BrokerPeerSession(sock, pid=123)
        self.assertFalse(self.open_fd(fd))

    def test_unsupported_kernel_pidfd_never_uses_numeric_pid_fallback(self):
        sock, fd = self.sock()
        actual = sock.getsockopt.side_effect
        def unsupported(level, option, *args):
            if option == 77: raise OSError(errno.ENOPROTOOPT,'unsupported')
            return actual(level,option,*args)
        sock.getsockopt.side_effect = unsupported
        with self.assertRaises(OSError):
            identity.BrokerPeerSession(sock, pid=123)
        self.assertTrue(self.open_fd(fd))
