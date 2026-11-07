"""Real pidfds with owned synthetic cgroup files; no kernel-domain qualification."""
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from host_recovery import runtime_processes as source
from host_recovery.broker_runtime import RuntimeDomain
from host_recovery.durable import Rejected


class RuntimeProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'cgroup.procs').write_bytes(b'')
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.fd)
        self.domain = Mock(spec=RuntimeDomain)
        self.domain.fd, self.domain.device = self.fd, os.fstat(self.fd).st_dev
        self.domain.cgroup = '/runtime.slice'
        self.domain.configuration.return_value = b'synthetic-domain'
        self.check = Mock()

    def capture(self):
        value = source.RuntimeProcessWitness.capture(domain=self.domain, check=self.check)
        self.addCleanup(value.close)
        return value

    def child(self):
        process = subprocess.Popen([sys.executable, '-I', '-c', 'import os; os.read(0,1)'], stdin=subprocess.PIPE)
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5.)
            process.stdin.close()
        self.addCleanup(cleanup)
        with open('/proc/%d/cgroup' % process.pid, 'rb') as stream:
            membership = stream.read()
        self.assertTrue(membership.startswith(b'0::') and membership.endswith(b'\n'))
        self.domain.cgroup = membership[3:-1].decode()
        (self.root/'cgroup.procs').write_text(str(process.pid)+'\n')
        return process

    def test_real_pidfd_live_refuses_then_exit_passes_without_numeric_signal(self):
        process = self.child()
        witness = self.capture()
        self.assertEqual(witness.count, 1)
        self.assertFalse(os.get_inheritable(witness._fds[0][0]))
        with self.assertRaisesRegex(Rejected, 'still-live'):
            witness.require_dead(check=self.check)
        # Deterministic pipe release and wait, not a wall-clock sleep.
        process.stdin.write(b'X'); process.stdin.flush()
        self.assertEqual(process.wait(timeout=5.), 0)
        witness.require_dead(check=self.check)
        owned = witness._fds[0][0]
        witness.close(); witness.close()
        with self.assertRaises(OSError): os.fstat(owned)
        with self.assertRaises(Rejected): witness.require_dead(check=self.check)
        with self.assertRaises(Rejected): _ = witness.count

    def test_recursive_scan_includes_empty_and_populated_descendants(self):
        (self.root/'child').mkdir()
        (self.root/'child/cgroup.procs').write_bytes(b'24\n23\n')
        groups, processes = source._scan(self.domain, self.check)
        self.assertEqual(set(groups), {'/runtime.slice','/runtime.slice/child'})
        self.assertEqual(processes, {23:'/runtime.slice/child',24:'/runtime.slice/child'})
        self.assertGreater(self.check.call_count, 0)

    def test_empty_capture_is_explicit_zero_not_containment_authority(self):
        witness = self.capture()
        self.assertEqual(witness.count, 0)
        witness.require_dead(check=self.check)
        self.assertFalse(hasattr(witness, 'start_allowed'))

    def test_pid_schema_duplicate_overflow_and_threaded_unreadable_refuse(self):
        for raw in (b'0\n',b'1\n',b'23\n23\n',b'01\n',b'-2\n',b'23',b'4294967296\n',b'bad\n',b'\n',b'2\n'*4097):
            with self.subTest(raw=raw[:32]):
                (self.root/'cgroup.procs').write_bytes(raw)
                with self.assertRaises(Rejected): self.capture()
        (self.root/'cgroup.procs').unlink()
        with self.assertRaises(FileNotFoundError): self.capture()

    def test_linked_group_or_proc_file_is_not_followed(self):
        (self.root/'alias').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(Rejected): self.capture()
        (self.root/'alias').unlink()
        (self.root/'cgroup.procs').unlink()
        (self.root/'cgroup.procs').symlink_to('/not-read')
        with self.assertRaises(OSError): self.capture()

    def test_depth_group_entry_and_aggregate_process_bounds_refuse(self):
        for name,limit in (('MAX_GROUPS',1),('MAX_DEPTH',0),('MAX_ENTRIES',1),('MAX_PROCESSES',1)):
            with self.subTest(name=name):
                child = self.root/'child'
                child.mkdir(exist_ok=True)
                (child/'cgroup.procs').write_bytes(b'23\n24\n')
                with patch.object(source,name,limit):
                    with self.assertRaises(Rejected): source._scan(self.domain,self.check)

    def test_duplicate_pid_across_groups_refuses_migration(self):
        (self.root/'cgroup.procs').write_bytes(b'23\n')
        (self.root/'child').mkdir()
        (self.root/'child/cgroup.procs').write_bytes(b'23\n')
        with self.assertRaisesRegex(Rejected, 'migration'): self.capture()

    def test_membership_mismatch_and_exit_during_capture_close_pidfd(self):
        for action in ('membership','exit','rescan','late-exit'):
            with self.subTest(action=action):
                process = self.child()
                opened = []
                original = os.pidfd_open
                def opened_pidfd(pid, flags):
                    fd = original(pid,flags); opened.append(fd)
                    return fd
                original_scan = source._scan
                scans = []
                def scan(domain, check):
                    result = original_scan(domain,check)
                    scans.append(result)
                    if action == 'rescan' and len(scans) == 2:
                        return {}, {}
                    return result
                with patch.object(source.os,'pidfd_open',side_effect=opened_pidfd), patch.object(source,'_scan',side_effect=scan):
                    if action == 'membership':
                        self.domain.cgroup = '/wrong.slice'
                        with self.assertRaisesRegex(Rejected, 'membership'): self.capture()
                    elif action in ('exit','late-exit'):
                        # Model exact liveness-read loss without a scheduling race.
                        with patch.object(source.RuntimeProcessWitness,'_exited',side_effect=
                                          [True] if action == 'exit' else [False,False,True]):
                            with self.assertRaisesRegex(Rejected, 'exited'): self.capture()
                    else:
                        with self.assertRaisesRegex(Rejected, 'inventory-changed'): self.capture()
                self.assertEqual(len(opened), 1)
                with self.assertRaises(OSError): os.fstat(opened[0])
                process.stdin.write(b'X'); process.stdin.flush(); process.wait(timeout=5.)

    def test_failed_membership_read_and_pidfd_stat_close_owned_descriptor(self):
        for action in ('read','stat'):
            with self.subTest(action=action):
                self.child()
                opened = []
                original_open, original_stat = os.pidfd_open, os.fstat
                def opened_pidfd(pid,flags):
                    fd = original_open(pid,flags); opened.append(fd)
                    return fd
                def fstat(fd):
                    if action == 'stat' and fd in opened:
                        raise OSError(errno.EIO, 'synthetic')
                    return original_stat(fd)
                with patch.object(source.os,'pidfd_open',side_effect=opened_pidfd), patch.object(source.os,'fstat',side_effect=fstat):
                    if action == 'read':
                        with patch('builtins.open',side_effect=OSError(errno.EIO,'synthetic')):
                            with self.assertRaises(OSError): self.capture()
                    else:
                        with self.assertRaises(OSError): self.capture()
                self.assertEqual(len(opened),1)
                with self.assertRaises(OSError): original_stat(opened[0])

    def test_changed_domain_and_revoked_check_refuse_death_observation(self):
        witness = self.capture()
        self.domain.configuration.return_value = b'different'
        with self.assertRaises(Rejected): witness.require_dead(check=self.check)
        self.domain.configuration.return_value = b'synthetic-domain'
        self.check.side_effect = Rejected('lost-authority')
        with self.assertRaisesRegex(Rejected,'lost-authority'): witness.require_dead(check=self.check)

    def test_unknown_poll_event_and_closed_pidfd_refuse_not_fake_death(self):
        self.child()
        witness = self.capture()
        with patch.object(source.select,'poll') as poll:
            poll.return_value.poll.return_value = [(witness._fds[0][0],source.select.POLLNVAL)]
            with self.assertRaisesRegex(Rejected,'pidfd-unconfirmed'): witness.require_dead(check=self.check)
        fd,identity = witness._fds[0]
        os.close(fd)
        witness._fds.clear()
        with self.assertRaises(OSError): source.RuntimeProcessWitness._exited(fd,identity)

    def test_absent_pidfd_support_never_uses_pid_fallback(self):
        with patch.object(source.os,'pidfd_open',side_effect=OSError(errno.ENOSYS,'synthetic')):
            self.child()
            with self.assertRaises(OSError): self.capture()

    def test_deadline_loss_during_scan_refuses_before_pidfd_acquisition(self):
        self.child()
        self.check.side_effect = Rejected('deadline')
        with patch.object(source.os,'pidfd_open') as opened:
            with self.assertRaisesRegex(Rejected,'deadline'): self.capture()
            opened.assert_not_called()
