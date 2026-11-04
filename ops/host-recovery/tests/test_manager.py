"""Scripted systemd/cgroup observations, NOT a disposable manager drill."""
import copy
from dataclasses import replace
import io
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from host_recovery import commands, durable, manager


def observed(unit="forward.service", invocation="a" * 32, cgroup="/recovery/forward.service"):
    return {"Id": unit, "LoadState": "loaded", "FragmentPath": "/accepted/" + unit,
            "DropInPaths": "", "Type": "exec", "KillMode": "control-group", "SendSIGKILL": "yes",
            "Delegate": "no", "ProtectControlGroups": "yes", "NoNewPrivileges": "yes", "Restart": "no",
            "ExecStart": "{ path=/accepted/helper ; argv[]=/accepted/helper ; }", "User": "recovery-worker",
            "Group": "recovery-worker", "Slice": "recovery.slice", "ReadWritePaths": "/accepted/write-set",
            "CapabilityBoundingSet": "", "AmbientCapabilities": "", "RestrictNamespaces": "yes",
            "ProtectSystem": "strict", "RestrictSUIDSGID": "yes",
            "InvocationID": invocation, "ControlGroup": cgroup, "ActiveState": "active", "SubState": "running",
            "Job": "0", "MainPID": "123"}


def binding(value):
    return manager.UnitBinding(value["Id"], value["InvocationID"], value["ControlGroup"], value["FragmentPath"],
                               "f" * 64, durable.digest(durable.canonical({k: value[k] for k in manager.STATIC})))


def encoded(value):
    return ("\n".join(k + "=" + v for k, v in value.items()) + "\n").encode()


class ScriptedCommands:
    def __init__(self, test):
        self.test = test
        self.calls = []
        self.rows = []
        self.failure = None

    def run(self, argv, *, deadline):
        self.test.assertEqual(deadline, 50)
        self.calls.append(argv)
        if self.failure is not None:
            raise self.failure
        if "show" in argv:
            return encoded(self.rows.pop(0))
        return b""


class SyntheticCgroups:
    def __init__(self, test):
        self.test = test
        self.value = False
        self.calls = []

    def populated(self, path):
        self.calls.append(path)
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.before = observed()
        self.stopped = {**self.before, "ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}
        self.forward = binding(self.before)
        self.recovery = binding(observed("restore.service", "b" * 32, "/recovery/restore.service"))
        self.commands = ScriptedCommands(self)
        self.cgroups = SyntheticCgroups(self)
        self.fences = [True, True]
        self.time = 1
        self.engine = manager.SystemdMutators(systemctl="/accepted/systemctl", commands=self.commands,
                                              cgroups=self.cgroups, forward=self.forward, recovery=self.recovery,
                                              start_fence=lambda: self.fences.pop(0), read_fragment_hash=lambda _: "f" * 64,
                                              clock=lambda: self.time)

    def quiesce(self, before=None, after=None, final=None):
        self.commands.rows = [copy.deepcopy(self.before if before is None else before),
                              copy.deepcopy(self.stopped if after is None else after),
                              copy.deepcopy(self.stopped if final is None else final)]
        return self.engine.quiesce_forward(deadline=50)

    def test_full_cgroup_kill_and_three_observations_precede_quiescence(self):
        self.assertTrue(self.quiesce())
        self.assertEqual(self.commands.calls[1], ("/accepted/systemctl", "--no-block", "stop", "--", "forward.service"))
        self.assertEqual(self.commands.calls[2], ("/accepted/systemctl", "kill", "--kill-whom=all", "--signal=SIGKILL",
                                                 "--", "forward.service"))
        self.assertEqual(self.cgroups.calls, [self.forward.cgroup])
        self.assertTrue(all(argv[-1] == "forward.service" for argv in self.commands.calls))
        self.assertFalse(any("start" in argv for argv in self.commands.calls))

    def test_main_pid_exit_with_populated_descendants_is_not_quiescence(self):
        self.cgroups.value = True
        self.assertFalse(self.quiesce())

    def test_no_pid_only_or_coerced_boolean_quiescence(self):
        self.cgroups.value = 0
        self.assertFalse(self.quiesce())

    def test_pending_stop_job_or_live_pid_cannot_pass(self):
        for update in ({"Job": "17"}, {"MainPID": "456"}, {"ActiveState": "deactivating", "SubState": "stop-sigterm"}):
            with self.subTest(update=update):
                self.setUp()
                row = {**self.stopped, **update}
                self.assertFalse(self.quiesce(after=row, final=row))

    def test_missing_group_is_not_implicitly_empty(self):
        self.cgroups.value = None
        self.assertFalse(self.quiesce())

    def test_inactive_unloaded_cgroup_with_cleared_identity_and_fence_can_be_quiescent(self):
        self.cgroups.value = None
        row = {**self.stopped, "ControlGroup": "", "InvocationID": ""}
        self.assertTrue(self.quiesce(before=row, after=row, final=row))
        self.assertEqual(len(self.commands.calls), 3)

    def test_failed_inactive_unit_with_empty_cgroup_can_be_quiescent(self):
        self.cgroups.value = None
        row = {**self.stopped, "ActiveState": "failed", "SubState": "failed", "ControlGroup": ""}
        self.assertTrue(self.quiesce(before=row, after=row, final=row))

    def test_neither_missing_nor_lost_start_fence_can_pass(self):
        self.fences = [False]
        with self.assertRaises(durable.Rejected):
            self.quiesce()
        self.assertEqual(self.commands.calls, [])
        self.fences = [True, False]
        with self.assertRaises(durable.Rejected):
            self.quiesce()

    def test_final_fence_overrun_or_clock_regression_cannot_acknowledge_quiescence(self):
        for value in (50, 0):
            with self.subTest(value=value):
                self.setUp()
                calls = []
                def fence():
                    calls.append(True)
                    if len(calls) == 2:
                        self.time = value
                    return True
                self.engine.start_fence = fence
                with self.assertRaises(commands.CommandUncertain):
                    self.quiesce()

    def test_integer_fence_acknowledgment_is_rejected(self):
        self.fences = [1]
        with self.assertRaises(durable.Rejected):
            self.quiesce()
        self.assertEqual(self.commands.calls, [])

    def test_restart_race_between_observations_never_passes(self):
        with self.assertRaises(durable.Rejected):
            self.quiesce(final={**self.before, "InvocationID": "c" * 32})

    def test_changed_state_after_cgroup_observation_is_pending(self):
        self.assertFalse(self.quiesce(final={**self.stopped, "Job": "1"}))

    def test_changed_fragment_or_static_unit_properties_are_rejected_before_stop(self):
        for update in ({"KillMode": "process"}, {"Restart": "always"}, {"DropInPaths": "/unknown.conf"},
                       {"Delegate": "yes"}, {"ExecStart": "unreviewed"}, {"FragmentPath": "/unknown.service"},
                       {"ReadWritePaths": "/"}):
            with self.subTest(update=update):
                self.setUp()
                with self.assertRaises(durable.Rejected):
                    self.quiesce(before={**self.before, **update})
                self.assertEqual(len(self.commands.calls), 1)
        self.setUp()
        self.engine.read_fragment_hash = lambda _: "0" * 64
        with self.assertRaises(durable.Rejected):
            self.quiesce()
        self.assertEqual(len(self.commands.calls), 1)

    def test_even_pinned_unsafe_unit_semantics_are_rejected(self):
        for update in ({"User": "root"}, {"User": ""}, {"Group": "0"}, {"KillMode": "mixed"},
                       {"SendSIGKILL": "no"}, {"NoNewPrivileges": "no"}, {"ProtectControlGroups": "no"},
                       {"CapabilityBoundingSet": "CAP_SYS_ADMIN"}, {"AmbientCapabilities": "CAP_KILL"},
                       {"RestrictNamespaces": "no"}, {"ProtectSystem": "no"}, {"RestrictSUIDSGID": "no"}):
            with self.subTest(update=update):
                self.setUp()
                self.before.update(update)
                self.engine.forward = binding(self.before)
                with self.assertRaises(durable.Rejected):
                    self.quiesce()

    def test_reused_unit_or_wrong_cgroup_rejects_before_stop(self):
        for update in ({"InvocationID": "c" * 32}, {"InvocationID": ""}, {"ControlGroup": "/other"},
                       {"ControlGroup": ""}, {"MainPID": "-1"}, {"MainPID": "00123"}):
            with self.subTest(update=update):
                self.setUp()
                with self.assertRaises(durable.Rejected):
                    self.quiesce(before={**self.before, **update})
                self.assertEqual(len(self.commands.calls), 1)

    def test_uncertain_manager_or_cgroup_result_never_passes(self):
        self.commands.failure = commands.CommandUncertain("command-deadline-missed")
        with self.assertRaises(durable.Rejected):
            self.quiesce()
        self.setUp()
        self.cgroups.value = durable.Rejected("cgroup-unavailable")
        with self.assertRaises(durable.Rejected):
            self.quiesce()

    def test_recovery_cannot_share_unit_invocation_or_nested_cgroup_with_forward(self):
        for recovery in (replace(self.recovery, unit=self.forward.unit),
                         replace(self.recovery, invocation_id=self.forward.invocation_id),
                         replace(self.recovery, cgroup=self.forward.cgroup),
                         replace(self.recovery, cgroup=self.forward.cgroup + "/child"),
                         replace(self.recovery, cgroup="/recovery")):
            with self.subTest(recovery=recovery), self.assertRaises(durable.Rejected):
                manager.SystemdMutators(systemctl="/accepted/systemctl", commands=self.commands, cgroups=self.cgroups,
                                        forward=self.forward, recovery=recovery, start_fence=lambda: True)

    def test_unbound_unit_cannot_be_observed(self):
        with self.assertRaises(durable.Rejected):
            self.engine.observe(binding(observed("unknown.service")), deadline=50)
        self.assertEqual(self.commands.calls, [])

    def test_binding_rejects_options_short_ids_and_path_traversal(self):
        for update in ({"unit": "--all.service"}, {"unit": "../other.service"}, {"invocation_id": "short"},
                       {"cgroup": "/recovery/../other"}, {"cgroup": "/"}, {"fragment_path": "relative"},
                       {"properties_sha256": "short"}):
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                replace(self.forward, **update)

    def test_property_parser_rejects_missing_duplicate_unknown_and_non_utf8(self):
        raw = encoded(self.before)
        for bad in (raw.replace(b"MainPID=123\n", b""), raw + b"Job=0\n", raw + b"Unknown=1\n",
                    raw + b"\x00", raw + b"\xff", raw + b"unstructured\n", b"x" * 65537):
            with self.subTest(bad=bad[-30:]), self.assertRaises(durable.Rejected):
                manager.properties(bad)


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.transport = commands.LocalCommands()

    def tearDown(self):
        for proc in self.transport.pending:
            proc.wait(timeout=5)
        self.transport.reap()

    def test_actual_synthetic_child_gets_no_credentials_shell_or_workspace_cwd(self):
        code = "import os;print(os.getcwd());print(sorted(os.environ));print('$(not-a-shell)')"
        raw = self.transport.run((sys.executable, "-I", "-c", code), deadline=time.monotonic() + 10)
        self.assertTrue(raw.startswith(b"/\n"))
        self.assertNotIn(b"PAPERCLIP", raw)
        self.assertNotIn(b"TOKEN", raw)
        self.assertIn(b"$(not-a-shell)", raw)

    def test_child_failure_never_exposes_raw_stdout_or_stderr(self):
        with self.assertRaises(commands.CommandUncertain) as caught:
            self.transport.run((sys.executable, "-I", "-c", "import sys;print('private');sys.stderr.write('secret');sys.exit(7)"),
                               deadline=time.monotonic() + 10)
        self.assertNotIn("private", str(caught.exception))
        self.assertNotIn("secret", str(caught.exception))

    def test_child_output_is_bounded(self):
        with self.assertRaises(commands.CommandUncertain) as caught:
            self.transport.run((sys.executable, "-I", "-c", "import os;os.write(1,b'x'*70000)"), deadline=time.monotonic() + 10)
        self.assertEqual(str(caught.exception), "command-output-overflow")

    def test_expired_deadline_starts_no_helper(self):
        transport = commands.LocalCommands(clock=lambda: 100)
        with patch.object(commands.subprocess, "Popen") as spawn, self.assertRaises(commands.CommandUncertain):
            transport.run((sys.executable, "-I", "-c", "raise Exception()"), deadline=100)
        spawn.assert_not_called()

    def test_regressed_or_nonfinite_clock_refuses_command(self):
        for values in ([100, 99], [float("nan")], [True], [100, float("inf")]):
            with self.subTest(values=values):
                clock = iter(values)
                transport = commands.LocalCommands(clock=lambda: next(clock))
                with self.assertRaises(commands.CommandUncertain):
                    transport.run((sys.executable, "-I", "-c", "pass"), deadline=200)

    def test_deadline_after_spawn_kills_only_helper_and_is_not_quiescence(self):
        values = iter([100, 100])
        transport = commands.LocalCommands(clock=lambda: next(values, 200))
        with self.assertRaises(commands.CommandUncertain) as caught:
            transport.run((sys.executable, "-I", "-c", "import signal;signal.pause()"), deadline=200)
        self.assertEqual(str(caught.exception), "command-deadline-missed")
        # Test cleanup is not an extra production recovery-budget allowance.
        for proc in transport.pending:
            proc.wait(timeout=5)
        transport.reap()
        self.assertEqual(transport.pending, [])

    def test_command_options_require_fixed_absolute_argv_and_finite_deadline(self):
        for argv, deadline in (([sys.executable], 200), (("python",), 200), ((sys.executable, "\0"), 200),
                               ((sys.executable,), float("nan")), ((sys.executable,), True)):
            with self.subTest(argv=argv, deadline=deadline), self.assertRaises(durable.Rejected):
                self.transport.run(argv, deadline=deadline)


class CgroupReaderTests(unittest.TestCase):
    """Fake mountinfo + ordinary temporary files; NOT kernel cgroup evidence."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="recovery-cgroup-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.group = self.root / "mutators" / "forward.service"
        self.group.mkdir(parents=True)
        self.events = self.group / "cgroup.events"
        self.events.write_bytes(b"populated 0\nfrozen 0\n")
        self.mountinfo = ("31 1 0:27 / " + str(self.root) + " rw - cgroup2 cgroup rw\n").encode()
        self.reader = manager.CgroupV2(str(self.root))

    def query(self, path="/mutators/forward.service"):
        with patch("builtins.open", return_value=io.BytesIO(self.mountinfo)):
            return self.reader.populated(path)

    def test_recursive_populated_bit_is_parsed_strictly(self):
        self.assertIs(self.query(), False)
        self.events.write_bytes(b"populated 1\nfrozen 0\n")
        self.assertIs(self.query(), True)
        self.events.write_bytes(b"populated 0\n")
        self.assertIs(self.query(), False)

    def test_missing_group_is_unknown_not_empty(self):
        self.assertIsNone(self.query("/missing"))

    def test_non_cgroup_or_subtree_mount_is_rejected(self):
        for raw in (self.mountinfo.replace(b"cgroup2", b"tmpfs"),
                    self.mountinfo.replace(b"0:27 / ", b"0:27 /subtree "),
                    self.mountinfo + self.mountinfo, b"invalid\n", b"\xff", b"x" * (1024 * 1024 + 1)):
            with self.subTest(raw=raw[:50]):
                self.mountinfo = raw
                with self.assertRaises(durable.Rejected):
                    self.query()

    def test_duplicate_unknown_missing_and_malformed_event_fields_are_rejected(self):
        for raw in (b"", b"populated 00\n", b"populated 0\npopulated 0\n", b"frozen 0\n",
                    b"populated false\n", b"populated 0\nunknown 1\n", b"populated 0 1\n", b"\xff"):
            with self.subTest(raw=raw):
                self.events.write_bytes(raw)
                with self.assertRaises(durable.Rejected):
                    self.query()

    def test_symlink_directory_or_events_never_followed(self):
        (self.root / "alias").symlink_to(self.group, target_is_directory=True)
        with self.assertRaises(durable.Rejected):
            self.query("/alias")
        self.events.unlink()
        self.events.symlink_to(self.root / "secret")
        with self.assertRaises(durable.Rejected):
            self.query()

    def test_path_traversal_or_mount_root_is_rejected(self):
        for path in ("/", "/mutators/../other", "relative", "/mutators//forward.service", "/mutators/."):
            with self.subTest(path=path), self.assertRaises(durable.Rejected):
                self.query(path)


class FragmentTests(unittest.TestCase):
    def test_fragment_hash_uses_no_follow_regular_file_and_safe_mode(self):
        with tempfile.TemporaryDirectory(prefix="recovery-fragment-") as root:
            path = Path(root) / "forward.service"
            path.write_bytes(b"synthetic unit fragment\n")
            path.chmod(0o600)
            self.assertEqual(manager.fragment_hash(str(path)), durable.digest(path.read_bytes()))
            path.chmod(0o666)
            with self.assertRaises(durable.Rejected):
                manager.fragment_hash(str(path))
            path.unlink()
            path.symlink_to("absent")
            with self.assertRaises(durable.Rejected):
                manager.fragment_hash(str(path))
