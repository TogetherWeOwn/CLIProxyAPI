"""Supervisor self-identity with scripted manager/cgroup replies, not a service drill."""
import copy
from dataclasses import replace
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import bootstrap, commands, durable, journal, manager, supervisor
from test_manager import encoded, observed
from test_recovery_state import intent


BOOT = "12345678-1234-1234-1234-123456789abc"


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.row = observed("cpa-supervisor.service", "b" * 32, "/recovery/cpa-supervisor.service")
        self.row.update(Restart="on-failure", MainPID=str(os.getpid()), User=str(os.geteuid()), Group=str(os.getegid()))
        self.binding = bootstrap.SupervisorBinding(self.row["Id"], self.row["FragmentPath"], "f" * 64,
            durable.digest(durable.canonical(manager.static_properties(self.row))), os.geteuid(), os.getegid())
        self.now, self.boot, self.group = 1001.0, BOOT, self.row["ControlGroup"]
        self.calls, self.groups = [], []
        self.failure = None
        self.after = lambda: None
        self.engine = bootstrap.SystemdSupervisorIdentity(systemctl="/accepted/systemctl",
            commands=SimpleNamespace(run=self.command), binding=self.binding, clock=lambda: self.now,
            boot_id=lambda: self.boot, read_fragment_hash=lambda _: "f" * 64, read_process_cgroup=self.cgroup)

    def command(self, argv, *, deadline):
        self.calls.append((argv, deadline))
        if self.failure:
            raise self.failure
        raw = encoded(self.row)
        self.after()
        return raw

    def cgroup(self, pid):
        self.groups.append(pid)
        return self.group

    def start(self):
        return self.engine.bootstrap(installation_id="installation-a", attempt_id="attempt-a", deadline=1100)

    def repin(self):
        self.engine.binding = replace(self.binding,
            properties_sha256=durable.digest(durable.canonical(manager.static_properties(self.row))))

    def test_bootstrap_observes_self_and_fixed_read_only_manager_argv(self):
        result = self.start()
        self.assertEqual(result["owner"], {"installation_id": "installation-a", "attempt_id": "attempt-a",
            "unit": self.row["Id"], "invocation_id": "b" * 32, "boot_id": BOOT})
        self.assertEqual(result["pid"], os.getpid())
        self.assertEqual(self.groups, [os.getpid()] * 3)
        self.assertEqual(len(self.calls), 2)
        for argv, deadline in self.calls:
            self.assertEqual(argv, ("/accepted/systemctl", "--no-pager", "show",
                "--property=" + ",".join(sorted(manager.PROPERTIES)), "--", self.binding.unit))
            self.assertEqual(deadline, 1100)
        self.assertNotIn("ExecStart", str(result))
        self.assertNotIn("ReadWritePaths", str(result))
        self.assertFalse(hasattr(self.engine, "fence"))
        self.assertFalse(hasattr(self.engine, "enqueue_recovery"))

    def test_reobservation_returns_only_original_owner(self):
        result = self.start()
        self.assertEqual(self.engine.observe_owner(result["owner"], deadline=1100), result["owner"])
        self.assertEqual(len(self.calls), 4)

    def test_returned_identity_is_not_mutable_authority(self):
        result = self.start()
        original = copy.deepcopy(result["owner"])
        result["owner"]["invocation_id"] = "a" * 32
        result["cgroup"] = "/foreign"
        self.assertEqual(self.engine.observe_owner(original, deadline=1100), original)

    def test_caller_and_environment_cannot_supply_manager_identity(self):
        with patch.dict(os.environ, {"INVOCATION_ID": "a" * 32, "MAINPID": "1", "BOOT_ID": "forged"}):
            self.assertEqual(self.start()["owner"]["invocation_id"], "b" * 32)

    def test_bootstrap_is_one_shot(self):
        self.start()
        with self.assertRaises(durable.Rejected):
            self.start()
        self.assertEqual(len(self.calls), 2)

    def test_unknown_or_bad_attempt_fails_before_query_and_cannot_retry(self):
        with self.assertRaises(durable.Rejected):
            self.engine.bootstrap(installation_id="../escape", attempt_id="attempt-a", deadline=1100)
        self.assertEqual(self.calls, [])
        with self.assertRaises(durable.Rejected):
            self.start()

    def test_observation_without_bootstrap_revokes_instance(self):
        with self.assertRaises(durable.Rejected):
            self.engine.observe_owner({}, deadline=1100)
        with self.assertRaises(durable.Rejected):
            self.start()
        self.assertEqual(self.calls, [])

    def test_foreign_expected_owner_refuses_without_query(self):
        result = self.start()
        for update in ({"attempt_id": "other"}, {"installation_id": "other"}, {"invocation_id": "a" * 32},
                       {"extra": True}):
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.engine.observe_owner({**result["owner"], **update}, deadline=1100)
        self.assertEqual(len(self.calls), 2)

    def test_wrong_mainpid_and_pending_or_nonrunning_manager_refuse(self):
        original = dict(self.row)
        for update in ({"MainPID": "0"}, {"MainPID": "1"}, {"MainPID": "0" + str(os.getpid())},
                       {"Job": "1"}, {"Job": "00"}, {"ActiveState": "activating"}, {"SubState": "exited"},
                       {"InvocationID": ""}, {"InvocationID": "PID-123"}, {"ControlGroup": "/a/../b"}):
            self.setUp()
            self.row = {**original, **update}
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.start()
            self.assertTrue(self.engine.revoked)

    def test_unit_fragment_and_static_changes_refuse(self):
        original = dict(self.row)
        for update in ({"Id": "other.service"}, {"FragmentPath": "/other"}, {"DropInPaths": "/added"},
                       {"LoadState": "not-found"}, {"ExecStart": "changed"}, {"ReadWritePaths": "/"}):
            self.setUp()
            self.row = {**original, **update}
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.start()
        self.setUp()
        self.engine.read_fragment_hash = lambda _: "0" * 64
        with self.assertRaises(durable.Rejected):
            self.start()

    def test_even_repinned_unsafe_supervisor_semantics_refuse(self):
        for update in ({"User": "root"}, {"Group": "recovery"}, {"Restart": "no"}, {"Restart": "always"},
                       {"Delegate": "yes"}, {"KillMode": "process"}, {"CapabilityBoundingSet": "CAP_SYS_ADMIN"},
                       {"ProtectSystem": "no"}, {"NoNewPrivileges": "no"}, {"Type": "simple"}):
            self.setUp()
            self.row.update(update)
            self.repin()
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.start()
        self.setUp()
        self.row["ExecStart"] = self.row["ExecStart"].replace("ignore_errors=no", "ignore_errors=yes")
        self.repin()
        with self.assertRaises(durable.Rejected):
            self.start()

    def test_actual_uid_or_gid_mismatch_refuses_before_query(self):
        for key in ("uid", "gid"):
            self.setUp()
            self.engine.binding = replace(self.binding, **{key: getattr(self.binding, key) + 1})
            with self.subTest(key=key), self.assertRaises(durable.Rejected):
                self.start()
            self.assertEqual(self.calls, [])

    def test_cgroup_mismatch_or_process_migration_refuses(self):
        self.group = "/foreign"
        with self.assertRaises(durable.Rejected):
            self.start()
        self.setUp()
        self.after = lambda: setattr(self, "group", "/migrated")
        with self.assertRaises(durable.Rejected):
            self.start()

    def test_invocation_replacement_during_or_after_bootstrap_refuses(self):
        self.after = lambda: self.row.update(InvocationID="c" * 32)
        with self.assertRaises(durable.Rejected):
            self.start()
        self.setUp()
        result = self.start()
        self.row.update(InvocationID="c" * 32)
        with self.assertRaises(durable.Rejected):
            self.engine.observe_owner(result["owner"], deadline=1100)
        self.row.update(InvocationID="b" * 32)
        with self.assertRaises(durable.Rejected):
            self.engine.observe_owner(result["owner"], deadline=1100)

    def test_cgroup_replacement_after_bootstrap_cannot_rebind(self):
        result = self.start()
        self.group = self.row["ControlGroup"] = "/replacement"
        with self.assertRaises(durable.Rejected):
            self.engine.observe_owner(result["owner"], deadline=1100)

    def test_boot_change_malformed_boot_or_missing_boot_refuses(self):
        for boot in ("boot-a", "", None, "A" * 36):
            self.setUp()
            self.boot = boot
            with self.subTest(boot=boot), self.assertRaises(durable.Rejected):
                self.start()
        self.setUp()
        self.after = lambda: setattr(self, "boot", "22345678-1234-1234-1234-123456789abc")
        with self.assertRaises(durable.Rejected):
            self.start()

    def test_boot_change_after_bootstrap_refuses_same_pid(self):
        result = self.start()
        self.boot = "22345678-1234-1234-1234-123456789abc"
        with self.assertRaises(durable.Rejected):
            self.engine.observe_owner(result["owner"], deadline=1100)

    def test_deadline_inclusive_regression_and_bad_clock_refuse(self):
        for now in (1100, float("nan"), float("inf"), True, "1001"):
            self.setUp()
            self.now = now
            with self.subTest(now=now), self.assertRaises(durable.Rejected):
                self.start()
        for now in (1000, 1100):
            self.setUp()
            self.after = lambda: setattr(self, "now", now)
            with self.subTest(now=now), self.assertRaises(durable.Rejected):
                self.start()

    def test_query_and_fragment_uncertainty_latch_without_retry(self):
        for failure in (commands.CommandUncertain("lost"), OSError("restricted detail")):
            self.setUp()
            self.failure = failure
            with self.subTest(failure=type(failure).__name__), self.assertRaises(Exception):
                self.start()
            self.failure = None
            with self.assertRaises(durable.Rejected):
                self.start()
            self.assertEqual(len(self.calls), 1)

    def test_fragment_change_between_queries_refuses(self):
        values = iter(("f" * 64, "0" * 64))
        self.engine.read_fragment_hash = lambda _: next(values)
        with self.assertRaises(durable.Rejected):
            self.start()

    def test_binding_rejects_invalid_unit_path_pins_and_root_identity(self):
        for update in ({"unit": "../x.service"}, {"fragment_path": "relative"}, {"fragment_path": "/"},
                       {"fragment_sha256": "A" * 64}, {"properties_sha256": "short"}, {"uid": 0},
                       {"gid": 0}, {"uid": True}, {"gid": 1.0}):
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                replace(self.binding, **update)
        with self.assertRaises(durable.Rejected):
            bootstrap.SystemdSupervisorIdentity(systemctl="systemctl", commands=self, binding=self.binding)

    def test_recovery_supervisor_uses_self_identity_but_fence_is_still_independent(self):
        value = intent()
        result = self.engine.bootstrap(installation_id=value["installation_id"], attempt_id=value["attempt_id"],
                                       deadline=1100)
        with tempfile.TemporaryDirectory() as path:
            value["owner"].update(boot_id=BOOT)
            with durable.directory(path, private=True) as fd:
                log = journal.Journal(fd)
                log.prepare(value)
                log.arm({"boot_id": BOOT, "monotonic": 1000})
            owner = result["owner"]
            # Match the synthetic original attempt, never alter bootstrap identity.
            self.assertEqual(owner["installation_id"], value["installation_id"])
            self.assertEqual(owner["attempt_id"], value["attempt_id"])
            enqueues, alerts = [], []
            transport = SimpleNamespace(observe_owner=self.engine.observe_owner,
                fence=lambda value, deadline: False,
                enqueue_recovery=lambda request, deadline: enqueues.append(request))
            with supervisor.recovery_owner(path, owner=owner, manager=transport, clock=lambda: self.now,
                    boot_id=lambda: BOOT, persist_alert=lambda _: None,
                    transport_alert=lambda notice: alerts.append(notice) or True) as process:
                state = process.reconcile(deadline=1100)
            self.assertEqual(state["state"], "recovery_unresolved")
            self.assertEqual(enqueues, [])
            self.assertEqual(len(alerts), 1)
            self.assertFalse(Path(path, "reconcile-request.json").exists())
            for key in ("forward_allowed", "start_permission", "recovery_completed", "installation_start_fence_proven"):
                self.assertIs(state[key], False)

    def test_real_local_executable_fixture_preserves_fixed_query_transport(self):
        with tempfile.TemporaryDirectory() as path:
            helper = Path(path, "reply")
            helper.write_text("#!" + sys.executable + " -I\nimport sys\nsys.stdout.buffer.write(" +
                              repr(encoded(self.row)) + ")\n")
            helper.chmod(0o700)
            self.engine.systemctl = str(helper)
            self.engine.commands = commands.LocalCommands()
            self.engine.clock = time.monotonic
            result = self.engine.bootstrap(installation_id="installation-a", attempt_id="attempt-a",
                                           deadline=time.monotonic() + 10)
            self.assertEqual(result["pid"], os.getpid())
            self.assertFalse(self.engine.commands.pending)

    def test_separate_process_ignores_forged_environment_with_actual_self_pid(self):
        source = """
import os, sys
sys.path[:0] = sys.argv[1:3]
from test_bootstrap import BootstrapTests
case = BootstrapTests()
case.setUp()
result = case.start()
assert result['pid'] == os.getpid()
assert result['owner']['invocation_id'] == 'b' * 32
assert result['owner']['boot_id'] == '12345678-1234-1234-1234-123456789abc'
print('self-mainpid-scripted-manager-no-start-grant')
"""
        root = Path(__file__).resolve().parent.parent
        env = {**os.environ, "INVOCATION_ID": "a" * 32, "MAINPID": "1", "BOOT_ID": "forged"}
        result = subprocess.run((sys.executable, "-I", "-c", source, str(root), str(root / "tests")),
                                env=env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"self-mainpid-scripted-manager-no-start-grant\n")


class KernelBootTests(unittest.TestCase):
    def test_exact_bounded_kernel_boot_read(self):
        with patch("builtins.open", return_value=io.BytesIO((BOOT + "\n").encode())) as opened:
            self.assertEqual(bootstrap.kernel_boot_id(), BOOT)
        opened.assert_called_once_with("/proc/sys/kernel/random/boot_id", "rb")

    def test_malformed_partial_oversize_or_unreadable_kernel_boot_refuses(self):
        for raw in (b"", BOOT.encode(), (BOOT + "\nextra").encode(), b"x" * 37,
                    (BOOT.upper() + "\n").encode(), b"\xff" * 36 + b"\n"):
            with self.subTest(raw=raw[:5]), patch("builtins.open", return_value=io.BytesIO(raw)):
                with self.assertRaises(durable.Rejected):
                    bootstrap.kernel_boot_id()
        with patch("builtins.open", side_effect=OSError("not available")):
            with self.assertRaises(durable.Rejected):
                bootstrap.kernel_boot_id()
