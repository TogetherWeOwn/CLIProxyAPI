"""Scripted systemd replies and a real local helper; NOT a manager recovery drill."""
from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

from host_recovery import commands, durable, jobs, manager
from test_manager import encoded, observed


class JobTests(unittest.TestCase):
    def setUp(self):
        self.request_id = "d" * 64
        self.row = observed(jobs.recovery_unit(self.request_id), "b" * 32, "/recovery/restore.service")
        self.binding = jobs.RecoveryJobBinding(self.request_id, self.row["FragmentPath"], "f" * 64,
            durable.digest(durable.canonical(manager.static_properties(self.row))))
        self.now, self.boot = 1, "boot-a"
        self.calls = []
        self.failure = None
        self.after = lambda: None
        self.engine = jobs.SystemdRecoveryJobs(systemctl="/accepted/systemctl", commands=SimpleNamespace(run=self.command),
            binding=self.binding, boot_id=lambda: self.boot, clock=lambda: self.now,
            read_fragment_hash=lambda _: "f" * 64)

    def command(self, argv, *, deadline):
        self.calls.append((argv, deadline))
        if self.failure:
            raise self.failure
        raw = encoded(self.row)
        self.after()
        return raw

    def observe(self):
        return self.engine.observe(self.request_id, deadline=50)

    def repin(self):
        self.engine.binding = replace(self.binding,
            properties_sha256=durable.digest(durable.canonical(manager.static_properties(self.row))))

    def test_read_only_digest_named_unit_and_running_invocation(self):
        value = self.observe()
        self.assertEqual(value["state"], "running")
        self.assertEqual(value["invocation_id"], "b" * 32)
        argv, deadline = self.calls[0]
        self.assertEqual(argv[:3], ("/accepted/systemctl", "--no-pager", "show"))
        self.assertEqual(argv[-2:], ("--", jobs.recovery_unit(self.request_id)))
        self.assertEqual(deadline, 50)
        self.assertFalse(any(word in argv for word in ("start", "restart", "stop", "reset-failed")))
        self.assertNotIn("ExecStart", value)

    def test_inactive_job_absence_is_never_proof_dispatch_did_not_happen(self):
        for invocation in ("", "b" * 32):
            with self.subTest(invocation=invocation):
                self.row.update(ActiveState="inactive", SubState="dead", MainPID="0", ControlGroup="",
                                InvocationID=invocation)
                self.assertEqual(self.observe()["state"], "inactive_unverified")

    def test_failed_worker_exit_is_not_restoration_success(self):
        self.row.update(ActiveState="failed", SubState="failed", MainPID="0")
        self.assertEqual(self.observe()["state"], "inactive_unverified")

    def test_pending_job_is_not_running_or_completed(self):
        self.row.update(Job="12", ActiveState="activating", SubState="start")
        self.assertEqual(self.observe()["state"], "pending")

    def test_unknown_states_and_unowned_running_process_refuse(self):
        original = dict(self.row)
        for update in ({"ActiveState": "activating"}, {"ActiveState": "unknown"}, {"SubState": "exited"},
                       {"MainPID": "0"}, {"InvocationID": ""}, {"ControlGroup": ""}):
            self.row = {**original, **update}
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.observe()

    def test_unknown_or_noncanonical_numbers_refuse(self):
        for key in ("Job", "MainPID"):
            invalid = ("01", "-1", "1 2", "1/start", "4294967296", "True", " ")
            if key == "MainPID":
                invalid += ("",)
            for text in invalid:
                original = self.row[key]
                self.row[key] = text
                with self.subTest(key=key, text=text), self.assertRaises(durable.Rejected):
                    self.observe()
                self.row[key] = original

    def test_explicit_idle_job_display_is_not_dispatch_or_completion_proof(self):
        self.row["Job"] = ""
        value = self.observe()
        self.assertEqual(value["job_id"], 0)
        self.assertEqual(value["state"], "running")
        self.row.update(ActiveState="inactive", SubState="dead", MainPID="0", ControlGroup="")
        value = self.observe()
        self.assertEqual(value["job_id"], 0)
        self.assertEqual(value["state"], "inactive_unverified")

    def test_missing_job_property_is_not_an_idle_job(self):
        del self.row["Job"]
        with self.assertRaisesRegex(durable.Rejected, "manager-properties-incomplete"):
            self.observe()

    def test_foreign_request_cannot_even_query_manager(self):
        with self.assertRaises(durable.Rejected):
            self.engine.observe("e" * 64, deadline=50)
        self.assertEqual(self.calls, [])

    def test_changed_unit_fragment_and_dropins_fail(self):
        original = dict(self.row)
        for update in ({"Id": "other.service"}, {"LoadState": "not-found"}, {"DropInPaths": "/changed"},
                       {"FragmentPath": "/changed"}, {"ExecStart": "changed"}):
            self.row = {**original, **update}
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.observe()
        self.row = original
        self.engine.read_fragment_hash = lambda _: "0" * 64
        with self.assertRaises(durable.Rejected):
            self.observe()

    def test_even_pinned_privileged_or_restarting_worker_refuses(self):
        original = dict(self.row)
        for update in ({"User": "root"}, {"Group": "0"}, {"Restart": "always"}, {"Delegate": "yes"},
                       {"KillMode": "process"}, {"CapabilityBoundingSet": "CAP_SYS_ADMIN"},
                       {"AmbientCapabilities": "CAP_KILL"}, {"ProtectSystem": "no"}):
            self.row = {**original, **update}
            self.repin()
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.observe()

    def test_bad_invocation_or_cgroup_refuses(self):
        original = dict(self.row)
        for update in ({"InvocationID": "pid-123"}, {"ControlGroup": "/a/../b"}):
            self.row = {**original, **update}
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.observe()

    def test_lost_reply_and_nonfinite_clock_are_not_observations(self):
        self.failure = commands.CommandUncertain("lost-reply")
        with self.assertRaises(durable.Rejected):
            self.observe()
        self.failure = None
        self.now = float("nan")
        with self.assertRaises(durable.Rejected):
            self.observe()

    def test_boot_change_clock_regression_and_expiry_during_query_refuse(self):
        for key, value in (("boot", "boot-b"), ("now", 0), ("now", 50)):
            with self.subTest(key=key, value=value):
                self.setUp()
                self.after = lambda: setattr(self, key, value)
                with self.assertRaises(durable.Rejected):
                    self.observe()

    def test_request_binding_syntax_and_explicit_command_required(self):
        for request in ("short", "A" * 64, True, "x/../y"):
            with self.subTest(request=request), self.assertRaises(durable.Rejected):
                replace(self.binding, request_id=request)
        with self.assertRaises(durable.Rejected):
            jobs.SystemdRecoveryJobs(systemctl="systemctl", commands=self, binding=self.binding,
                                     boot_id=lambda: self.boot)

    def test_observation_schema_rejects_coercion_and_unsupported_outcomes(self):
        original = self.observe()
        for update in ({"job_id": False}, {"job_id": 1.0}, {"request_id": "e" * 64}, {"boot_id": "boot-b"},
                       {"unit": "foreign.service"}, {"state": "completed"}, {"extra": True},
                       {"invocation_id": ""}, {"state": "pending"}):
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                jobs.validate_observation({**original, **update}, self.request_id, self.boot)

    def test_real_helper_transport_returns_only_scripted_observation(self):
        with tempfile.TemporaryDirectory() as path:
            helper = Path(path) / "reply"
            helper.write_text("#!" + sys.executable + " -I\nimport sys\nsys.stdout.buffer.write(" +
                              repr(encoded(self.row)) + ")\n")
            helper.chmod(0o700)
            self.engine.systemctl = str(helper)
            self.engine.commands = commands.LocalCommands()
            self.engine.clock = time.monotonic
            value = self.engine.observe(self.request_id, deadline=time.monotonic() + 10)
            self.assertEqual(value["state"], "running")
            self.assertFalse(self.engine.commands.pending)
