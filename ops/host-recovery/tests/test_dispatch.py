"""Scripted manager dispatch with real journal/transport; NOT a systemd drill."""
import copy
import json
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

from host_recovery import commands, dispatch, durable, jobs, manager
import test_supervisor
from test_manager import encoded, observed


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.case = test_supervisor.SupervisorTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        with self.case.open() as process:
            self.request = copy.deepcopy(process.plan)
        self.request["deadline"] = 1100.0
        self.sign()
        self.now, self.boot = 1050.0, "boot-a"
        self.calls, self.authorizations = [], []
        self.allowed = True
        self.on_command = lambda _: None
        self.reply, self.failure = b"", None
        self.bind()

    def sign(self):
        self.request.pop("request_id", None)
        self.request["request_id"] = durable.digest(durable.canonical(self.request))

    def bind(self):
        self.row = observed(jobs.recovery_unit(self.request["request_id"]), "", "/recovery/restore.service")
        self.row.update(ActiveState="inactive", SubState="dead", MainPID="0", ControlGroup="")
        self.binding = jobs.RecoveryJobBinding(self.request["request_id"], self.row["FragmentPath"], "f" * 64,
            durable.digest(durable.canonical(manager.static_properties(self.row))))
        self.engine = dispatch.SystemdRecoveryDispatch(systemctl="/accepted/systemctl",
            commands=SimpleNamespace(run=self.command), binding=self.binding, authorize=self.authorize,
            boot_id=lambda: self.boot, clock=lambda: self.now, read_fragment_hash=lambda _: "f" * 64)

    def authorize(self, request, *, deadline, phase):
        self.authorizations.append((request, deadline))
        return self.allowed

    def command(self, argv, *, deadline):
        self.calls.append((argv, deadline))
        self.on_command(argv)
        if self.failure:
            raise self.failure
        return encoded(self.row) if "show" in argv else self.reply

    def enqueue(self):
        return self.engine.enqueue_recovery(self.request, deadline=1100.0)

    def starts(self):
        return [argv for argv, _ in self.calls if "start" in argv]

    def test_only_fixed_request_instance_is_enqueued_once(self):
        receipt = self.enqueue()
        self.assertEqual(receipt, {"request_id": self.request["request_id"], "accepted": True,
                                   "separate_recovery_owner": True})
        self.assertEqual(self.starts(), [("/accepted/systemctl", "--no-block", "start", "--",
                                         jobs.recovery_unit(self.request["request_id"]))])
        self.assertEqual(len(self.authorizations), 3)
        self.assertTrue(all(deadline == 1100.0 for _, deadline in self.calls + self.authorizations))
        with self.assertRaises(durable.Rejected):
            self.enqueue()
        self.assertEqual(len(self.starts()), 1)

    def test_foreign_or_tampered_request_never_queries_or_starts(self):
        for update in ({"request_id": "e" * 64}, {"deadline": 1099.0}, {"extra": True},
                       {"forward_allowed": 0}, {"production_acceptance": 0}, {"schema": "other"}):
            with self.subTest(update=update):
                self.setUp()
                self.request.update(update)
                with self.assertRaises(durable.Rejected):
                    self.enqueue()
                self.assertEqual(self.calls, [])

    def test_even_self_consistent_wrong_owner_boot_arm_or_budget_refuses(self):
        for change in (lambda r: r["owner"].update(boot_id="boot-b"),
                       lambda r: r["owner"].update(attempt_id="other"),
                       lambda r: r.update(original_arm={"boot_id": "boot-b", "monotonic": 1000.0}),
                       lambda r: r.update(failure_lower_bound=True),
                       lambda r: r.update(deadline=1181.0),
                       lambda r: r.update(detection_upper_bound_seconds=51.0),
                       lambda r: r.update(detection_upper_bound_seconds=-1),
                       lambda r: r.update(detection_upper_bound_seconds=False)):
            with self.subTest(change=change):
                self.setUp()
                change(self.request)
                self.sign()
                self.bind()
                with self.assertRaises(durable.Rejected):
                    self.enqueue()
                self.assertEqual(self.calls, [])

    def test_malformed_values_are_fixed_rejections_without_transport(self):
        for key, value in (("deadline", float("nan")), ("original_arm", None), ("owner", []),
                           ("intent_sha256", b"not-json"), ("intent_sha256", "short"),
                           ("detection_upper_bound_seconds", float("inf"))):
            with self.subTest(key=key, value=value):
                self.setUp()
                self.request[key] = value
                with self.assertRaises(durable.Rejected):
                    self.enqueue()
                self.assertEqual(self.calls, [])

    def test_caller_cannot_expand_deadline_and_expiry_exhausts_object(self):
        with self.assertRaises(durable.Rejected):
            self.engine.enqueue_recovery(self.request, deadline=1101.0)
        with self.assertRaises(durable.Rejected):
            self.enqueue()
        self.assertEqual(self.calls, [])
        self.bind()
        self.now = 1100.0
        with self.assertRaises(durable.Rejected):
            self.enqueue()
        self.assertEqual(self.calls, [])

    def test_active_pending_failed_or_previously_invoked_workers_are_not_restarted(self):
        for update in ({"InvocationID": "b" * 32}, {"Job": "5"},
                       {"ActiveState": "active", "SubState": "running", "MainPID": "123",
                        "ControlGroup": "/recovery/restore.service", "InvocationID": "b" * 32},
                       {"ActiveState": "failed", "SubState": "failed", "InvocationID": "c" * 32}):
            with self.subTest(update=update):
                self.setUp()
                self.row.update(update)
                with self.assertRaises(durable.Rejected):
                    self.enqueue()
                self.assertEqual(self.starts(), [])

    def test_changed_command_fragment_or_sandbox_refuses_before_start(self):
        for update in ({"ExecStart": self.row["ExecStart"].replace("argv[]=/accepted/helper", "argv[]=/changed")},
                       {"DropInPaths": "/changed"}, {"Restart": "always"}, {"User": "root"}):
            with self.subTest(update=update):
                self.setUp()
                self.row.update(update)
                with self.assertRaises(durable.Rejected):
                    self.enqueue()
                self.assertEqual(self.starts(), [])
        self.setUp()
        self.engine.observer.read_fragment_hash = lambda _: "e" * 64
        with self.assertRaises(durable.Rejected):
            self.enqueue()
        self.assertEqual(self.starts(), [])

    def test_denied_or_coerced_authorization_never_queries(self):
        for allowed in (False, 1, None, {}, "yes"):
            with self.subTest(allowed=allowed):
                self.setUp()
                self.allowed = allowed
                with self.assertRaises(durable.Rejected):
                    self.enqueue()
                self.assertEqual(self.calls, [])

    def test_lease_loss_after_query_prevents_start(self):
        self.on_command = lambda _: setattr(self, "allowed", False)
        with self.assertRaises(durable.Rejected):
            self.enqueue()
        self.assertEqual(self.starts(), [])

    def test_lost_reply_does_not_allow_second_start_or_acknowledgment(self):
        def fail(argv):
            if "start" in argv:
                self.failure = commands.CommandUncertain("lost-reply")
        self.on_command = fail
        with self.assertRaises(durable.Rejected):
            self.enqueue()
        self.failure = None
        with self.assertRaises(durable.Rejected):
            self.enqueue()
        self.assertEqual(len(self.starts()), 1)

    def test_bad_success_reply_never_acknowledges_or_retries(self):
        for reply in (b"unexpected\n", "", None, False):
            with self.subTest(reply=reply):
                self.setUp()
                self.reply = reply
                with self.assertRaises(durable.Rejected):
                    self.enqueue()
                self.assertEqual(len(self.starts()), 1)
                with self.assertRaises(durable.Rejected):
                    self.enqueue()

    def test_expiry_or_boot_loss_on_either_boundary_is_uncertain(self):
        for operation in ("show", "start"):
            for key, value in (("now", 1100.0), ("now", 1049.0), ("boot", "boot-b")):
                with self.subTest(operation=operation, key=key):
                    self.setUp()
                    def change(argv):
                        if operation in argv:
                            setattr(self, key, value)
                    self.on_command = change
                    with self.assertRaises(durable.Rejected):
                        self.enqueue()
                    self.assertEqual(len(self.starts()), 0 if operation == "show" else 1)

    def test_authorization_callback_cannot_mutate_dispatched_request(self):
        original = copy.deepcopy(self.request)
        def change(request, *, deadline, phase):
            request["request_id"] = "e" * 64
            return True
        self.engine.authorize = change
        self.assertEqual(self.enqueue()["request_id"], original["request_id"])
        self.assertEqual(self.request, original)

    def test_real_local_helper_receives_fixed_argv_not_a_shell(self):
        with tempfile.TemporaryDirectory() as path:
            helper, receipt = Path(path) / "manager-fixture", Path(path) / "received.json"
            self.now = time.monotonic()
            self.request.update(original_arm={"boot_id": self.boot, "monotonic": self.now - 1},
                                failure_lower_bound=self.now - 1, detection_upper_bound_seconds=1,
                                deadline=self.now + 10)
            self.sign()
            self.bind()
            expected = ["--no-block", "start", "--", jobs.recovery_unit(self.request["request_id"])]
            helper.write_text("#!" + sys.executable + " -I\nimport json,sys\nfrom pathlib import Path\n"
                "if 'show' in sys.argv:\n sys.stdout.buffer.write(" + repr(encoded(self.row)) + ")\n"
                "elif sys.argv[1:] == " + repr(expected) + ":\n Path(" + repr(str(receipt)) +
                ").write_text(json.dumps(sys.argv[1:]))\nelse: sys.exit(2)\n")
            helper.chmod(0o700)
            engine = dispatch.SystemdRecoveryDispatch(systemctl=str(helper), commands=commands.LocalCommands(),
                binding=self.binding, authorize=lambda *a, **kw: True, boot_id=lambda: self.boot,
                read_fragment_hash=lambda _: "f" * 64)
            result = engine.enqueue_recovery(self.request, deadline=self.request["deadline"])
            self.assertEqual(result["request_id"], self.request["request_id"])
            self.assertEqual(durable.canonical(json.loads(receipt.read_bytes())), durable.canonical(expected))


class DispatchLeaseTests(unittest.TestCase):
    def setUp(self):
        self.case = test_supervisor.SupervisorTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def test_lease_is_unavailable_before_after_or_outside_context(self):
        saved = []
        with self.case.open() as process:
            with self.assertRaises(durable.Rejected):
                process.authorize_dispatch(process.plan, deadline=1100, phase="observe")
            def enqueue(request):
                saved.append(request)
                for phase in ("observe", "enqueue", "acknowledge"):
                    self.assertTrue(process.authorize_dispatch(request, deadline=1100, phase=phase))
                self.assertEqual(durable.decode((self.case.root / "reconcile-request.json").read_bytes()), request)
            self.case.manager.on_enqueue = enqueue
            self.assertEqual(process.reconcile(deadline=1100)["state"], "recovery_enqueued")
            self.assertIsNone(process.dispatch_request)
            with self.assertRaises(durable.Rejected):
                process.authorize_dispatch(saved[0], deadline=1100, phase="enqueue")
        with self.assertRaises(durable.Rejected):
            process.authorize_dispatch(saved[0], deadline=1100, phase="enqueue")

    def test_reordered_repeated_partial_or_swallowed_denial_cannot_acknowledge(self):
        for phases in (("enqueue",), ("observe", "observe"), ("observe",),
                       ("observe", "enqueue"), ("observe", "enqueue", "acknowledge", "enqueue")):
            with self.subTest(phases=phases):
                self.setUp()
                with self.case.open() as process:
                    def enqueue(request):
                        for phase in phases:
                            try:
                                process.authorize_dispatch(request, deadline=1100, phase=phase)
                            except durable.Rejected:
                                pass
                    self.case.manager.on_enqueue = enqueue
                    self.assertEqual(process.reconcile(deadline=1100)["state"], "recovery_unresolved")
                    self.assertFalse((self.case.root / "reconcile-enqueued.json").exists())
                    self.assertIsNone(process.dispatch_request)

    def test_changed_request_file_owner_fence_or_deadline_revokes_lease(self):
        for kind in ("file", "owner", "fence", "deadline", "argument"):
            with self.subTest(kind=kind):
                self.setUp()
                with self.case.open() as process:
                    def enqueue(request):
                        if kind == "file":
                            (self.case.root / "reconcile-request.json").write_bytes(b"{}\n")
                        elif kind == "owner":
                            self.case.manager.owner_change = True
                        elif kind == "fence":
                            self.case.manager.fenced = False
                        elif kind == "deadline":
                            self.case.now = 1100
                        else:
                            request["request_id"] = "e" * 64
                        process.authorize_dispatch(request, deadline=1100, phase="observe")
                    self.case.manager.on_enqueue = enqueue
                    state = process.reconcile(deadline=1100)
                    self.assertEqual(state["state"], "recovery_unresolved")
                    self.assertTrue(state["alert"]["transport_delivered"])
                    self.assertIsNone(process.dispatch_request)
                    self.assertFalse((self.case.root / "reconcile-enqueued.json").exists())

    def test_sigkill_after_scripted_start_keeps_request_but_cannot_recreate_lease(self):
        source = r'''
import json, sys
from pathlib import Path
from types import SimpleNamespace
sys.path[:0] = [sys.argv[1], sys.argv[2]]
from host_recovery import dispatch, durable, jobs, manager, supervisor
from test_supervisor import ScriptedManager
from test_manager import observed, encoded
root, owner = sys.argv[3], json.loads(sys.argv[4])
boundary = ScriptedManager()
with supervisor.recovery_owner(root, owner=owner, manager=boundary, clock=lambda: 1050.0,
        boot_id=lambda: "boot-a", persist_alert=lambda _: None, transport_alert=lambda _: True) as process:
    def enqueue(request, *, deadline):
        row = observed(jobs.recovery_unit(request["request_id"]), "", "/recovery/restore.service")
        row.update(ActiveState="inactive", SubState="dead", MainPID="0", ControlGroup="")
        binding = jobs.RecoveryJobBinding(request["request_id"], row["FragmentPath"], "f" * 64,
            durable.digest(durable.canonical(manager.static_properties(row))))
        calls = []
        def authorize(value, *, deadline, phase):
            result = process.authorize_dispatch(value, deadline=deadline, phase=phase)
            calls.append(result)
            if len(calls) == 3:
                print("DISPATCHED", flush=True)
                sys.stdin.readline()
            return result
        commands = SimpleNamespace(run=lambda argv, **kw: encoded(row) if "show" in argv else b"")
        adapter = dispatch.SystemdRecoveryDispatch(systemctl="/scripted/systemctl", commands=commands,
            binding=binding, authorize=authorize, boot_id=lambda: "boot-a", clock=lambda: 1050.0,
            read_fragment_hash=lambda _: "f" * 64)
        return adapter.enqueue_recovery(request, deadline=deadline)
    boundary.enqueue_recovery = enqueue
    process.reconcile(deadline=1100.0)
'''
        tests = Path(__file__).resolve().parent
        child = subprocess.Popen([sys.executable, "-I", "-c", source, str(tests.parent), str(tests),
                                  str(self.case.root), json.dumps(self.case.owner)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(10), "child did not reach dispatch reply boundary")
            self.assertEqual(child.stdout.readline(), b"DISPATCHED\n")
            with self.assertRaises(BlockingIOError):
                with durable.installation_lock(self.case.root, self.case.owner):
                    pass
            self.assertTrue((self.case.root / "reconcile-request.json").exists())
            self.assertFalse((self.case.root / "reconcile-enqueued.json").exists())
            child.kill()
            self.assertEqual(child.wait(timeout=5), -9)
            request = durable.decode((self.case.root / "reconcile-request.json").read_bytes())
            with self.case.open() as reopened:
                self.assertEqual(reopened.status()["error"], "supervisor-dispatch-reconciliation-required")
                with self.assertRaises(durable.Rejected):
                    reopened.authorize_dispatch(request, deadline=1100, phase="enqueue")
            self.assertEqual(self.case.enqueues(), [])
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            child.stdin.close()
            child.stdout.close()
            child.stderr.close()

    def test_integrated_dispatch_holds_lock_and_reopen_never_redispatches(self):
        with self.case.open() as process:
            def enqueue(request, *, deadline):
                case = DispatchTests()
                case.setUp()
                self.addCleanup(case.doCleanups)
                case.request = copy.deepcopy(request)
                case.bind()
                case.engine.authorize = process.authorize_dispatch
                with self.assertRaises(BlockingIOError):
                    with durable.installation_lock(self.case.root, self.case.owner):
                        pass
                return case.engine.enqueue_recovery(request, deadline=deadline)
            self.case.manager.enqueue_recovery = enqueue
            state = process.reconcile(deadline=1100)
            self.assertEqual(state["state"], "recovery_enqueued")
            self.case.assert_fenced(state)
        with self.case.open() as reopened:
            self.assertEqual(reopened.status()["error"], "supervisor-dispatch-reconciliation-required")
            with self.assertRaises(durable.Rejected):
                reopened.authorize_dispatch({}, deadline=1100, phase="observe")
