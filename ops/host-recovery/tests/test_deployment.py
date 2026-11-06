"""Scripted daemon/fence/oracle boundaries only; no Docker endpoint is opened."""
from dataclasses import replace
import copy
from pathlib import Path
import sys
import tempfile
import time
import unittest

from host_recovery import commands, daemon, deployment, durable
import test_coordinator
from test_daemon import row
from test_recovery_state import intent


def projection():
    return {"object_id": intent()["old_object_id"], "image_id": "sha256:" + "e" * 64,
            "path": "/proxy", "args": ["--config", "/config/config.yaml"],
            "config": {"Env": ["SYNTHETIC_SECRET=not-real"], "Cmd": ["/proxy"], "User": "123"},
            "host_config": {"Binds": ["/synthetic:/config:ro"], "Privileged": False},
            "mounts": [{"Type": "bind", "Source": "/synthetic", "Destination": "/config", "RW": False}]}


class Docker:
    def __init__(self):
        self.value, self.state, self.calls = projection(), row(intent()["old_object_id"]), []
        self.hook, self.deadline = None, 50

    def run(self, argv, *, deadline):
        if self.deadline is not None:
            assert deadline == self.deadline
        self.calls.append(argv)
        assert argv[-1] == intent()["old_object_id"]
        assert argv[2:4] == ("container", "inspect")
        if self.hook:
            self.hook(argv)
        data = self.value if argv[-2] == "--format=" + deployment.FORMAT else self.state
        return data if type(data) is bytes else durable.canonical(data)


class Oracle:
    def __init__(self):
        self.starts = 0
        self.lost = False
        value = intent()
        self.receipt = {"baseline_sha256": value["baseline_sha256"], "object_id": value["old_object_id"],
                        "original_image": True, "original_replay": True, "new_plugin_absent": True,
                        "complete_write_set": True, "metadata_verified": True, "all_writers_stopped": True}

    def verify_baseline_stopped(self, value, *, deadline):
        return self.receipt

    def start_old(self, value, receipt, *, deadline):
        self.starts += 1
        if self.lost:
            raise OSError("private start error")
        return True


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.value, self.docker, self.time, self.fenced = intent(), Docker(), 1, True
        self.checks, self.on_check = 0, None
        objects = daemon.DockerObjects(docker="/accepted/docker", endpoint="unix:///accepted/disposable.sock",
                    commands=self.docker, intent=self.value, old_image_id="e" * 64,
                    start_fence=lambda: self.fenced, clock=lambda: self.time)
        approval = deployment.DeploymentApproval(durable.digest(durable.canonical(self.value)), "e" * 64,
                                                durable.digest(durable.canonical(projection())))
        self.gate = deployment.OldDeploymentGate(objects=objects, approval=approval,
                                               check=self.check, clock=lambda: self.time)
        self.oracle = Oracle()
        self.boundary = deployment.RecoveredDeploymentBoundary(self.oracle, self.gate)

    def check(self, *, deadline):
        self.assertEqual(deadline, 50)
        self.checks += 1
        if self.on_check:
            self.on_check()
        return self.fenced

    def verify(self):
        return self.gate.verify(self.value, deadline=50)

    def stopped(self):
        return self.boundary.verify_baseline_stopped(self.value, deadline=50)

    def start(self, receipt):
        return self.boundary.start_old(self.value, receipt, deadline=50)

    def test_matching_projection_returns_only_non_authorizing_digest(self):
        receipt = self.verify()
        self.assertTrue(receipt["deployment_matches"])
        self.assertIs(receipt["start_authorized"], False)
        self.assertNotIn(b"SYNTHETIC_SECRET", durable.canonical(receipt))
        self.assertNotIn(b"/synthetic", durable.canonical(receipt))
        self.assertTrue(all(argv[:2] == ("/accepted/docker", "--host=unix:///accepted/disposable.sock")
                            for argv in self.docker.calls))
        self.assertEqual(sum(argv[-2] == "--format=" + deployment.FORMAT for argv in self.docker.calls), 3)

    def test_each_command_mount_environment_and_host_setting_drift_refuses(self):
        for key, value in (("path", "/other"), ("args", ["--other"]), ("config", {"Env": ["changed"]}),
                           ("host_config", {"Privileged": True}), ("mounts", []),
                           ("object_id", "f" * 64), ("image_id", "sha256:" + "f" * 64)):
            with self.subTest(key=key):
                self.setUp()
                self.docker.value[key] = value
                with self.assertRaises(durable.Rejected):
                    self.verify()

    def test_reordered_mapping_keys_match_but_argument_and_mount_order_are_exact(self):
        self.docker.value = dict(reversed(list(self.docker.value.items())))
        self.verify()
        self.docker.value["args"].reverse()
        with self.assertRaises(durable.Rejected):
            self.verify()

    def test_running_or_ambiguous_old_object_cannot_pass(self):
        for update in ({"running": True, "status": "running"}, {"paused": True}, {"restarting": True},
                       {"dead": True}, {"restart_policy": "always"}, {"auto_remove": True}):
            with self.subTest(update=update):
                self.setUp()
                self.docker.state.update(update)
                with self.assertRaises(durable.Rejected):
                    self.verify()

    def test_final_fence_callback_cannot_hide_a_running_old_object(self):
        def mutate():
            if self.checks == 3:
                self.docker.state.update(running=True, status="running")
        self.on_check = mutate
        with self.assertRaises(durable.Rejected):
            self.verify()
        self.assertEqual(self.checks, 3)

    def test_final_fence_callback_cannot_hide_configuration_drift(self):
        def mutate():
            if self.checks == 3:
                self.docker.value["mounts"] = []
        self.on_check = mutate
        with self.assertRaises(durable.Rejected):
            self.verify()
        self.assertEqual(self.checks, 3)

    def test_final_projection_cannot_change_original_binding(self):
        for target in ("approval", "intent", "object", "image"):
            with self.subTest(target=target):
                self.setUp()
                reached = []
                def mutate(argv):
                    if len(self.docker.calls) != 6:
                        return
                    self.assertEqual(argv[-2], "--format=" + deployment.FORMAT)
                    reached.append(target)
                    if target == "approval":
                        self.gate.approval = replace(self.gate.approval, intent_sha256="0" * 64)
                    elif target == "intent":
                        self.value["package_sha256"] = "0" * 64
                    elif target == "object":
                        self.gate.objects.old_object_id = "0" * 64
                    else:
                        self.gate.objects.old_image_id = "0" * 64
                self.docker.hook = mutate
                with self.assertRaises(durable.Rejected):
                    self.verify()
                self.assertEqual(reached, [target])
                self.docker.hook = None
                with self.assertRaises(durable.Rejected):
                    self.verify()

    def test_final_projection_cannot_replace_the_object_reader(self):
        original = self.gate.objects
        def replace_reader(argv):
            if len(self.docker.calls) == 6:
                self.gate.objects = copy.copy(original)
        self.docker.hook = replace_reader
        with self.assertRaises(durable.Rejected):
            self.verify()
        self.assertIsNot(self.gate.objects, original)
        self.assertEqual(len(self.docker.calls), 6)

    def test_final_deadline_read_cannot_change_the_original_binding(self):
        reached = []
        def clock():
            if len(self.docker.calls) == 6:
                reached.append("final-clock")
                self.value["package_sha256"] = "0" * 64
            return self.time
        self.gate.clock = clock
        with self.assertRaises(durable.Rejected):
            self.verify()
        self.assertEqual(reached, ["final-clock"])

    def test_original_observer_configuration_cannot_be_rebound(self):
        for phase in ("fence", "first-state", "final-projection", "before-start"):
            for target in ("check", "clock", "transport", "endpoint", "reader-clock", "reader-fence"):
                with self.subTest(phase=phase, target=target):
                    self.setUp()
                    reached = []
                    def replace_observer():
                        reached.append((phase, target))
                        if target == "check":
                            self.gate.check = lambda **kwargs: True
                        elif target == "clock":
                            self.gate.clock = lambda: self.time
                        elif target == "transport":
                            self.gate.objects.commands = copy.copy(self.docker)
                        elif target == "endpoint":
                            self.gate.objects.prefix = ("/accepted/docker", "--host=unix:///other.sock")
                        elif target == "reader-clock":
                            self.gate.objects.clock = lambda: self.time
                        else:
                            self.gate.objects.start_fence = lambda: True
                    if phase == "before-start":
                        receipt = self.stopped()
                        replace_observer()
                        with self.assertRaises(durable.Rejected):
                            self.start(receipt)
                        self.assertEqual(self.oracle.starts, 0)
                    else:
                        if phase == "fence":
                            self.on_check = replace_observer
                        else:
                            def change(argv):
                                if len(self.docker.calls) == (1 if phase == "first-state" else 6):
                                    replace_observer()
                            self.docker.hook = change
                        with self.assertRaises(durable.Rejected):
                            self.verify()
                    self.assertEqual(reached, [(phase, target)])
                    self.assertTrue(self.gate.failed)
                    with self.assertRaises(durable.Rejected):
                        self.verify()

    def test_caught_reentrant_deployment_observation_poisoning(self):
        reached = []
        def reenter():
            with self.assertRaises(durable.Rejected):
                self.verify()
            reached.append(True)
        self.on_check = reenter
        with self.assertRaises(durable.Rejected):
            self.verify()
        self.assertEqual(reached, [True])
        self.assertEqual(self.docker.calls, [])
        self.assertTrue(self.gate.failed)

    def test_clock_cannot_move_backwards_between_observation_and_start(self):
        receipt = self.stopped()
        calls = len(self.docker.calls)
        self.time = 0
        with self.assertRaises(durable.Rejected):
            self.start(receipt)
        self.assertEqual(len(self.docker.calls), calls)
        self.assertEqual(self.oracle.starts, 0)
        self.assertTrue(self.gate.failed)

    def test_final_clock_callback_cannot_replace_original_fence(self):
        reached = []
        def clock():
            if len(self.docker.calls) == 6:
                reached.append(True)
                self.gate.check = lambda **kwargs: True
            return self.time
        self.gate.clock = clock
        with self.assertRaises(durable.Rejected):
            self.verify()
        self.assertEqual(reached, [True])
        self.assertTrue(self.gate.failed)

    def test_transport_replacement_refuses_before_next_projection(self):
        reached, replacement_calls = [], []
        transport = copy.copy(self.docker)
        transport.run = lambda *args, **kwargs: replacement_calls.append(True)
        def replace_transport(argv):
            reached.append(True)
            self.gate.objects.commands = transport
        self.docker.hook = replace_transport
        with self.assertRaises(durable.Rejected):
            self.verify()
        self.assertEqual(reached, [True])
        self.assertEqual(replacement_calls, [])
        self.assertEqual(len(self.docker.calls), 1)

    def test_unchanged_observers_reused_with_original_clock_and_same_deadline(self):
        first = self.verify()
        self.time = 2
        self.assertEqual(self.verify(), first)
        receipt = self.stopped()
        self.time = 3
        self.assertIs(self.start(receipt), True)
        self.assertEqual(self.oracle.starts, 1)
        self.assertFalse(self.gate.failed)

    def test_false_numeric_or_lost_fence_poison_gate(self):
        for flag in (False, 1, None):
            with self.subTest(flag=flag):
                self.setUp()
                self.fenced = flag
                with self.assertRaises(durable.Rejected):
                    self.verify()
                self.fenced = True
                with self.assertRaises(durable.Rejected):
                    self.verify()
                self.assertEqual(self.docker.calls, [])

    def test_changed_intent_and_each_approval_pin_refuse_before_daemon(self):
        for field in ("intent_sha256", "old_image_id", "projection_sha256"):
            with self.subTest(field=field):
                self.setUp()
                self.gate.approval = replace(self.gate.approval, **{field: "0" * 64})
                with self.assertRaises(durable.Rejected):
                    self.verify()
        self.setUp()
        self.value["baseline_sha256"] = "0" * 64
        with self.assertRaises(durable.Rejected):
            self.verify()
        self.assertEqual(self.docker.calls, [])

    def test_callback_cannot_replace_approval_or_mutate_original_intent(self):
        for target in ("approval", "intent"):
            with self.subTest(target=target):
                self.setUp()
                def mutate():
                    if target == "approval":
                        self.gate.approval = replace(self.gate.approval, projection_sha256="0" * 64)
                    else:
                        self.value["baseline_sha256"] = "0" * 64
                self.on_check = mutate
                with self.assertRaises(durable.Rejected):
                    self.verify()
                self.assertEqual(self.docker.calls, [])

    def test_malformed_private_or_oversized_output_has_fixed_error(self):
        for raw in (b"private error", b"", b"{}", b'{"a":1,"a":2}', b"x" * 65537):
            with self.subTest(length=len(raw)):
                self.setUp()
                self.docker.value = raw
                with self.assertRaisesRegex(durable.Rejected, "^deployment-observation-unconfirmed$"):
                    self.verify()

    def test_matching_pin_does_not_excuse_wrong_projection_types(self):
        for key, value in (("config", []), ("host_config", None), ("mounts", [{}]), ("args", [1]),
                           ("path", ""), ("extra", "not-allowed")):
            with self.subTest(key=key):
                self.setUp()
                self.docker.value[key] = value
                self.gate.approval = replace(self.gate.approval,
                    projection_sha256=durable.digest(durable.canonical(self.docker.value)))
                with self.assertRaises(durable.Rejected):
                    self.verify()

    def test_daemon_failure_and_deadline_or_clock_loss_are_not_matches(self):
        for mode in ("io", "deadline", "clock"):
            with self.subTest(mode=mode):
                self.setUp()
                def lose(_):
                    if mode == "io":
                        raise OSError("private daemon failure")
                    self.time = 50 if mode == "deadline" else 0
                self.docker.hook = lose
                with self.assertRaisesRegex(durable.Rejected, "^deployment-observation-unconfirmed$"):
                    self.verify()

    def test_incomplete_existing_oracle_is_not_replaced_by_good_deployment(self):
        self.oracle.receipt["new_plugin_absent"] = False
        with self.assertRaises(durable.Rejected):
            self.stopped()
        self.assertEqual(self.docker.calls, [])
        self.assertEqual(self.oracle.starts, 0)

    def test_callback_cannot_change_an_already_validated_oracle_receipt(self):
        self.on_check = lambda: self.oracle.receipt.update(new_plugin_absent=False)
        receipt = self.stopped()
        self.assertIs(receipt["new_plugin_absent"], True)

    def test_valid_oracle_plus_fresh_deployment_delegates_start_once(self):
        receipt = self.stopped()
        calls = len(self.docker.calls)
        self.assertTrue(self.start(receipt))
        self.assertGreater(len(self.docker.calls), calls)
        with self.assertRaises(durable.Rejected):
            self.start(receipt)
        self.assertEqual(self.oracle.starts, 1)

    def test_configuration_change_between_oracle_and_start_prevents_start(self):
        receipt = self.stopped()
        self.docker.value["mounts"] = []
        with self.assertRaises(durable.Rejected):
            self.start(receipt)
        self.assertEqual(self.oracle.starts, 0)

    def test_changed_receipt_or_intent_cannot_delegates_start(self):
        for target in ("receipt", "intent"):
            with self.subTest(target=target):
                self.setUp()
                receipt = self.stopped()
                if target == "receipt":
                    receipt["original_image"] = False
                else:
                    self.value["baseline_sha256"] = "0" * 64
                with self.assertRaises(durable.Rejected):
                    self.start(receipt)
                self.assertEqual(self.oracle.starts, 0)

    def test_lost_start_response_cannot_reuse_verification(self):
        receipt = self.stopped()
        self.oracle.lost = True
        with self.assertRaises(durable.Rejected):
            self.start(receipt)
        with self.assertRaises(durable.Rejected):
            self.start(receipt)
        self.assertEqual(self.oracle.starts, 1)

    def test_real_local_helper_uses_only_fixed_inspection_argv(self):
        with tempfile.TemporaryDirectory(prefix="deployment-helper-") as root:
            helper = Path(root) / "docker-fixture"
            helper.write_text("#!" + sys.executable + " -I\nimport sys\n"
                + "expected=" + repr(self.gate.objects.prefix[1]) + "\n"
                + "assert sys.argv[1] == expected\nassert sys.argv[2:4] == ['container','inspect']\n"
                + "assert sys.argv[-1] == " + repr(self.value["old_object_id"]) + "\n"
                + "projection=" + repr(durable.canonical(projection())) + "\n"
                + "state=" + repr(durable.canonical(self.docker.state)) + "\n"
                + "fmt=" + repr("--format=" + deployment.FORMAT) + "\n"
                + "sys.stdout.buffer.write(projection if sys.argv[-2] == fmt else state)\n")
            helper.chmod(0o700)
            transport = commands.LocalCommands()
            objects = self.gate.objects
            objects.prefix = (str(helper), objects.prefix[1])
            objects.commands, objects.clock = transport, time.monotonic
            self.gate.clock = time.monotonic
            self.gate.check = lambda **_: True
            result = self.gate.verify(self.value, deadline=time.monotonic() + 10)
            self.assertIs(result["start_authorized"], False)
            transport.reap()
            self.assertEqual(transport.pending, [])

    def test_coordinator_recovery_requires_actual_gate_before_old_start(self):
        for drift in (False, True):
            with self.subTest(drift=drift):
                self.setUp()
                fixture = test_coordinator.CoordinatorTests()
                fixture.setUp()
                try:
                    fixture.admit()
                    self.gate.approval = replace(self.gate.approval,
                        intent_sha256=durable.digest(durable.canonical(fixture.log.intent)))
                    self.docker.deadline = None
                    self.gate.clock = self.gate.objects.clock = lambda: fixture.time
                    def check(*, deadline):
                        fixture.engine.meter.check(deadline)
                        return True
                    self.gate.check = check
                    fixture.engine.boundary = deployment.RecoveredDeploymentBoundary(fixture.boundary, self.gate)
                    fixture.boundary.overrides["mutate"] = durable.Rejected("synthetic-forward-failure")
                    if drift:
                        self.docker.value["mounts"] = []
                    result = fixture.engine.forward()
                    self.assertEqual(result["outcome"], "recovery_unresolved" if drift else "baseline_restored")
                    self.assertEqual("start-old" in fixture.boundary.calls, not drift)
                    self.assertEqual((fixture.state / "recovery-outcome.json").exists(), not drift)
                    self.assertTrue(result["start_fenced"])
                    self.assertTrue(fixture.notices)
                    self.assertEqual(fixture.file.read_bytes(), b"original-baseline-config")
                    self.assertFalse(result["production_acceptance"])
                finally:
                    fixture.doCleanups()

    def test_failed_and_repeated_oracle_calls_do_not_reenter(self):
        self.stopped()
        calls = len(self.docker.calls)
        with self.assertRaises(durable.Rejected):
            self.stopped()
        self.assertEqual(len(self.docker.calls), calls)
        with self.assertRaises(durable.Rejected):
            self.start(copy.deepcopy(self.oracle.receipt))
        self.assertEqual(self.oracle.starts, 0)
