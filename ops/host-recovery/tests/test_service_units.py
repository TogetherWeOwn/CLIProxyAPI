"""Offline unit/owned-file components, never installed-manager authority proof."""
import copy
from dataclasses import replace
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from host_recovery import durable, service_anchor, service_units
from host_recovery.jobs import recovery_unit
import service_entry
import supervise
import claim_worker
import test_launch

ROOT = Path(__file__).resolve().parent.parent


class ServiceUnitTests(unittest.TestCase):
    def setUp(self):
        self.unit = service_units.ServiceUnit("supervisor", "supervisor.service", "/usr/bin/python3",
            str(ROOT), "/etc/cpa-recovery/supervisor.json", 1000, 1000,
            ("/var/lib/cpa-recovery/content", "/run/cpa-recovery/alert"),
            ("/var/lib/cpa-recovery/journal", "/run/cpa-recovery/claim", "/run/cpa-recovery/receipts"))

    def worker(self):
        return replace(self.unit, role="worker", unit=recovery_unit("a" * 64),
            anchor="/etc/cpa-recovery/worker.json", read_write=())

    def test_deterministic_bytes_and_secret_free_receipt(self):
        raw = self.unit.render()
        self.assertEqual(raw, self.unit.render())
        self.assertEqual(raw, replace(self.unit, read_only=tuple(reversed(self.unit.read_only)),
                                      read_write=tuple(reversed(self.unit.read_write))).render())
        receipt = self.unit.receipt()
        self.assertEqual(receipt["unit_sha256"], durable.digest(raw))
        self.assertNotIn(str(ROOT), durable.canonical(receipt).decode())
        for key in ("installed", "recovery_authority", "installation_start_fence_proven", "production_acceptance"):
            self.assertIs(receipt[key], False)

    def test_fixed_exec_is_isolated_and_has_no_launch_digest_cycle(self):
        command = next(line for line in self.unit.render().decode().splitlines() if line.startswith("ExecStart="))
        self.assertEqual(command, "ExecStart=/usr/bin/python3 -I " + str(ROOT)
            + "/service_entry.py --role supervisor --anchor /etc/cpa-recovery/supervisor.json")
        for forbidden in ("--sha256", "--deadline", "Environment", "%", "$", "/bin/sh"):
            self.assertNotIn(forbidden, self.unit.render().decode())
        self.assertNotIn("[Install]", self.unit.render().decode())

    def test_whole_group_unprivileged_no_restart_and_no_output_pipe(self):
        for unit in (self.unit, self.worker()):
            rows = dict(line.split("=", 1) for line in unit.render().decode().splitlines() if "=" in line)
            expected = {"Type": "exec", "User": "1000", "Group": "1000", "KillMode": "control-group",
                "SendSIGKILL": "yes", "Delegate": "no", "ProtectControlGroups": "yes",
                "NoNewPrivileges": "yes", "Restart": "no", "CapabilityBoundingSet": "",
                "AmbientCapabilities": "", "RestrictNamespaces": "yes", "ProtectSystem": "strict",
                "RestrictSUIDSGID": "yes", "WorkingDirectory": "/", "StandardOutput": "null",
                "StandardError": "null", "RestrictAddressFamilies": "AF_UNIX"}
            for key, value in expected.items():
                self.assertEqual(rows[key], value, key)
            self.assertFalse(any(key in rows for key in ("ExecStartPre", "ExecStopPost", "EnvironmentFile")))
        self.assertNotEqual(self.unit.unit, self.worker().unit)
        self.assertIn(b"ReadWritePaths=\n", self.worker().render())
        for dependency in (b"BindsTo=", b"PartOf=", b"Requires=", b"OnFailure="):
            self.assertNotIn(dependency, self.worker().render())

    def test_literal_paths_refuse_systemd_expansion_and_path_modifiers(self):
        for path in ("/", "/etc/a b", "/etc/%i", "/etc/$X", "/etc/a\nExecStart=/bin/false",
                     "/etc/../root", "/etc//a", "/etc/a\\b", "-/etc/a", "/etc/\"a\"", "/etc/a;"):
            for field in ("python", "package", "anchor"):
                with self.subTest(path=path, field=field), self.assertRaises(durable.Rejected):
                    replace(self.unit, **{field: path})

    def test_unprivileged_owner_and_fixed_role_instances_required(self):
        for change in ({"uid": 0}, {"gid": 0}, {"uid": True}, {"uid": -1}, {"gid": 2 ** 32},
                       {"role": "recover"}, {"unit": "a.timer"}, {"unit": "a\n.service"},
                       {"unit": "cpa-recovery@a.service"}, {"role": "worker"}):
            with self.subTest(change=change), self.assertRaises(durable.Rejected):
                replace(self.unit, **change)
        self.worker()

    def test_readonly_inputs_code_interpreter_and_anchor_cannot_be_writable(self):
        for path in (self.unit.package, "/usr", "/etc/cpa-recovery", self.unit.anchor,
                     self.unit.read_only[0], self.unit.read_only[0] + "/child", "/var/lib"):
            with self.subTest(path=path), self.assertRaises(durable.Rejected):
                replace(self.unit, read_write=(path,))

    def test_path_set_ambiguity_and_identity_worker_writes_refuse(self):
        for change in ({"read_only": []}, {"read_write": []}, {"read_write": ("/run/a", "/run/a/sub")},
                       {"read_only": ("/run/a", "/run/a")}, {"read_write": ("-/run/a",)},
                       {"read_only": tuple("/run/" + str(n) for n in range(33))}):
            with self.subTest(change=change), self.assertRaises(durable.Rejected):
                replace(self.unit, **change)
        with self.assertRaises(durable.Rejected):
            replace(self.worker(), read_write=("/run/output",))

    @unittest.skipUnless(shutil.which("systemd-analyze"), "offline systemd verifier unavailable")
    def test_actual_systemd_parser_accepts_both_units_without_manager_contact(self):
        with tempfile.TemporaryDirectory(prefix="recovery-unit-verify-") as temp:
            paths = []
            for unit in (self.unit, self.worker()):
                path = Path(temp) / unit.unit
                path.write_bytes(unit.render())
                paths.append(str(path))
            result = subprocess.run(["systemd-analyze", "verify", "--man=no", *paths],
                capture_output=True, timeout=20, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())


class ServiceAnchorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_launch.LaunchTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.path = self.fixture.fixture.root / "service-anchor.json"
        self.arguments = {"approval": str(self.fixture.path), "sha256": self.fixture.pin,
            "uid": os.geteuid(), "gid": os.getegid(), "endpoint": "/run/cpa-recovery/claim",
            "endpoint-device": 1, "endpoint-inode": 2, "deadline": 1170.0}
        self.value = {"schema": "host-recovery-service-anchor-v1", "role": "worker",
            "unit": recovery_unit(self.fixture.approval.job.request_id), "arguments": self.arguments}
        self.save()

    def save(self, value=None):
        self.path.write_bytes(durable.canonical(self.value if value is None else value))
        self.path.chmod(0o600)

    def read(self):
        # This explicitly models an installer owner with the test user's UID.
        # Only read_service_anchor's fixed root:root boundary is used by the CLI.
        return service_anchor._read_anchor(str(self.path), role=self.value["role"], uid=os.geteuid(), gid=os.getegid())

    def supervisor(self):
        return {**self.value, "role": "supervisor", "unit": self.fixture.approval.supervisor.unit,
            "arguments": {**self.arguments, "alert-endpoint": "/run/cpa-recovery/alert",
                "alert-endpoint-device": 1, "alert-endpoint-inode": 3,
                "alert-receipts": "/run/cpa-recovery/receipts", "alert-receipts-device": 1,
                "alert-receipts-inode": 4, "alert-route": "route-a", "listener-uid": 1000,
                "listener-instance": "listener-a", "alert-deadline": 1180.0}}

    def test_owned_file_readback_and_argv_roundtrip_preserve_bytes(self):
        before = self.fixture.fixture.state()
        self.assertEqual(self.read(), self.value)
        args = service_anchor.anchor_argv(self.read())
        self.assertEqual(args[args.index("--sha256") + 1], self.fixture.pin)
        self.assertEqual(args[args.index("--deadline") + 1], "1170.0")
        self.assertEqual(self.fixture.fixture.state(), before)

    def test_public_reader_and_real_cli_reject_unprivileged_anchor(self):
        with self.assertRaises(durable.Rejected):
            service_anchor.read_service_anchor(str(self.path), role="worker")
        before = self.fixture.fixture.state()
        result = subprocess.run([sys.executable, "-I", str(ROOT / "service_entry.py"),
            "--role", "worker", "--anchor", str(self.path)], capture_output=True, timeout=10,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "CPA_ANCHOR_UID": str(os.geteuid())})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout + result.stderr, b"")
        self.assertEqual(self.fixture.fixture.state(), before)

    def test_no_cli_owner_override_or_configured_execution_role(self):
        for extra in (["--uid", str(os.geteuid())], ["--role", "recover"], ["--callback", "os.system"]):
            result = subprocess.run([sys.executable, "-I", str(ROOT / "service_entry.py"),
                "--role", "worker", "--anchor", str(self.path), *extra], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr, b"host-recovery-service: invalid-arguments\n")

    def test_worker_and_supervisor_anchor_schemas_do_not_accept_extra_arguments(self):
        for value in (self.value, self.supervisor()):
            self.assertEqual(service_anchor.parse_anchor(durable.canonical(value), role=value["role"]), value)
            for name in ("module", "execution", "callback", "help", "anchor", "role"):
                changed = copy.deepcopy(value)
                changed["arguments"][name] = "anything"
                with self.subTest(role=value["role"], field=name), self.assertRaises(durable.Rejected):
                    service_anchor.parse_anchor(durable.canonical(changed), role=value["role"])
            for field in value["arguments"]:
                changed = copy.deepcopy(value)
                del changed["arguments"][field]
                with self.subTest(missing=field), self.assertRaises(durable.Rejected):
                    service_anchor.parse_anchor(durable.canonical(changed), role=value["role"])

    def test_wrong_role_schema_unknown_field_and_bad_numeric_values_refuse(self):
        for changes in ({"role": "supervisor"}, {"schema": "other"}, {"extra": True}, {"unit": "x.socket"},
                        {"arguments": []}):
            with self.subTest(changes=changes), self.assertRaises(durable.Rejected):
                service_anchor.parse_anchor(durable.canonical({**self.value, **changes}), role="worker")
        for name, values in {"uid": [0, True, -1, "1000", 2 ** 31], "gid": [0],
                             "endpoint-inode": [0, -1, 2 ** 64, True], "endpoint-device": [-1, 2 ** 64],
                             "sha256": ["x"], "deadline": [0, -1, True, "1170"],
                             "approval": ["/etc/%i", "/etc/a\nsecret", "/etc/$X"]}.items():
            for item in values:
                changed = copy.deepcopy(self.value)
                changed["arguments"][name] = item
                with self.subTest(name=name, item=item), self.assertRaises(durable.Rejected):
                    service_anchor.parse_anchor(durable.canonical(changed), role="worker")

    def test_unsafe_leaf_permissions_links_and_changed_readback_refuse(self):
        self.path.chmod(0o666)
        with self.assertRaises(durable.Rejected):
            self.read()
        self.path.chmod(0o600)
        link = self.path.with_name("anchor-link.json")
        link.symlink_to(self.path)
        with self.assertRaises((durable.Rejected, OSError)):
            service_anchor._read_anchor(str(link), role="worker", uid=os.geteuid(), gid=os.getegid())
        original = service_anchor.read_file
        calls = []
        def changed(*args, **kwargs):
            calls.append(True)
            if len(calls) == 2:
                self.save({**self.value, "unit": "different.service"})
            return original(*args, **kwargs)
        with patch.object(service_anchor, "read_file", side_effect=changed), self.assertRaisesRegex(durable.Rejected, "anchor-changed"):
            self.read()
        self.assertEqual(len(calls), 2)

    def test_anchor_directory_and_file_descriptors_close_after_refusal(self):
        before = len(os.listdir("/proc/self/fd"))
        self.save({**self.value, "role": "other"})
        with self.assertRaises(durable.Rejected):
            self.read()
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_entry_routes_only_fixed_existing_cli_and_preserves_original_arguments(self):
        for value, runner in ((self.value, claim_worker), (self.supervisor(), supervise)):
            with patch.object(service_entry, "read_service_anchor", return_value=value), patch.object(runner, "main", return_value=3) as run:
                self.assertEqual(service_entry.main(["--role", value["role"], "--anchor", "/etc/cpa/anchor.json"]), 3)
                run.assert_called_once_with(service_anchor.anchor_argv(value))

    def test_entry_wrong_unit_or_launch_pin_refuses_before_runner(self):
        for changes in ({"unit": "wrong.service"}, {"arguments": {**self.arguments, "sha256": "0" * 64}}):
            with patch.object(service_entry, "read_service_anchor", return_value={**self.value, **changes}), patch.object(claim_worker, "main") as run:
                self.assertEqual(service_entry.main(["--role", "worker", "--anchor", "/etc/cpa/anchor.json"]), 1)
                run.assert_not_called()
