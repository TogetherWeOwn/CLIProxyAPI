"""Owned filesystem/CLI components; manager identity is scripted, not systemd."""
import copy
from dataclasses import asdict, replace
import errno
import fcntl
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import bootstrap, durable, launch, manager
from host_recovery.bootstrap import SupervisorBinding
import test_bootstrap
import test_installation as fixtures
from test_manager import encoded, observed

ROOT = Path(__file__).resolve().parent.parent


class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.InstallationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.args = self.fixture.seed()
        self.path = self.fixture.root / "approval.json"
        self.approval = launch.LaunchApproval(self.fixture.approval, self.args["content_approval"],
            self.args["recovery_approval"], SupervisorBinding("supervisor.service", "/synthetic/supervisor.service",
                "a" * 64, "b" * 64, os.geteuid(), os.getegid()), self.args["binding"], "/usr/bin/systemctl")
        self.value = {"schema": "host-recovery-launch-v1", **asdict(self.approval)}
        self.save()
        self.now = 1050.0
        self.observer = unittest.mock.Mock()
        self.observer.bootstrap.return_value = {"owner": self.args["supervisor_owner"]}
        self.observer.observe_owner.return_value = self.args["supervisor_owner"]

    def save(self, value=None):
        self.raw = durable.canonical(self.value if value is None else value)
        self.path.write_bytes(self.raw)
        self.path.chmod(0o600)
        self.pin = durable.digest(self.raw)

    def load(self, **kwargs):
        return launch.load_launch(str(self.path), **{"sha256": self.pin, "uid": os.geteuid(),
                                                    "gid": os.getegid(), **kwargs})

    def status(self, **kwargs):
        with patch.object(launch, "SystemdSupervisorIdentity", return_value=self.observer):
            return launch.inspect_status(self.load(), deadline=1170.0, clock=lambda: self.now,
                                         boot_id=lambda: "boot-a", **kwargs)

    def test_pinned_launch_roundtrip_does_not_mutate_sources(self):
        before = self.fixture.state()
        self.assertEqual(self.load(), self.approval)
        self.assertEqual(self.fixture.state(), before)

    def test_external_anchor_not_adjacent_values_is_required(self):
        with self.assertRaisesRegex(durable.Rejected, "pin-mismatch"):
            self.load(sha256="0" * 64)
        self.path.write_bytes(self.raw.replace(b"installation-a", b"installation-b"))
        with self.assertRaisesRegex(durable.Rejected, "pin-mismatch"):
            self.load()

    def test_bad_digest_or_numeric_owner_refuses(self):
        for changes in ({"sha256": "x"}, {"uid": True}, {"gid": -1}, {"uid": os.geteuid() + 1},
                        {"gid": os.getegid() + 1}):
            with self.subTest(changes=changes), self.assertRaises(durable.Rejected):
                self.load(**changes)

    def test_unknown_missing_and_wrong_typed_top_fields_refuse(self):
        for key in self.value:
            value = copy.deepcopy(self.value)
            del value[key]
            with self.subTest(missing=key), self.assertRaises(durable.Rejected):
                launch.parse_launch(durable.canonical(value))
        for changes in ({"extra": True}, {"schema": "other"}, {"installation": None}, {"content": []},
                        {"recovery": True}, {"supervisor": "secret"}, {"job": {}}):
            with self.subTest(changes=changes), self.assertRaises(durable.Rejected):
                launch.parse_launch(durable.canonical({**self.value, **changes}))

    def test_exact_nested_fields_and_duplicate_json_keys_refuse(self):
        for key in ("installation", "content", "recovery", "supervisor", "job"):
            value = copy.deepcopy(self.value)
            value[key]["unexpected"] = "secret"
            with self.subTest(key=key), self.assertRaises(durable.Rejected):
                launch.parse_launch(durable.canonical(value))
        with self.assertRaises(durable.Rejected):
            launch.parse_launch(self.raw[:-2] + b',"schema":"host-recovery-launch-v1"}\n')

    def test_cross_bound_owners_and_installation_refuse(self):
        for changes in ({"installation": replace(self.approval.installation, installation_id="other")},
                        {"content": replace(self.approval.content, uid=os.geteuid() + 1)},
                        {"recovery": replace(self.approval.recovery, gid=os.getegid() + 1)},
                        {"supervisor": replace(self.approval.supervisor, uid=os.geteuid() + 1)},
                        {"job": {}}, {"installation": {}}):
            with self.subTest(changes=changes), self.assertRaises(durable.Rejected):
                replace(self.approval, **changes)

    def test_explicit_canonical_systemctl_path_required(self):
        for value in (None, "relative", "/", "/usr//bin/systemctl", "/usr/../bin/systemctl", "/x\0y", "/x/"):
            with self.subTest(value=value), self.assertRaises(durable.Rejected):
                replace(self.approval, systemctl=value)

    def test_unsafe_configuration_modes_refuse(self):
        for mode in (0o666, 0o660, 0o700, 0o4600):
            self.path.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(durable.Rejected):
                self.load()
        self.path.chmod(0o600)

    def test_symlink_hardlink_and_fifo_refuse(self):
        self.path.rename(self.fixture.root / "target")
        self.path.symlink_to("target")
        with self.assertRaises(OSError):
            self.load()
        self.path.unlink()
        os.link(self.fixture.root / "target", self.path)
        with self.assertRaises(durable.Rejected):
            self.load()
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(durable.Rejected):
            self.load()

    def test_writable_or_linked_parent_refuses(self):
        self.fixture.root.chmod(0o770)
        with self.assertRaises(durable.Rejected):
            self.load()
        self.fixture.root.chmod(0o700)
        link = self.fixture.root / "link"
        link.symlink_to(self.fixture.root, target_is_directory=True)
        with self.assertRaises((OSError, durable.Rejected)):
            launch.load_launch(str(link / self.path.name), sha256=self.pin, uid=os.geteuid(), gid=os.getegid())

    def test_oversized_and_malformed_configuration_refuse(self):
        for raw in (b"x" * 65537, b"{", b"[]", b'{"schema":NaN}'):
            self.path.write_bytes(raw)
            with self.subTest(size=len(raw)), self.assertRaises(durable.Rejected):
                launch.load_launch(str(self.path), sha256=durable.digest(raw), uid=os.geteuid(), gid=os.getegid())

    def test_configuration_replaced_after_parse_refuses(self):
        actual = launch.parse_launch
        def changed(raw):
            result = actual(raw)
            self.path.rename(self.fixture.root / "old-approval")
            self.path.write_bytes(raw)
            self.path.chmod(0o600)
            return result
        with patch.object(launch, "parse_launch", side_effect=changed):
            with self.assertRaisesRegex(durable.Rejected, "configuration-changed"):
                self.load()

    def test_ancestor_replaced_after_parse_refuses(self):
        actual = launch.parse_launch
        def changed(raw):
            result = actual(raw)
            moved = self.fixture.root / "moved"
            self.fixture.content.rename(moved)
            # Replace the approval's parent edge, while keeping identical bytes.
            old = self.fixture.root.with_name(self.fixture.root.name + "-old")
            self.fixture.root.rename(old)
            self.addCleanup(lambda: old.rename(self.fixture.root))
            self.fixture.root.mkdir(mode=0o700)
            self.addCleanup(self.fixture.root.rmdir)
            return result
        with patch.object(launch, "parse_launch", side_effect=changed):
            with self.assertRaisesRegex(durable.Rejected, "directory-changed"):
                self.load()

    def test_read_failure_closes_all_open_descriptors(self):
        before = len(os.listdir("/proc/self/fd"))
        for number in (errno.EIO, errno.ENOSPC):
            with patch.object(launch, "read_file", side_effect=OSError(number, "restricted-secret-path")):
                with self.assertRaises(OSError):
                    self.load()
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_status_uses_loaded_approvals_without_any_grant(self):
        before = self.fixture.state()
        value = self.status()
        self.assertEqual(value["state"], "inputs_verified_only")
        for key in ("complete_fence_proven", "recovery_execution_allowed", "start_allowed",
                    "terminal_outcome_verified", "production_acceptance"):
            self.assertIs(value[key], False)
        self.assertEqual(value["request_id"], self.approval.job.request_id)
        self.assertEqual(self.fixture.state(), before)
        self.assertNotIn(str(self.fixture.root), durable.canonical(value).decode())
        self.observer.bootstrap.assert_called_once_with(installation_id="installation-a",
            attempt_id=self.approval.recovery.attempt_id, deadline=1170.0)
        self.observer.observe_owner.assert_called_once_with(self.args["supervisor_owner"], deadline=1170.0)

    def test_status_holds_existing_installation_lock_during_reobservation(self):
        def observe(*args, **kwargs):
            with durable.directory(str(self.fixture.journal), private=True) as fd:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.observer.observe_owner.side_effect = observe
        self.status()
        with durable.directory(str(self.fixture.journal), private=True) as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_status_manager_failure_returns_no_status_and_releases_lock(self):
        self.observer.observe_owner.side_effect = durable.Rejected("restricted-secret")
        with self.assertRaises(durable.Rejected):
            self.status()
        with durable.directory(str(self.fixture.journal), private=True) as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_status_original_deadline_shortens_queries(self):
        with patch.object(launch, "SystemdSupervisorIdentity", return_value=self.observer):
            value = launch.inspect_status(self.load(), deadline=1500.0, clock=lambda: self.now,
                                          boot_id=lambda: "boot-a")
        self.observer.observe_owner.assert_called_once_with(self.args["supervisor_owner"], deadline=1180.0)
        self.assertFalse(value["start_allowed"])

    def test_status_deadline_missed_during_manager_query_never_returns_green(self):
        self.observer.observe_owner.side_effect = lambda *a, **kw: setattr(self, "now", 1180.0)
        with self.assertRaises(durable.Rejected):
            self.status()

    def test_status_content_change_during_manager_query_refuses(self):
        self.observer.observe_owner.side_effect = lambda *a, **kw: (self.fixture.content / "settings.json").write_bytes(b"bad")
        with self.assertRaises(durable.Rejected):
            self.status()

    def test_status_original_request_change_during_manager_query_refuses(self):
        def changed(*args, **kwargs):
            path = self.fixture.journal / "reconcile-request.json"
            value = durable.decode(path.read_bytes())
            value["deadline"] = 1175.0
            value.pop("request_id")
            value["request_id"] = durable.digest(durable.canonical(value))
            path.write_bytes(durable.canonical(value))
        self.observer.observe_owner.side_effect = changed
        with self.assertRaises(durable.Rejected):
            self.status()

    def test_status_expired_or_wrong_supervisor_cannot_read_content(self):
        self.now = 1180.0
        with self.assertRaises(durable.Rejected):
            self.status()
        self.now = 1050.0
        self.observer.bootstrap.return_value = {"owner": {**self.args["supervisor_owner"], "invocation_id": "c" * 32}}
        with self.assertRaises(durable.Rejected):
            self.status()

    def manager_fixture(self):
        fragment = self.fixture.root / "supervisor.service"
        fragment.write_bytes(b"synthetic unit bytes, not installed\n")
        fragment.chmod(0o600)
        row = observed("supervisor.service", "b" * 32, "/recovery/supervisor.service")
        row.update(FragmentPath=str(fragment), Restart="on-failure", MainPID=str(os.getpid()),
                   User=str(os.geteuid()), Group=str(os.getegid()))
        binding = SupervisorBinding(row["Id"], str(fragment), durable.digest(fragment.read_bytes()),
            durable.digest(durable.canonical(manager.static_properties(row))), os.geteuid(), os.getegid())
        records = {name: durable.decode((self.fixture.journal / name).read_bytes())
                   for name in ("intent.json", "arm.json", "reconcile-request.json")}
        records["intent.json"]["owner"]["boot_id"] = test_bootstrap.BOOT
        intent_pin = durable.digest(durable.canonical(records["intent.json"]))
        records["arm.json"]["arm"]["boot_id"] = test_bootstrap.BOOT
        records["arm.json"]["intent_sha256"] = intent_pin
        request = records["reconcile-request.json"]
        request["owner"]["boot_id"] = request["original_arm"]["boot_id"] = test_bootstrap.BOOT
        request["intent_sha256"] = intent_pin
        request.pop("request_id")
        request["request_id"] = durable.digest(durable.canonical(request))
        for name, value in records.items():
            (self.fixture.journal / name).write_bytes(durable.canonical(value))
        self.approval = replace(self.approval, supervisor=binding,
            recovery=replace(self.approval.recovery, intent_sha256=intent_pin),
            job=replace(self.approval.job, request_id=request["request_id"]))
        self.value = {"schema": "host-recovery-launch-v1", **asdict(self.approval)}
        self.save()
        return row

    def test_status_composes_real_identity_parser_and_loaders_with_scripted_manager(self):
        row = self.manager_fixture()
        calls = []
        def command(argv, *, deadline):
            calls.append((argv, deadline))
            return encoded(row)
        actual = bootstrap.SystemdSupervisorIdentity
        def identity(**kwargs):
            return actual(**kwargs, read_process_cgroup=lambda pid: row["ControlGroup"])
        before = self.fixture.state()
        with patch.object(launch, "SystemdSupervisorIdentity", side_effect=identity):
            value = launch.inspect_status(self.load(), deadline=1170.0, clock=lambda: self.now,
                boot_id=lambda: test_bootstrap.BOOT, commands=SimpleNamespace(run=command))
        self.assertEqual(len(calls), 4)
        for argv, deadline in calls:
            self.assertEqual(argv, (self.approval.systemctl, "--no-pager", "show",
                "--property=" + ",".join(sorted(manager.PROPERTIES)), "--", "supervisor.service"))
            self.assertEqual(deadline, 1170.0)
        self.assertEqual(value["request_id"], self.approval.job.request_id)
        self.assertFalse(value["complete_fence_proven"])
        self.assertEqual(self.fixture.state(), before)

    def test_status_real_identity_parser_refuses_foreign_mainpid_before_loading(self):
        row = self.manager_fixture()
        row["MainPID"] = str(os.getpid() + 1)
        actual = bootstrap.SystemdSupervisorIdentity
        def identity(**kwargs):
            return actual(**kwargs, read_process_cgroup=lambda pid: row["ControlGroup"])
        with patch.object(launch, "SystemdSupervisorIdentity", side_effect=identity):
            with patch.object(launch, "open_installation") as roots:
                with self.assertRaisesRegex(durable.Rejected, "mainpid-unconfirmed"):
                    launch.inspect_status(self.load(), deadline=1170.0, clock=lambda: self.now,
                        boot_id=lambda: test_bootstrap.BOOT, commands=SimpleNamespace(run=lambda *a, **kw: encoded(row)))
        roots.assert_not_called()

    def test_cli_pin_failure_is_opaque_and_does_not_invoke_manager(self):
        proc = subprocess.run((sys.executable, "-I", str(ROOT / "status.py"), "--approval", str(self.path),
            "--sha256", "0" * 64, "--uid", str(os.geteuid()), "--gid", str(os.getegid()),
            "--deadline", "999999999999"), capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b"host-recovery-status: unavailable\n")
        self.assertNotIn(str(self.path).encode(), proc.stderr)

    def test_cli_invalid_arguments_do_not_echo_values(self):
        for args in (("--unknown", "restricted-secret"), ("--uid", "restricted-secret")):
            proc = subprocess.run((sys.executable, "-I", str(ROOT / "status.py"), *args),
                                  capture_output=True, timeout=10)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stdout, b"")
            self.assertEqual(proc.stderr, b"host-recovery-status: invalid-arguments\n")

    def test_cli_expired_deadline_does_not_read_configuration(self):
        proc = subprocess.run((sys.executable, "-I", str(ROOT / "status.py"), "--approval", "/nonexistent/secret",
            "--sha256", self.pin, "--uid", str(os.geteuid()), "--gid", str(os.getegid()), "--deadline", "0"),
            capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b"host-recovery-status: unavailable\n")
