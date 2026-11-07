"""Protected launch/evidence files; SCRIPTED bootstrap/peer/host boundaries."""
import copy
from dataclasses import replace
import errno
import fcntl
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import alert, commands, durable, installation, jobs, worker_runtime
from test_installation import approve
import test_launch

ROOT = Path(__file__).resolve().parent.parent


class WorkerRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_launch.LaunchTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.installation = self.fixture.fixture
        self.endpoint = self.installation.root / "ipc"
        self.endpoint.mkdir(mode=0o700)
        self.evidence = self.installation.root / "evidence"
        self.evidence.mkdir(mode=0o700)
        self.request_path = self.installation.journal / "reconcile-request.json"
        self.request = durable.decode(self.request_path.read_bytes())
        self.request["detection_upper_bound_seconds"] = 5.
        self.request.pop("request_id")
        self.request["request_id"] = durable.digest(durable.canonical(self.request))
        self.request_path.write_bytes(durable.canonical(self.request))
        self.approval = replace(self.fixture.approval,
            job=replace(self.fixture.approval.job, request_id=self.request["request_id"]))
        self.now, self.boot = 1005., "boot-a"
        self.claim = {"schema": "host-recovery-worker-claim-v1", "request_id": self.approval.job.request_id,
            "intent_sha256": self.approval.recovery.intent_sha256, "supervisor_owner": self.request["owner"],
            "worker": {"schema": "host-recovery-job-observation-v1", "request_id": self.approval.job.request_id,
                "boot_id": self.boot, "unit": jobs.recovery_unit(self.approval.job.request_id),
                "invocation_id": "c" * 32, "state": "running", "job_id": 0,
                "pid": os.getpid(), "cgroup": "/scripted/recovery.service"},
            "peer": {"pid": os.getpid(), "uid": os.geteuid(), "gid": os.getegid()}, "nonce": "scripted-nonce",
            "restoration_permission": False, "start_permission": False}
        self.calls, self.notices, self.captured = [], [], []
        self.before_peer, self.after_claim = lambda: None, lambda: None
        self.peer_ok = True
        self.after_peer_check = lambda: None
        test = self

        class Bootstrap:
            def __init__(self, **kwargs):
                test.assertEqual(kwargs["request"], test.request)
                self.result_receipt = None
                test.captured.append(self)

            def _verify_peer(self, **kwargs):
                test.before_peer()
                return copy.deepcopy(test.claim["worker"])

            def claim(self, path, *, deadline, recovery_provider=None):
                test.assertEqual(path, str(test.endpoint / ("claim-" + test.request["request_id"] + ".sock")))
                test.assertEqual(deadline, min(test.deadline, test.request["deadline"]))
                # The supervisor, not this worker, already owns the journal lock.
                with durable.directory(str(test.installation.journal), private=True) as fd:
                    with test.assertRaises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._verify_peer(peer={}, peer_alive=lambda: True, deadline=deadline)
                if recovery_provider is not None:
                    test.provider = recovery_provider
                    def check(**kwargs):
                        result = test.peer_ok
                        test.after_peer_check()
                        return result
                    self.report = recovery_provider(test.claim, deadline=deadline, check=check)
                    self.result_receipt = {"observed": True, "start_permission": False}
                test.after_claim()
                return copy.deepcopy(test.claim)

        self.bootstrap = Bootstrap
        self.provider = None
        self.override = lambda name: None

        class Boundary:
            def __getattr__(self, name):
                def call(*args, deadline, check):
                    test.calls.append(name)
                    test.assertTrue(check(deadline=deadline))
                    test.override(name)
                    test.assertTrue(check(deadline=deadline))
                    if name == "verify_baseline_stopped":
                        intent = args[0]
                        return {"baseline_sha256": intent["baseline_sha256"], "object_id": intent["old_object_id"],
                            "original_image": True, "original_replay": True, "new_plugin_absent": True,
                            "complete_write_set": True, "metadata_verified": True, "all_writers_stopped": True}
                    return True
                return call
        self.boundary = Boundary()
        self.deadline = 1170.

    def run_worker(self, execute=False, **changes):
        args = dict(endpoint=approve(self.endpoint), deadline=self.deadline,
                    clock=lambda: self.now, boot_id=lambda: self.boot,
                    commands=SimpleNamespace(run=lambda *args, **kwargs: b""))
        if execute:
            args.update(boundary=self.boundary, evidence=approve(self.evidence), persist_alert=lambda _: None,
                        transport_alert=lambda notice: self.notices.append(notice) or True)
        args.update(changes)
        with installation.open_installation(self.approval.installation), \
                patch.object(worker_runtime, "SystemdWorkerBootstrap", self.bootstrap):
            return worker_runtime.run_worker(self.approval, **args)

    def test_identity_entrypoint_loads_originals_without_lock_overlap_or_execution(self):
        before = self.installation.state()
        result = self.run_worker()
        self.assertEqual(result["operation"], "claim")
        self.assertEqual(result["state"], "identity_received_only")
        self.assertIsNone(result["result_receipt"])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.installation.state(), before)
        for key in ("start_permission", "recovery_completed", "installation_settled", "production_acceptance"):
            self.assertIs(result[key], False)
        raw = durable.canonical(result)
        for private in (str(self.installation.root), "scripted-nonce", "scripted/recovery", '"peer"'):
            self.assertNotIn(private.encode(), raw)

    def test_execution_composes_original_request_evidence_and_same_connection_report(self):
        before = {p.name: p.read_bytes() for p in self.installation.journal.iterdir()}
        result = self.run_worker(execute=True)
        self.assertEqual(result["state"], "report_acknowledged_unsettled")
        self.assertEqual(self.calls, ["authorize_worker_recovery", "fence", "quiesce", "validate_recovery",
            "restore_complete", "verify_baseline_stopped", "start_old", "old_ready"])
        raw = (self.evidence / ("worker-evidence-" + self.request["request_id"] + ".json")).read_bytes()
        self.assertEqual(durable.digest(raw), self.captured[0].report["evidence_sha256"])
        self.assertEqual(durable.decode(raw)["status"]["outcome"], "baseline_restored")
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.installation.journal.iterdir()})
        self.assertFalse(result["installation_settled"])

    def test_retained_provider_and_identity_validator_revoke_after_context_exit(self):
        self.run_worker(execute=True)
        with self.assertRaises(durable.Rejected):
            self.provider(self.claim, deadline=1170., check=lambda **kw: True)
        with self.assertRaisesRegex(durable.Rejected, "session-unavailable"):
            self.captured[0]._verify_peer(peer={}, peer_alive=lambda: True, deadline=1170.)

    def test_missing_execution_boundary_never_downgrades_to_identity_success(self):
        for changes in ({"boundary": None}, {"evidence": None}, {"persist_alert": None},
                        {"transport_alert": None}, {"persist_alert": True}):
            with self.subTest(changes=changes), self.assertRaises(durable.Rejected):
                self.run_worker(execute=True, **changes)
        self.assertEqual(self.captured, [])

    def test_separate_roots_required_in_both_directions_and_by_inode(self):
        for root in (approve(self.installation.journal), approve(self.installation.content),
                     approve(self.installation.root), approve(self.evidence)):
            with self.subTest(root=root.path), self.assertRaises(durable.Rejected):
                self.run_worker(execute=True, endpoint=root)
        self.assertEqual(self.captured, [])

    def test_endpoint_owner_mode_and_independent_inode_are_not_learned(self):
        root = approve(self.endpoint)
        for changes in ({"inode": root.inode + 1}, {"uid": root.uid + 1}, {"gid": root.gid + 1}, {"mode": 0o755}):
            with self.subTest(changes=changes), self.assertRaises(durable.Rejected):
                self.run_worker(endpoint=replace(root, **changes))
        self.assertEqual(self.captured, [])

    def test_request_content_or_arm_change_before_claim_validation_refuses(self):
        for name in ("intent.json", "arm.json", "reconcile-request.json"):
            path = self.installation.journal / name
            raw = path.read_bytes()
            self.before_peer = lambda: path.write_bytes(b"{}")
            with self.subTest(name=name), self.assertRaises(durable.Rejected):
                self.run_worker()
            path.write_bytes(raw)
        self.assertEqual(self.calls, [])

    def test_changed_content_after_claim_cannot_publish_identity_receipt(self):
        self.after_claim = lambda: (self.installation.content / "settings.json").write_bytes(b"changed")
        with self.assertRaises(durable.Rejected):
            self.run_worker()

    def test_snapshot_failure_is_sticky_even_if_bootstrap_swallows_it_and_repairs_bytes(self):
        raw = self.request_path.read_bytes()
        base = self.bootstrap
        test = self
        class Swallow(base):
            def claim(self, path, **kwargs):
                test.request_path.write_bytes(b"{}")
                with test.assertRaises(durable.Rejected):
                    self._verify_peer(peer={}, peer_alive=lambda: True, deadline=1170.)
                test.request_path.write_bytes(raw)
                return copy.deepcopy(test.claim)
        self.bootstrap = Swallow
        with self.assertRaisesRegex(durable.Rejected, "session-unavailable"):
            self.run_worker()

    def test_post_report_clock_boot_or_endpoint_loss_cannot_publish_result(self):
        for changed in (lambda: setattr(self, "now", 1170.), lambda: setattr(self, "boot", "other"),
                        lambda: self.endpoint.chmod(0o755)):
            with self.subTest(changed=changed):
                self.setUp()
                self.after_claim = changed
                with self.assertRaises((durable.Rejected, OSError)):
                    self.run_worker(execute=True)
                self.assertFalse((self.installation.journal / "recovery-outcome.json").exists())

    def test_input_drift_during_restore_revokes_before_start(self):
        def changed(name):
            if name == "restore_complete":
                self.request_path.write_bytes(b"{}")
        self.override = changed
        with self.assertRaises(durable.Rejected):
            self.run_worker(execute=True)
        self.assertNotIn("start_old", self.calls)
        self.assertTrue(self.notices)
        self.assertEqual(list(self.evidence.iterdir()), [])

    def test_live_peer_refusal_during_restore_blocks_later_start(self):
        self.override = lambda name: setattr(self, "peer_ok", False) if name == "restore_complete" else None
        with self.assertRaises(durable.Rejected):
            self.run_worker(execute=True)
        self.assertNotIn("start_old", self.calls)
        self.assertTrue(self.notices)

    def test_storage_read_faults_close_descriptors_without_bootstrapping(self):
        before = len(os.listdir("/proc/self/fd"))
        for code in (errno.EIO, errno.ENOSPC):
            with patch.object(worker_runtime, "read_file", side_effect=OSError(code, "synthetic")):
                with self.assertRaises(OSError):
                    self.run_worker()
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        self.assertEqual(self.captured, [])

    def test_peer_loss_during_trailing_snapshot_refuses_before_authorization(self):
        actual = worker_runtime.load_content
        armed, reached = False, []
        def after_peer():
            nonlocal armed
            if self.peer_ok:
                armed = True
        def capture(*args, **kwargs):
            nonlocal armed
            result = actual(*args, **kwargs)
            if armed:
                armed = False
                reached.append("closed-during-trailing-content-read")
                self.peer_ok = False
            return result
        self.after_peer_check = after_peer
        with patch.object(worker_runtime, "load_content", side_effect=capture):
            with self.assertRaises(durable.Rejected):
                self.run_worker(execute=True)
        self.assertEqual(reached, ["closed-during-trailing-content-read"])
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.evidence.iterdir()), [])
        self.assertTrue(self.notices)

    def test_normal_engine_notice_does_not_hide_later_handoff_failure(self):
        self.after_claim = lambda: (self.installation.content / "settings.json").write_bytes(b"changed")
        with self.assertRaises(durable.Rejected):
            self.run_worker(execute=True)
        self.assertEqual([n["recovery_error"] for n in self.notices],
                         [None, "supervisor-worker-result-unconfirmed"])
        self.assertTrue(all(n["start_fenced"] for n in self.notices))
        self.assertFalse((self.installation.journal / "recovery-outcome.json").exists())

    def test_later_report_failure_preserves_original_recovery_error_notice(self):
        def fail_restore(name):
            if name == "restore_complete":
                raise OSError(errno.EIO, "synthetic restore failure")
        self.override = fail_restore
        def lost_report():
            raise durable.Rejected("synthetic-report-receipt-lost")
        self.after_claim = lost_report
        with self.assertRaises(durable.Rejected):
            self.run_worker(execute=True)
        self.assertEqual([n["recovery_error"] for n in self.notices],
                         ["recovery-restore-failed", "supervisor-worker-result-unconfirmed"])
        self.assertNotIn("start_old", self.calls)

    def test_external_command_owner_retains_and_reaps_timed_out_helper(self):
        now = 1005.
        owned = commands.LocalCommands(lambda: now)
        actual_read = os.read
        reached = []
        def read(fd, size):
            nonlocal now
            value = actual_read(fd, size)
            if value:
                reached.append(value)
                now = 1007.
            return value
        test = self
        class TimeoutBootstrap(self.bootstrap):
            def claim(self, path, **kwargs):
                with patch.object(commands.os, "read", side_effect=read):
                    owned.run((sys.executable, "-I", "-c",
                               "import os,signal;os.write(1,b'ready');signal.pause()"), deadline=1006.)
                test.fail("helper did not reach injected deadline")
        self.bootstrap = TimeoutBootstrap
        def cleanup():
            for process in owned.pending:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            owned.reap()
        self.addCleanup(cleanup)
        with self.assertRaises(commands.CommandUncertain):
            self.run_worker(commands=owned)
        self.assertEqual(reached, [b"ready"])
        self.assertEqual(len(owned.pending), 1)
        self.assertEqual(owned.pending[0].wait(timeout=5), -9)
        owned.reap()
        self.assertEqual(owned.pending, [])

    def test_embedding_requires_explicit_command_cleanup_owner(self):
        with self.assertRaisesRegex(durable.Rejected, "command-owner-required"):
            self.run_worker(commands=None)
        self.assertEqual(self.captured, [])

    def test_pre_bootstrap_read_and_alert_receipt_faults_still_attempt_transport(self):
        for code in (errno.EIO, errno.ENOSPC):
            notices, reached = [], []
            def persist(notice):
                reached.append("persist")
                raise OSError(code, "private synthetic path")
            def transport(notice):
                reached.append("transport")
                alert.validate_notice(notice)
                notices.append(notice)
                return True
            with patch.object(worker_runtime, "read_file", side_effect=OSError(code, "private synthetic path")):
                with self.assertRaises(OSError):
                    self.run_worker(execute=True, persist_alert=persist, transport_alert=transport)
            self.assertEqual(reached, ["persist", "transport"])
            self.assertEqual(notices[0]["recovery_error"], "recovery-resume-inputs-failed")
            self.assertNotIn(b"private synthetic path", durable.canonical(notices))
        self.assertEqual(self.captured, [])

    def test_expired_or_cross_boot_launch_never_bootstraps(self):
        for now, boot in ((1180., "boot-a"), (1005., "other")):
            self.now, self.boot = now, boot
            with self.subTest(now=now, boot=boot), self.assertRaises(durable.Rejected):
                self.run_worker()
        self.assertEqual(self.captured, [])

    def test_cli_rejects_missing_inputs_and_unsupported_execution_flag(self):
        for args in ([], ["--execute"], ["--approval", "private-path"]):
            result = subprocess.run([sys.executable, "-I", str(ROOT / "claim_worker.py"), *args],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(b"private-path", result.stderr)

    def test_cli_identity_success_exits_unresolved_and_output_failure_has_no_retry(self):
        spec = importlib.util.spec_from_file_location("claim_worker_cli", ROOT / "claim_worker.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        args = ["--approval", "synthetic", "--sha256", "a" * 64, "--uid", str(os.geteuid()),
                "--gid", str(os.getegid()), "--endpoint", str(self.endpoint),
                "--endpoint-device", str(self.endpoint.stat().st_dev),
                "--endpoint-inode", str(self.endpoint.stat().st_ino), "--deadline", "1170"]
        receipt = {"state": "identity_received_only", "start_permission": False}
        with patch.object(module.time, "monotonic", return_value=1005.), \
                patch.object(module, "load_launch", return_value=self.approval), \
                patch.object(module, "run_worker", return_value=receipt), \
                patch.object(module.os, "write", side_effect=lambda fd, raw: len(raw)) as write:
            self.assertEqual(module.main(args), 3)
            self.assertEqual(write.call_count, 1)
            with patch.object(module.os, "write", return_value=0) as partial:
                self.assertEqual(module.main(args), 1)
                self.assertEqual(partial.call_count, 1)
