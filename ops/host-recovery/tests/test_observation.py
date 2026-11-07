"""Owned lock/process components; manager/kernel observations remain scripted."""
import copy
from dataclasses import replace
import errno
import fcntl
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import bootstrap, durable, jobs, launch, loading, manager, observation
import test_bootstrap
import test_launch
from test_manager import encoded, observed

ROOT = Path(__file__).resolve().parent.parent


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_launch.LaunchTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.installation = self.fixture.fixture
        self.now = 1050.0
        self.owner = self.fixture.args["supervisor_owner"]
        self.identity = self.fixture.observer
        self.job = {"schema": "host-recovery-job-observation-v1",
                    "request_id": self.fixture.approval.job.request_id, "boot_id": "boot-a",
                    "unit": jobs.recovery_unit(self.fixture.approval.job.request_id),
                    "invocation_id": "c" * 32, "state": "running", "job_id": 0}
        self.jobs = unittest.mock.Mock()
        self.jobs.observe.side_effect = lambda *a, **kw: copy.deepcopy(self.job)
        self.waits = []

    def wait(self, seconds):
        self.waits.append(seconds)
        self.now += seconds
        return False

    def observe(self, **kwargs):
        args = dict(deadline=1170.0, interval=1.0, max_observations=3, stop=lambda: False,
                    wait=self.wait, clock=lambda: self.now, boot_id=lambda: "boot-a")
        args.update(kwargs)
        with patch.object(launch, "SystemdSupervisorIdentity", return_value=self.identity):
            with patch.object(observation, "SystemdRecoveryJobs", return_value=self.jobs):
                return observation.observe_request(self.fixture.load(), **args)

    def unlocked(self):
        with durable.directory(str(self.installation.journal), private=True) as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def locked(self):
        with durable.directory(str(self.installation.journal), private=True) as fd:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_readonly_observation_retains_same_lock_across_ticks_without_grants(self):
        before = self.installation.state()
        def wait(seconds):
            self.locked()
            return self.wait(seconds)
        value = self.observe(wait=wait)
        self.assertEqual(value["state"], "observation_ended_unresolved")
        self.assertEqual(value["reason"], "observation_limit")
        self.assertEqual(value["observations"], 3)
        self.assertEqual(value["sampled_elapsed_seconds"], 2.0)
        self.assertEqual(self.waits, [1.0, 1.0])
        for key in ("complete_fence_proven", "recovery_execution_allowed", "start_allowed",
                    "terminal_outcome_verified", "production_acceptance", "recovery_completed", "alert_delivery_verified"):
            self.assertIs(value[key], False)
        self.assertEqual(value["job"], self.job)
        self.assertNotIn(str(self.installation.root), durable.canonical(value).decode())
        self.assertEqual(self.installation.state(), before)
        self.unlocked()

    def test_unknown_invalid_and_unbounded_lifecycle_arguments_refuse_before_manager(self):
        for args in ({"interval": 0}, {"interval": True}, {"interval": float("nan")},
                     {"interval": float("inf")}, {"max_observations": True}, {"max_observations": 0},
                     {"max_observations": 4097}, {"stop": None}, {"wait": None}):
            with self.subTest(args=args), self.assertRaises(durable.Rejected):
                self.observe(**args)
        self.identity.bootstrap.assert_not_called()

    def test_one_observation_does_not_wait(self):
        value = self.observe(max_observations=1)
        self.assertEqual(value["observations"], 1)
        self.assertEqual(self.waits, [])
        self.assertEqual(self.jobs.observe.call_count, 2)

    def test_preexisting_stop_returns_unresolved_without_job_query(self):
        value = self.observe(stop=lambda: True)
        self.assertEqual(value["reason"], "stop_requested")
        self.assertEqual(value["observations"], 0)
        self.assertIsNone(value["job"])
        self.jobs.observe.assert_not_called()
        self.unlocked()

    def test_stop_callback_must_return_strict_boolean(self):
        with self.assertRaisesRegex(durable.Rejected, "stop-schema"):
            self.observe(stop=lambda: 1)
        self.unlocked()

    def test_wait_callback_must_return_strict_boolean(self):
        with self.assertRaisesRegex(durable.Rejected, "wait-schema"):
            self.observe(wait=lambda seconds: None)
        self.unlocked()

    def test_signal_style_interrupt_wait_ends_unresolved(self):
        value = self.observe(wait=lambda seconds: True)
        self.assertEqual(value["reason"], "stop_requested")
        self.assertEqual(value["observations"], 1)
        self.unlocked()

    def test_early_uninterrupted_wait_refuses_busy_poll(self):
        with self.assertRaisesRegex(durable.Rejected, "wait-incomplete"):
            self.observe(wait=lambda seconds: False)
        self.assertEqual(self.jobs.observe.call_count, 2)
        self.unlocked()

    def test_fractional_wait_does_not_false_reject_rounding(self):
        value = self.observe(interval=0.1, max_observations=3)
        self.assertEqual(value["observations"], 3)
        self.assertAlmostEqual(value["sampled_elapsed_seconds"], 0.2)

    def test_subprecision_interval_cannot_spin_at_unchanged_clock(self):
        with self.assertRaisesRegex(durable.Rejected, "wait-incomplete"):
            self.observe(interval=1e-100)
        self.assertEqual(self.jobs.observe.call_count, 2)

    def test_original_deadline_shortens_every_query_and_wait(self):
        def wait(seconds):
            self.assertEqual(seconds, 130.0)
            self.now += seconds
            return False
        with self.assertRaisesRegex(durable.Rejected, "deadline-missed"):
            self.observe(deadline=1500.0, interval=1000.0, wait=wait)
        for call in self.jobs.observe.call_args_list:
            self.assertEqual(call.kwargs["deadline"], 1180.0)
        for call in self.identity.observe_owner.call_args_list:
            self.assertEqual(call.kwargs["deadline"], 1180.0)
        self.unlocked()

    def test_caller_can_shorten_not_extend_original_reserve(self):
        value = self.observe(deadline=1051.5, interval=1.0, max_observations=2)
        self.assertEqual(value["deadline"], 1051.5)
        self.assertEqual(value["sampled_elapsed_seconds"], 1.0)

    def test_clock_regression_between_ticks_refuses(self):
        def wait(seconds):
            self.now -= 1.0
            return False
        with self.assertRaisesRegex(durable.Rejected, "clock-discontinuity"):
            self.observe(wait=wait)
        self.unlocked()

    def test_expiry_during_job_query_returns_no_receipt(self):
        def observe(*args, **kwargs):
            self.now = 1170.0
            return copy.deepcopy(self.job)
        self.jobs.observe.side_effect = observe
        with self.assertRaises(durable.Rejected):
            self.observe()
        self.unlocked()

    def test_owner_change_or_missing_ack_never_becomes_observed_status(self):
        for value in (None, True, {**self.owner, "invocation_id": "e" * 32}):
            self.identity.observe_owner.return_value = value
            with self.subTest(value=value), self.assertRaises(durable.Rejected):
                self.observe()
        self.jobs.observe.assert_not_called()
        self.unlocked()

    def test_worker_invocation_replacement_and_loss_refuse(self):
        for replacement in ("", "d" * 32):
            self.jobs.reset_mock()
            self.job.update(invocation_id="c" * 32, state="running", job_id=0)
            def wait(seconds):
                self.job["invocation_id"] = replacement
                self.job["state"] = "inactive_unverified" if not replacement else "running"
                return self.wait(seconds)
            with self.subTest(replacement=replacement), self.assertRaisesRegex(durable.Rejected, "invocation-lost"):
                self.observe(wait=wait)
            self.unlocked()

    def test_supervisor_invocation_cannot_be_recovery_worker(self):
        self.job["invocation_id"] = self.owner["invocation_id"]
        with self.assertRaisesRegex(durable.Rejected, "separate-worker"):
            self.observe()

    def test_inactive_worker_is_unverified_and_not_success(self):
        self.job["state"] = "inactive_unverified"
        value = self.observe()
        self.assertEqual(value["reason"], "worker_inactive_unverified")
        self.assertFalse(value["recovery_completed"])
        self.assertFalse(value["terminal_outcome_verified"])
        self.assertEqual(self.waits, [])

    def test_pending_to_running_binds_first_nonempty_invocation_only(self):
        self.job.update(invocation_id="", state="pending", job_id=123)
        def wait(seconds):
            self.job.update(invocation_id="c" * 32, state="running", job_id=0)
            return self.wait(seconds)
        value = self.observe(wait=wait)
        self.assertEqual(value["observations"], 3)
        self.assertEqual(value["job"]["state"], "running")
        self.assertFalse(value["recovery_completed"])

    def test_job_change_inside_one_observation_refuses(self):
        self.jobs.observe.side_effect = [copy.deepcopy(self.job), {**self.job, "invocation_id": "d" * 32}]
        with self.assertRaisesRegex(durable.Rejected, "changed-during-query"):
            self.observe()
        self.unlocked()

    def test_wrong_boot_request_unit_and_unknown_job_state_refuse(self):
        for changes in ({"boot_id": "other"}, {"request_id": "e" * 64}, {"unit": "wrong.service"},
                        {"state": "verified"}, {"job_id": True}):
            self.jobs.observe.side_effect = lambda *a, **kw: {**self.job, **changes}
            with self.subTest(changes=changes), self.assertRaises(durable.Rejected):
                self.observe()
        self.unlocked()

    def test_content_changes_during_wait_refuse_without_adopting_new_bytes(self):
        def wait(seconds):
            (self.installation.content / "settings.json").write_bytes(b"restricted-secret")
            return self.wait(seconds)
        with self.assertRaises(durable.Rejected):
            self.observe(wait=wait)
        self.unlocked()

    def test_request_changes_during_wait_refuse_without_new_budget(self):
        def wait(seconds):
            path = self.installation.journal / "reconcile-request.json"
            value = durable.decode(path.read_bytes())
            value["deadline"] = 1175.0
            value.pop("request_id")
            value["request_id"] = durable.digest(durable.canonical(value))
            path.write_bytes(durable.canonical(value))
            return self.wait(seconds)
        with self.assertRaises(durable.Rejected):
            self.observe(wait=wait)
        self.unlocked()

    def test_storage_read_failure_after_tick_releases_lock_and_cannot_publish(self):
        actual = loading.read_file
        before = self.installation.state()
        for number in (errno.EIO, errno.ENOSPC):
            armed = False
            def wait(seconds):
                nonlocal armed
                armed = True
                return self.wait(seconds)
            def read(*args, **kwargs):
                if armed:
                    raise OSError(number, "restricted-secret")
                return actual(*args, **kwargs)
            with self.subTest(number=number), patch.object(loading, "read_file", side_effect=read):
                with self.assertRaises(OSError):
                    self.observe(wait=wait)
            self.unlocked()
        self.assertEqual(self.installation.state(), before)

    def test_replaced_ancestor_on_context_exit_returns_no_receipt(self):
        moved = self.installation.root / "content-old"
        original = launch._CallingSession.status
        def status(session):
            result = original(session)
            self.installation.content.rename(moved)
            self.installation.content.mkdir(mode=0o700)
            return result
        with patch.object(launch._CallingSession, "status", side_effect=status, autospec=True):
            with self.assertRaises(durable.Rejected):
                self.observe(max_observations=1)
        self.unlocked()

    def test_session_references_cannot_validate_or_report_after_exit(self):
        with patch.object(launch, "SystemdSupervisorIdentity", return_value=self.identity):
            with launch._calling_session(self.fixture.load(), deadline=1170.0, clock=lambda: self.now,
                                         boot_id=lambda: "boot-a", commands=None) as session:
                self.locked()
            with self.assertRaises(durable.Rejected):
                session.validate()
            with self.assertRaises(durable.Rejected):
                session.status()
        self.unlocked()

    def test_session_refusal_is_sticky_without_later_adoption(self):
        with patch.object(launch, "SystemdSupervisorIdentity", return_value=self.identity):
            with launch._calling_session(self.fixture.load(), deadline=1170.0, clock=lambda: self.now,
                                         boot_id=lambda: "boot-a", commands=None) as session:
                self.identity.observe_owner.return_value = None
                with self.assertRaises(durable.Rejected):
                    session.validate()
                self.identity.observe_owner.return_value = self.owner
                with self.assertRaisesRegex(durable.Rejected, "unavailable"):
                    session.validate()
                with self.assertRaises(durable.Rejected):
                    session.status()

    def test_composes_real_manager_parsers_with_scripted_unit_and_kernel_reads(self):
        supervisor_row = self.fixture.manager_fixture()
        fragment = self.installation.root / "recovery.service"
        fragment.write_bytes(b"synthetic pinned recovery unit, not installed\n")
        fragment.chmod(0o600)
        unit = jobs.recovery_unit(self.fixture.approval.job.request_id)
        worker_row = observed(unit, "c" * 32, "/recovery/worker.service")
        worker_row.update(FragmentPath=str(fragment), Restart="no", MainPID="123",
                          User=str(os.geteuid()), Group=str(os.getegid()))
        self.fixture.approval = replace(self.fixture.approval, job=replace(self.fixture.approval.job,
            fragment_path=str(fragment), fragment_sha256=durable.digest(fragment.read_bytes()),
            properties_sha256=durable.digest(durable.canonical(manager.static_properties(worker_row)))))
        calls = []
        def run(argv, *, deadline):
            calls.append((argv, deadline))
            row = supervisor_row if argv[-1] == supervisor_row["Id"] else worker_row
            self.assertIn(argv[-1], (supervisor_row["Id"], unit))
            self.locked() if argv[-1] == unit else None
            return encoded(row)
        actual = bootstrap.SystemdSupervisorIdentity
        def identity(**kwargs):
            return actual(**kwargs, read_process_cgroup=lambda pid: supervisor_row["ControlGroup"])
        before = self.installation.state()
        with patch.object(launch, "SystemdSupervisorIdentity", side_effect=identity):
            value = observation.observe_request(self.fixture.approval, deadline=1170.0, interval=1.0,
                max_observations=2, stop=lambda: False, wait=self.wait, clock=lambda: self.now,
                boot_id=lambda: test_bootstrap.BOOT, commands=SimpleNamespace(run=run))
        self.assertEqual(value["observations"], 2)
        self.assertEqual(sum(argv[-1] == unit for argv, _ in calls), 4)
        for argv, deadline in calls:
            self.assertEqual(argv[1:3], ("--no-pager", "show"))
            self.assertEqual(deadline, 1170.0)
        self.assertEqual(before, self.installation.state())
        self.unlocked()

    def test_cli_bad_arguments_and_pin_failure_are_opaque(self):
        for args, code, error in ((["--unknown", "restricted-secret"], 2, b"invalid-arguments"),
                (["--approval", str(self.fixture.path), "--sha256", "0" * 64, "--uid", str(os.geteuid()),
                  "--gid", str(os.getegid()), "--deadline", "999999999999", "--interval", "1",
                  "--max-observations", "2"], 1, b"unavailable")):
            proc = subprocess.run((sys.executable, "-I", str(ROOT / "observe.py"), *args),
                                  capture_output=True, timeout=10)
            self.assertEqual(proc.returncode, code)
            self.assertEqual(proc.stdout, b"")
            self.assertEqual(proc.stderr, b"host-recovery-observe: " + error + b"\n")

    def test_cli_expiry_precedes_configuration_read(self):
        proc = subprocess.run((sys.executable, "-I", str(ROOT / "observe.py"), "--approval", "/nonexistent/secret",
            "--sha256", self.fixture.pin, "--uid", str(os.geteuid()), "--gid", str(os.getegid()),
            "--deadline", "0", "--interval", "1", "--max-observations", "2"), capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b"host-recovery-observe: unavailable\n")

    def child(self):
        # Actual CLI main/signal/Event/lock in a separate process. Only the manager,
        # boot/clock and cgroup-related observation boundaries are scripted.
        script = '''
import importlib.util,json,os,sys,time
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
from host_recovery import launch,observation,jobs
from host_recovery.durable import decode
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location("observation_cli",sys.argv[1]+"/observe.py")
cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
path,pin,owner,ready=sys.argv[2],sys.argv[3],json.loads(sys.argv[4]),int(sys.argv[5])
identity=SimpleNamespace(bootstrap=lambda **kw:{"owner":owner},observe_owner=lambda *a,**kw:owner)
request=decode(open(path.replace("approval.json","journal/reconcile-request.json"),"rb").read())
job={"schema":"host-recovery-job-observation-v1","request_id":request["request_id"],"boot_id":"boot-a",
     "unit":jobs.recovery_unit(request["request_id"]),"invocation_id":"c"*32,"state":"running","job_id":0}
actual=observation.observe_request
# CLI and recovery deadlines share the fixture clock, independent of host uptime.
real_clock=time.monotonic
origin=real_clock()
clock=lambda:1050.0+real_clock()-origin
RealEvent=cli.threading.Event
class Event:
    def __init__(self):
        self.inner=RealEvent()
    def is_set(self): return self.inner.is_set()
    def set(self): self.inner.set()
    def wait(self,seconds):
        os.write(ready,b"R");return self.inner.wait(seconds)
def observe(*a,**kw):
    kw.update(clock=clock,boot_id=lambda:"boot-a")
    return actual(*a,**kw)
with patch.object(launch,"SystemdSupervisorIdentity",return_value=identity), \\
     patch.object(observation,"SystemdRecoveryJobs",return_value=SimpleNamespace(observe=lambda *a,**kw:job)), \\
     patch.object(cli,"observe_request",side_effect=observe),patch.object(cli.threading,"Event",Event), \\
     patch.object(cli.time,"monotonic",clock):
    code=cli.main(["--approval",path,"--sha256",pin,"--uid",str(os.geteuid()),"--gid",str(os.getegid()),
        "--deadline",str(time.monotonic()+100),"--interval","30","--max-observations","3"])
sys.exit(code)
'''
        read, write = os.pipe()
        proc = subprocess.Popen((sys.executable, "-I", "-c", script, str(ROOT), str(self.fixture.path),
            self.fixture.pin, durable.canonical(self.owner).decode(), str(write)), pass_fds=(write,),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(write)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        self.addCleanup(proc.stdout.close)
        self.addCleanup(proc.stderr.close)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(read, selectors.EVENT_READ)
                self.assertTrue(selector.select(10), "child failed to reach synchronized wait")
            self.assertEqual(os.read(read, 1), b"R")
        finally:
            os.close(read)
        return proc

    def test_actual_cli_sigterm_interrupts_wait_returns_unresolved_and_releases_lock(self):
        before = self.installation.state()
        proc = self.child()
        self.locked()
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=10)
        self.assertEqual(proc.returncode, 3, err)
        value = durable.decode(out)
        self.assertEqual(value["reason"], "stop_requested")
        self.assertEqual(value["observations"], 1)
        self.assertFalse(value["recovery_completed"])
        self.assertFalse(value["start_allowed"])
        self.assertEqual(err, b"")
        self.unlocked()
        self.assertEqual(self.installation.state(), before)

    def test_actual_cli_sigint_stops_without_keyboardinterrupt_or_recovery_grant(self):
        before = self.installation.state()
        proc = self.child()
        self.locked()
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=10)
        self.assertEqual(proc.returncode, 3, err)
        self.assertEqual(durable.decode(out)["reason"], "stop_requested")
        self.assertEqual(err, b"")
        self.unlocked()
        self.assertEqual(self.installation.state(), before)

    def test_actual_cli_broken_output_refuses_after_unlock_without_buffered_retry(self):
        before = self.installation.state()
        proc = self.child()
        self.locked()
        proc.stdout.close()
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=10), 1)
        self.assertEqual(proc.stderr.read(), b"host-recovery-observe: unavailable\n")
        self.unlocked()
        self.assertEqual(self.installation.state(), before)

    def test_actual_cli_sigkill_releases_lock_with_original_request_and_no_receipt(self):
        before = self.installation.state()
        proc = self.child()
        self.locked()
        proc.kill()
        out, err = proc.communicate(timeout=10)
        self.assertEqual(proc.returncode, -signal.SIGKILL)
        self.assertEqual(out, b"")
        self.assertEqual(err, b"")
        self.unlocked()
        self.assertEqual(self.installation.state(), before)
