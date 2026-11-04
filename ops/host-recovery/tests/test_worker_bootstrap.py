"""Manager bootstrap fixtures and real local IPC, NOT installed-systemd proof."""
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import bootstrap, durable, jobs, journal, manager, supervisor, worker, worker_bootstrap
from test_bootstrap import BOOT
from test_manager import encoded, observed
from test_recovery_state import intent
from test_supervisor import ScriptedManager


class WorkerBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.now, self.boot = 1050.0, BOOT
        self.request = {"schema": "host-recovery-reconcile-request-v1", "attempt_id": "attempt-a",
            "intent_sha256": "e" * 64, "owner": {"installation_id": "installation", "attempt_id": "attempt-a",
                "unit": "cpa-supervisor.service", "invocation_id": "a" * 32, "boot_id": BOOT},
            "original_arm": {"boot_id": BOOT, "monotonic": 1000.0}, "failure_lower_bound": 1000.0,
            "deadline": 1100.0, "detection_upper_bound_seconds": 50.0,
            "forward_allowed": False, "production_acceptance": False}
        self.sign()
        self.setup_rows(os.getpid() + 1)
        self.calls = []
        self.after = lambda row: None
        self.failure = None
        self.change = lambda: None
        self.before_peer, self.after_peer = lambda: None, lambda: None
        self.alive = True
        self.peer_updates = {}
        self.rebuild()

    def sign(self):
        self.request.pop("request_id", None)
        self.request["request_id"] = durable.digest(durable.canonical(self.request))

    def setup_rows(self, supervisor_pid):
        self.supervisor_row = observed(self.request["owner"]["unit"], self.request["owner"]["invocation_id"],
                                       "/scripted/supervisor.service")
        self.supervisor_row.update(MainPID=str(supervisor_pid), Restart="on-failure",
                                   User=str(os.geteuid()), Group=str(os.getegid()))
        self.worker_row = observed(jobs.recovery_unit(self.request["request_id"]), "b" * 32,
                                   "/scripted/recovery.service")
        self.worker_row.update(MainPID=str(os.getpid()), User=str(os.geteuid()), Group=str(os.getegid()))

    def rebuild(self):
        self.supervisor_binding = bootstrap.SupervisorBinding(self.supervisor_row["Id"],
            self.supervisor_row["FragmentPath"], "f" * 64,
            durable.digest(durable.canonical(manager.static_properties(self.supervisor_row))), os.geteuid(), os.getegid())
        self.worker_binding = jobs.RecoveryJobBinding(self.request["request_id"], self.worker_row["FragmentPath"],
            "f" * 64, durable.digest(durable.canonical(manager.static_properties(self.worker_row))))
        self.engine = worker_bootstrap.SystemdWorkerBootstrap(systemctl="/accepted/systemctl",
            commands=SimpleNamespace(run=self.command), supervisor_binding=self.supervisor_binding,
            worker_binding=self.worker_binding, request=self.request, intent_sha256=self.request["intent_sha256"],
            installation_id=self.request["owner"]["installation_id"], attempt_id=self.request["attempt_id"],
            clock=lambda: self.now, boot_id=lambda: self.boot, read_fragment_hash=lambda _: "f" * 64,
            read_process_cgroup=self.cgroup)

    def command(self, argv, *, deadline):
        self.calls.append((argv, deadline))
        if self.failure:
            raise self.failure
        row = self.supervisor_row if argv[-1] == self.supervisor_row["Id"] else self.worker_row
        raw = encoded(row)
        self.after(row)
        return raw

    def cgroup(self, pid):
        if pid == os.getpid():
            return self.worker_row["ControlGroup"]
        return self.supervisor_row["ControlGroup"]

    def fake_client(self, path, **kw):
        self.client_policy = kw
        def claim(*, deadline):
            peer = {"pid": kw["supervisor_pid"], "uid": kw["supervisor_uid"], "gid": os.getegid(), **self.peer_updates}
            self.before_peer()
            first = kw["verify_identity"](peer=peer, peer_alive=lambda: self.alive, deadline=deadline)
            self.change()
            self.after_peer()
            last = kw["verify_identity"](peer=peer, peer_alive=lambda: self.alive, deadline=deadline)
            self.assertEqual(first, last)
            return {"worker": last, "restoration_permission": False, "start_permission": False}
        return SimpleNamespace(claim=claim)

    def claim(self, deadline=1100):
        with patch.object(worker_bootstrap, "WorkerClient", side_effect=self.fake_client):
            return self.engine.claim("/synthetic/worker.sock", deadline=deadline)

    def test_fixed_readonly_queries_and_independent_identity_before_and_after_claim(self):
        value = self.claim()
        self.assertEqual(value["worker"]["pid"], os.getpid())
        self.assertFalse(value["restoration_permission"])
        self.assertFalse(value["start_permission"])
        self.assertEqual(self.client_policy["supervisor_pid"], int(self.supervisor_row["MainPID"]))
        self.assertEqual(len(self.calls), 11)
        for argv, deadline in self.calls:
            self.assertEqual(argv[:-1], ("/accepted/systemctl", "--no-pager", "show",
                "--property=" + ",".join(sorted(manager.PROPERTIES)), "--"))
            self.assertEqual(deadline, 1100)
        with self.assertRaises(durable.Rejected):
            self.claim()

    def test_recovery_provider_phase_queries_shorten_original_deadline_without_renewal(self):
        passed = []
        def client(path, **kw):
            def claim(*, deadline, recovery_provider):
                self.assertEqual(deadline, 1100.)
                peer = {"pid": kw["supervisor_pid"], "uid": kw["supervisor_uid"], "gid": os.getegid()}
                observed = kw["verify_identity"](peer=peer, peer_alive=lambda: True, deadline=1075.)
                with self.assertRaises(durable.Rejected):
                    kw["verify_identity"](peer=peer, peer_alive=lambda: True, deadline=1101.)
                passed.append(recovery_provider)
                return {"worker": observed}
            return SimpleNamespace(claim=claim, result_receipt={"observed": True})
        provider = lambda *a, **kw: None
        with patch.object(worker_bootstrap, "WorkerClient", side_effect=client):
            self.engine.claim("/synthetic/worker.sock", deadline=1100., recovery_provider=provider)
        self.assertEqual(passed, [provider])
        self.assertIn(1075., [deadline for _, deadline in self.calls])
        self.assertTrue(all(deadline <= 1100. for _, deadline in self.calls))
        self.assertEqual(self.engine.end, 1100.)
        self.assertEqual(self.engine.result_receipt, {"observed": True})

    def test_caller_or_environment_cannot_replace_request_owner(self):
        with patch.dict(os.environ, {"INVOCATION_ID": "forged", "MAINPID": "1", "BOOT_ID": "forged"}):
            self.claim()
        self.assertEqual(self.client_policy["supervisor_owner"], self.request["owner"])
        self.request["owner"]["invocation_id"] = "c" * 32
        self.assertNotEqual(self.engine.request["owner"], self.request["owner"])

    def test_unbound_or_changed_request_refuses_before_manager_queries(self):
        for change in (lambda e: e.request.update(request_id="0" * 64),
                       lambda e: setattr(e, "installation_id", "foreign"),
                       lambda e: setattr(e, "attempt_id", "foreign"),
                       lambda e: setattr(e, "intent_sha256", "0" * 64)):
            self.setUp()
            change(self.engine)
            with self.subTest(change=change), self.assertRaises(durable.Rejected):
                self.claim()
            self.assertEqual(self.calls, [])

    def test_supervisor_mainpid_discovery_requires_strict_live_numeric_identity(self):
        for update in ({"MainPID": "0"}, {"MainPID": "01"}, {"MainPID": "2147483648"},
                       {"MainPID": str(os.getpid())}, {"Job": "1"}, {"ActiveState": "inactive"},
                       {"InvocationID": "c" * 32}):
            self.setUp()
            self.supervisor_row.update(update)
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.claim()

    def test_worker_mainpid_invocation_cgroup_or_pending_state_refuses(self):
        for update in ({"MainPID": str(os.getpid() + 1)}, {"Job": "1"}, {"InvocationID": ""},
                       {"ActiveState": "activating"}, {"ControlGroup": "/unsafe/../group"}):
            self.setUp()
            self.worker_row.update(update)
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.claim()

    def test_distinct_supervisor_and_worker_invocation_and_cgroup_required(self):
        for update in ({"InvocationID": self.request["owner"]["invocation_id"]},
                       {"ControlGroup": self.supervisor_row["ControlGroup"]}):
            self.setUp()
            self.worker_row.update(update)
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.claim()

    def test_numeric_worker_ownership_must_match_actual_effective_ids_even_if_repinned(self):
        for key, value in (("User", str(os.geteuid() + 1)), ("Group", str(os.getegid() + 1)),
                           ("User", "recovery"), ("Group", "recovery")):
            self.setUp()
            self.worker_row[key] = value
            self.rebuild()
            with self.subTest(key=key, value=value), self.assertRaises(durable.Rejected):
                self.claim()

    def test_supervisor_fragment_or_command_change_refuses(self):
        for update in ({"DropInPaths": "/extra"}, {"ExecStart": "changed"}, {"ReadWritePaths": "/"}):
            self.setUp()
            self.supervisor_row.update(update)
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.claim()
        self.setUp()
        self.engine.supervisor.read_fragment_hash = lambda _: "0" * 64
        with self.assertRaises(durable.Rejected):
            self.claim()

    def test_peer_pid_uid_gid_and_liveness_are_independent_requirements(self):
        for updates in ({"pid": 1}, {"uid": os.geteuid() + 1}, {"gid": os.getegid() + 1}):
            self.setUp()
            self.peer_updates = updates
            with self.subTest(updates=updates), self.assertRaises(durable.Rejected):
                self.claim()
        self.setUp()
        self.alive = False
        with self.assertRaises(durable.Rejected):
            self.claim()

    def test_replacement_between_discovery_and_connected_observation_refuses(self):
        for update in ({"InvocationID": "c" * 32}, {"MainPID": "1"}, {"ControlGroup": "/replacement"}):
            self.setUp()
            self.before_peer = lambda: self.supervisor_row.update(update)
            with self.subTest(update=update), self.assertRaises(durable.Rejected):
                self.claim()

    def test_post_reply_worker_or_supervisor_replacement_cannot_be_adopted(self):
        for row, update in (("supervisor_row", {"InvocationID": "c" * 32}),
                            ("worker_row", {"InvocationID": "c" * 32}),
                            ("supervisor_row", {"ControlGroup": "/replacement"}),
                            ("worker_row", {"ControlGroup": "/replacement"})):
            self.setUp()
            self.change = lambda: getattr(self, row).update(update)
            with self.subTest(row=row, update=update), self.assertRaises(durable.Rejected):
                self.claim()

    def test_peer_exit_during_query_refuses_without_numeric_pid_fallback(self):
        self.after = lambda _: setattr(self, "alive", False)
        with self.assertRaises(durable.Rejected):
            self.claim()

    def test_cgroup_migration_or_kernel_read_uncertainty_refuses(self):
        self.engine.supervisor.read_process_cgroup = lambda _: "/foreign"
        with self.assertRaises(durable.Rejected):
            self.claim()
        self.setUp()
        def fail(_):
            raise OSError("unavailable")
        self.engine.supervisor.read_process_cgroup = fail
        with self.assertRaises(OSError):
            self.claim()

    def test_boot_loss_or_budget_expiry_during_exchange_refuses(self):
        for change in (lambda: setattr(self, "boot", "22345678-1234-1234-1234-123456789abc"),
                       lambda: setattr(self, "now", 1100.0), lambda: setattr(self, "now", 1000.0)):
            self.setUp()
            self.change = change
            with self.subTest(change=change), self.assertRaises(durable.Rejected):
                self.claim()

    def test_expired_bad_clock_or_missing_boot_refuses_before_queries_and_exhausts(self):
        for now in (1100, float("nan"), float("inf"), True):
            self.setUp()
            self.now = now
            with self.subTest(now=now), self.assertRaises(durable.Rejected):
                self.claim()
            self.assertEqual(self.calls, [])
            self.now = 1050
            with self.assertRaises(durable.Rejected):
                self.claim()
        self.setUp()
        self.boot = "boot-a"
        with self.assertRaises(durable.Rejected):
            self.claim()
        self.assertEqual(self.calls, [])

    def test_caller_deadline_can_shorten_but_not_expand_original_request(self):
        self.claim(deadline=9999)
        self.assertTrue(all(deadline == 1100 for _, deadline in self.calls))
        self.setUp()
        self.claim(deadline=1075)
        self.assertTrue(all(deadline == 1075 for _, deadline in self.calls))

    def test_lost_manager_reply_does_not_allow_retry(self):
        self.failure = OSError("private manager failure")
        with self.assertRaises(OSError):
            self.claim()
        self.failure = None
        with self.assertRaises(durable.Rejected):
            self.claim()
        self.assertEqual(len(self.calls), 1)


PROCESS = r'''
import json,os,sys,time
sys.path[:0] = sys.argv[1:3]
from test_worker_bootstrap import WorkerBootstrapTests
case = WorkerBootstrapTests()
case.setUp()
case.request = json.loads(sys.argv[4])
case.setup_rows(int(sys.argv[5]))
case.now = time.monotonic()
case.rebuild()
case.engine.supervisor.clock = time.monotonic
case.engine.supervisor.last_clock = None
queries = 0
def after(row):
    global queries
    if row is case.supervisor_row:
        queries += 1
        if queries == int(sys.argv[6]):
            row['InvocationID'] = 'c' * 32
case.after = after
try:
    result = case.engine.claim(sys.argv[3], deadline=case.request['deadline'])
    print(json.dumps(result), flush=True)
    sys.stdin.readline()
except Exception as failure:
    print(type(failure).__name__, flush=True)
    sys.exit(2)
'''


class ManagedWorkerIPCTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="managed-worker-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "state"
        self.root.mkdir(mode=0o700)
        self.path = str(Path(self.temp.name) / "worker.sock")
        self.listener = worker.WorkerListener(self.path, worker_uid=os.geteuid())
        self.addCleanup(self.listener.close)
        self.children = []
        self.addCleanup(self.stop_children)
        self.value = intent()
        self.value["owner"]["boot_id"] = BOOT
        self.now = time.monotonic()
        with durable.directory(str(self.root), private=True) as fd:
            log = journal.Journal(fd)
            log.prepare(self.value)
            log.arm({"boot_id": BOOT, "monotonic": self.now - 1})
        self.owner = {**self.value["owner"], "invocation_id": "a" * 32}
        self.manager = ScriptedManager()
        self.pid = None
        self.observer = SimpleNamespace(observe=self.observe, observe_worker=self.observe_worker)

    def stop_children(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()

    def observe(self, request_id, *, deadline):
        return {"schema": "host-recovery-job-observation-v1", "request_id": request_id, "boot_id": BOOT,
            "unit": jobs.recovery_unit(request_id), "invocation_id": "b" * 32, "state": "running", "job_id": 0}

    def observe_worker(self, request_id, *, pid, deadline):
        self.assertEqual(pid, self.pid)
        return {**self.observe(request_id, deadline=deadline), "pid": pid, "cgroup": "/scripted/recovery.service"}

    def open(self):
        return supervisor.recovery_owner(str(self.root), owner=self.owner, manager=self.manager,
            clock=time.monotonic, boot_id=lambda: BOOT, persist_alert=lambda _: None, transport_alert=lambda _: True)

    def start(self, process, change_after=0):
        root = Path(__file__).resolve().parent.parent
        child = subprocess.Popen([sys.executable, "-I", "-c", PROCESS, str(root), str(root / "tests"), self.path,
            json.dumps(process.pending_request), str(os.getpid()), str(change_after)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "INVOCATION_ID": "forged", "MAINPID": "1"})
        self.children.append(child)
        self.pid = child.pid
        return child

    def read(self, child):
        with selectors.DefaultSelector() as wait:
            wait.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(wait.select(10), "worker exchange did not finish")
        raw = child.stdout.readline()
        if not raw:
            self.fail(child.stderr.read().decode())
        return raw

    def serve(self, process):
        return self.listener.accept_once(supervisor=process, observer=self.observer,
                                         deadline=process.pending_request["deadline"])

    def test_actual_peer_claim_uses_worker_manager_bootstrap_with_no_start_grant(self):
        with self.open() as process:
            process.reconcile(deadline=self.now + 8)
            child = self.start(process)
            claim = self.serve(process)
            self.assertEqual(json.loads(self.read(child)), claim)
            self.assertFalse(claim["start_permission"])
            self.assertFalse(claim["restoration_permission"])
            child.stdin.write(b"done\n")
            child.stdin.flush()
            self.assertEqual(child.wait(timeout=5), 0)
        self.assertEqual(durable.decode((self.root / "reconcile-worker.json").read_bytes()), claim)

    def test_manager_replacement_after_discovery_prevents_sending_claim(self):
        with self.open() as process:
            process.reconcile(deadline=self.now + 8)
            child = self.start(process, change_after=1)
            with self.assertRaises(durable.Rejected):
                self.serve(process)
            self.assertEqual(self.read(child), b"Rejected\n")
            self.assertEqual(child.wait(timeout=5), 2)
        self.assertFalse((self.root / "reconcile-worker.json").exists())

    def test_well_formed_claim_with_different_worker_invocation_is_not_accepted(self):
        with self.open() as process:
            process.reconcile(deadline=self.now + 8)
            original = self.observe
            self.observe = lambda *args, **kw: {**original(*args, **kw), "invocation_id": "c" * 32}
            self.observer.observe = self.observe
            child = self.start(process)
            claim = self.serve(process)
            self.assertEqual(claim["worker"]["invocation_id"], "c" * 32)
            self.assertEqual(self.read(child), b"Rejected\n")
            self.assertEqual(child.wait(timeout=5), 2)
        self.assertTrue((self.root / "reconcile-worker.json").exists())

    def test_manager_loss_after_reply_keeps_durable_claim_but_client_refuses(self):
        with self.open() as process:
            process.reconcile(deadline=self.now + 8)
            child = self.start(process, change_after=3)
            self.serve(process)
            self.assertEqual(self.read(child), b"Rejected\n")
            self.assertEqual(child.wait(timeout=5), 2)
        self.assertTrue((self.root / "reconcile-worker.json").exists())
        with self.open() as process:
            self.assertEqual(process.status()["state"], "recovery_unresolved")
            self.assertFalse(process.status()["start_permission"])
