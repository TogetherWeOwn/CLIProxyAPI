"""Pinned-input/broker composition; all manager/fence replies remain scripted."""
from dataclasses import asdict, replace
import errno
import fcntl
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import bootstrap, broker, durable, jobs, launch, manager, outcomes, worker
import test_bootstrap
from test_installation import approve
import test_launch
from test_manager import encoded, observed
from test_worker import CLIENT

ROOT = Path(__file__).resolve().parent.parent


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_launch.LaunchTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.installation = self.fixture.fixture
        self.endpoint = self.installation.root / "ipc"
        self.endpoint.mkdir(mode=0o700)
        self.endpoint_approval = approve(self.endpoint)
        self.notices, self.listeners, self.deadlines = [], [], []
        self.persist = lambda notice: None
        self.fenced = True
        self.pid, self.invocation = 123, "c" * 32
        self.on_accept = lambda process: None
        self.on_fence = lambda: None
        self.after_reply = lambda process: None
        self.process = None
        self.owner = self.fixture.args["supervisor_owner"]
        self.job = SimpleNamespace(observe=self.observe, observe_worker=self.observe_worker)
        self.identity = self.fixture.observer

    def locked(self):
        with durable.directory(str(self.installation.journal), private=True) as fd:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def unlocked(self):
        with durable.directory(str(self.installation.journal), private=True) as fd:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def observe(self, request_id, *, deadline):
        self.locked()
        self.deadlines.append(deadline)
        return {"schema": "host-recovery-job-observation-v1", "request_id": request_id,
                "unit": jobs.recovery_unit(request_id), "boot_id": self.owner["boot_id"],
                "invocation_id": self.invocation, "state": "running", "job_id": 0}

    def observe_worker(self, request_id, *, pid, deadline, uid, gid):
        self.assertEqual((uid, gid), (os.geteuid(), os.getegid()))
        self.assertEqual(pid, self.pid)
        return {**self.observe(request_id, deadline=deadline), "pid": pid, "cgroup": "/synthetic/worker.service"}

    def fence(self, intent, *, deadline):
        self.locked()
        self.deadlines.append(deadline)
        self.assertEqual(intent, durable.decode((self.installation.journal / "intent.json").read_bytes()))
        self.on_fence()
        return self.fenced

    def listener(self, path, *, worker_uid, clock):
        self.locked()
        self.assertEqual(path, str(self.endpoint / ("claim-" + self.fixture.approval.job.request_id + ".sock")))
        self.assertEqual(worker_uid, os.geteuid())
        value = SimpleNamespace(closed=False)
        self.listeners.append(value)
        def close():
            value.closed = True
        def accept_once(*, supervisor, observer, deadline, result_oracle=None):
            self.locked()
            self.process = supervisor
            self.on_accept(supervisor)
            result = supervisor.claim_worker(peer={"pid": self.pid, "uid": os.geteuid(), "gid": os.getegid()},
                nonce="fixture-nonce", observer=observer, peer_alive=lambda: True, deadline=deadline)
            self.after_reply(supervisor)
            if result_oracle is not None:
                report = {"schema": "host-recovery-worker-result-v1", "request_id": supervisor.pending_request["request_id"],
                          "intent_sha256": supervisor.intent_sha256, "claim_sha256": durable.digest(durable.canonical(result)),
                          "outcome": "baseline_restored", "evidence_sha256": "e" * 64}
                supervisor.record_worker_result(report, peer=result["peer"], observer=observer,
                                                peer_alive=lambda: True, deadline=deadline)
                state = supervisor.observe_result(observer=observer, oracle=result_oracle, deadline=deadline)
                if not state["worker_result_observed"]:
                    raise durable.Rejected("synthetic-result-refused")
            return result
        value.close, value.accept_once = close, accept_once
        return value

    def serve(self, **kwargs):
        args = dict(endpoint=self.endpoint_approval, deadline=1170.0, fence=self.fence,
            persist_alert=self.persist, transport_alert=lambda value: self.notices.append(value) or True,
            clock=lambda: self.fixture.now, boot_id=lambda: self.owner["boot_id"])
        args.update(kwargs)
        with patch.object(launch, "SystemdSupervisorIdentity", return_value=self.identity), \
                patch.object(broker, "SystemdRecoveryJobs", return_value=self.job), \
                patch.object(broker, "WorkerListener", side_effect=self.listener):
            return broker.serve_claim(self.fixture.approval, **args)

    def original(self):
        return {name: (self.installation.journal / name).read_bytes()
                for name in ("intent.json", "arm.json", "reconcile-request.json")}

    def assert_no_grants(self, result):
        for key in ("complete_fence_proven", "recovery_execution_allowed", "start_allowed",
                    "terminal_outcome_verified", "production_acceptance", "restoration_permission",
                    "recovery_completed", "peer_acknowledgment_verified"):
            self.assertIs(result[key], False)

    def test_claim_composes_original_inputs_and_retains_same_lock_without_grants(self):
        original = self.original()
        result = self.serve()
        self.assertEqual(result["state"], "identity_reply_sent_only")
        self.assertTrue(result["claim_recorded"])
        self.assertTrue(result["claim_reply_sent"])
        self.assert_no_grants(result)
        self.assertEqual(original, self.original())
        self.assertTrue(all(value.closed for value in self.listeners))
        self.assertTrue(self.process.closed)
        self.assertEqual(self.notices, [])
        self.assertTrue(self.deadlines and all(value == 1170.0 for value in self.deadlines))
        self.unlocked()
        raw = durable.canonical(result)
        for secret in (str(self.installation.root), "fixture-nonce", "synthetic/worker", '"peer"'):
            self.assertNotIn(secret.encode(), raw)

    def test_result_oracle_composes_same_lock_and_does_not_settle_installation(self):
        original = self.original()
        calls = []
        def oracle(intent, report, *, deadline):
            self.locked()
            calls.append(deadline)
            return outcomes.expected_oracle(intent, report)
        result = self.serve(result_oracle=oracle)
        self.assertEqual(result["operation"], "claim_and_result")
        self.assertEqual(result["state"], "result_observed_unsettled")
        self.assertTrue(result["worker_result_observed"])
        self.assertFalse(result["installation_settled"])
        self.assert_no_grants(result)
        self.assertEqual(calls, [1170.0])
        self.assertEqual(original, self.original())
        self.unlocked()

    def test_result_oracle_refusal_cannot_return_claim_only_success(self):
        with self.assertRaises(durable.Rejected):
            self.serve(result_oracle=lambda *args, **kw: True)
        self.assertFalse(self.process.status()["worker_result_observed"])
        self.assertTrue(self.process.closed)
        self.assertTrue(self.notices)
        self.assertTrue((self.installation.journal / "reconcile-result.json").exists())
        self.assertFalse((self.installation.journal / "reconcile-result-observed.json").exists())
        self.unlocked()

    def test_caller_deadline_never_extends_original_request(self):
        self.assert_no_grants(self.serve(deadline=9999))
        self.assertTrue(all(value == 1180.0 for value in self.deadlines))

    def test_prior_claim_cannot_be_replied_to_again(self):
        self.serve()
        saved = (self.installation.journal / "reconcile-worker.json").read_bytes()
        with self.assertRaises(durable.Rejected):
            self.serve()
        self.assertEqual(len(self.listeners), 1)
        self.assertEqual(saved, (self.installation.journal / "reconcile-worker.json").read_bytes())
        self.unlocked()

    def test_invalid_boundary_policy_refuses_before_manager(self):
        for kwargs in ({"endpoint": None}, {"fence": None}, {"persist_alert": None}, {"transport_alert": None},
                       {"endpoint": replace(self.endpoint_approval, mode=0o755)}):
            with self.subTest(kwargs=kwargs), self.assertRaises(durable.Rejected):
                self.serve(**kwargs)
        self.identity.bootstrap.assert_not_called()
        self.assertEqual(self.listeners, [])

    def test_foreign_endpoint_owner_or_nested_protected_root_refuses_before_socket(self):
        for endpoint in (replace(self.endpoint_approval, uid=os.geteuid() + 1),
                         approve(self.installation.content), approve(self.installation.journal)):
            with self.subTest(endpoint=endpoint), self.assertRaises(durable.Rejected):
                self.serve(endpoint=endpoint)
        self.assertEqual(self.listeners, [])
        self.unlocked()

    def test_endpoint_replacement_during_fence_refuses_and_closes_listener(self):
        moved = self.installation.root / "old-ipc"
        def change():
            self.endpoint.rename(moved)
            self.endpoint.mkdir(mode=0o700)
        self.on_fence = change
        with self.assertRaises(durable.Rejected):
            self.serve()
        self.assertTrue(self.listeners[0].closed)
        self.assertFalse((self.installation.journal / "reconcile-worker.json").exists())
        self.assertTrue(self.notices)
        self.unlocked()

    def test_endpoint_is_revalidated_on_context_exit_after_reply(self):
        def change(process):
            self.endpoint.rename(self.installation.root / "old-ipc")
            self.endpoint.mkdir(mode=0o700)
        self.after_reply = change
        with self.assertRaises(durable.Rejected):
            self.serve()
        self.assertTrue((self.installation.journal / "reconcile-worker.json").exists())
        self.assertTrue(self.notices)
        self.unlocked()

    def test_fence_denial_or_nonboolean_never_creates_claim(self):
        for value in (False, 1, None, "yes"):
            self.fenced = value
            with self.subTest(value=value), self.assertRaises(durable.Rejected):
                self.serve()
            self.assertFalse((self.installation.journal / "reconcile-worker.json").exists())
        self.assertTrue(all(value.closed for value in self.listeners))
        self.unlocked()

    def test_pinned_content_change_in_fence_prevents_claim(self):
        self.on_fence = lambda: (self.installation.content / "settings.json").write_bytes(b"changed")
        with self.assertRaises(durable.Rejected):
            self.serve()
        self.assertFalse((self.installation.journal / "reconcile-worker.json").exists())
        self.assertTrue(self.notices)

    def test_original_request_change_in_fence_is_not_adopted(self):
        self.on_fence = lambda: (self.installation.journal / "reconcile-request.json").write_bytes(b"{}")
        with self.assertRaises(durable.Rejected):
            self.serve()
        self.assertFalse((self.installation.journal / "reconcile-worker.json").exists())
        self.assertTrue(self.notices)

    def test_replacement_supervisor_refuses_before_socket_even_with_original_files(self):
        self.identity.observe_owner.return_value = {**self.owner, "invocation_id": "e" * 32}
        with self.assertRaises(durable.Rejected):
            self.serve()
        self.assertEqual(self.listeners, [])
        self.assertTrue(self.notices)

    def test_bootstrap_failure_attempts_independent_alert_despite_disk_failure(self):
        self.identity.bootstrap.side_effect = OSError(errno.EIO, "restricted synthetic path")
        self.persist = lambda _: (_ for _ in ()).throw(OSError(errno.ENOSPC, "private path"))
        with self.assertRaisesRegex(durable.Rejected, "^broker-claim-unconfirmed$"):
            self.serve()
        self.assertEqual(len(self.notices), 1)
        self.assertNotIn(b"private path", durable.canonical(self.notices))
        self.assertEqual(self.listeners, [])

    def test_context_exit_failure_after_reply_never_returns_receipt(self):
        self.after_reply = lambda process: (self.installation.content / "settings.json").write_bytes(b"changed")
        with self.assertRaises(durable.Rejected):
            self.serve()
        self.assertTrue((self.installation.journal / "reconcile-worker.json").exists())
        self.assertEqual(len(self.notices), 1)
        self.assertTrue(self.process.closed)
        self.unlocked()

    def test_claim_persistence_fault_retains_originals_and_attempts_alert(self):
        original = self.original()
        self.persist = lambda _: (_ for _ in ()).throw(OSError(errno.EIO, "private path"))
        for phase in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
            for code in (errno.EIO, errno.ENOSPC):
                with self.subTest(phase=phase, code=code):
                    self.notices.clear()
                    reached = []
                    def fault(point):
                        if point == phase:
                            reached.append(point)
                            raise OSError(code, "private path")
                    def prepare(process):
                        # Observe/bind the worker before isolating the claim-write
                        # fault. Assert the exact hook fires, not a signature error.
                        process._observe_pending(observer=self.job, deadline=1170.0)
                        self.assertIsNone(process.error)
                        process.log.fault = fault
                    self.on_accept = prepare
                    with self.assertRaises(durable.Rejected):
                        self.serve()
                    self.assertEqual(reached, [phase])
                    self.assertTrue(self.process.log.uncertain)
                    self.assertEqual(self.original(), original)
                    self.assertTrue(self.notices)
                    self.assertTrue(all(value.closed for value in self.listeners))
                    self.unlocked()
                    # Reset only this owned synthetic fixture between fault cases.
                    for path in self.installation.journal.iterdir():
                        if path.name not in original:
                            path.unlink()

    def test_listener_bind_failure_is_not_retried_or_unlinked(self):
        def unavailable(*args, **kwargs):
            raise FileExistsError("retained endpoint")
        self.listener = unavailable
        original = self.original()
        with self.assertRaises(durable.Rejected):
            self.serve()
        self.assertEqual(self.original(), original)
        self.assertTrue(self.notices)
        self.unlocked()

    def test_deadline_expiry_after_claim_never_returns_success(self):
        self.after_reply = lambda process: setattr(self.fixture, "now", 1170.0)
        with self.assertRaises(durable.Rejected):
            self.serve()
        self.assertTrue((self.installation.journal / "reconcile-worker.json").exists())
        self.assertTrue(self.notices)
        self.unlocked()

    def test_claim_or_binding_change_after_reply_never_returns_recorded_receipt(self):
        original = self.original()
        for name in ("reconcile-worker.json", "reconcile-observed.json"):
            with self.subTest(name=name):
                self.after_reply = lambda process: (self.installation.journal / name).write_bytes(b"{}")
                with self.assertRaises(durable.Rejected):
                    self.serve()
                self.assertTrue(self.notices)
                self.assertTrue(self.process.closed)
                self.unlocked()
                for path in self.installation.journal.iterdir():
                    if path.name not in original:
                        path.unlink()

    def test_final_manager_read_cannot_conceal_saved_claim_tamper(self):
        changed = []
        def observe(*args, **kwargs):
            if self.process is not None and self.process.closed:
                (self.installation.journal / "reconcile-worker.json").write_bytes(b"{}")
                changed.append(True)
            return self.owner
        self.identity.observe_owner.side_effect = observe
        with self.assertRaises(durable.Rejected):
            self.serve()
        self.assertEqual(changed, [True])
        self.assertTrue(self.notices)
        self.unlocked()

    def test_listener_close_failure_still_revokes_borrowed_supervisor(self):
        def changed(process):
            def close():
                raise OSError(errno.EIO, "synthetic close failure")
            self.listeners[-1].close = close
        self.after_reply = changed
        with self.assertRaises(durable.Rejected):
            self.serve()
        self.assertTrue(self.process.closed)
        self.assertTrue(self.notices)
        self.unlocked()

    def test_captured_supervisor_and_session_cannot_be_reused_after_exit(self):
        self.serve()
        with self.assertRaises(durable.Rejected):
            self.process.manager.observe_owner(self.owner, deadline=1170.0)
        with self.assertRaises(durable.Rejected):
            self.process.reconcile(deadline=1170.0)
        self.assertFalse(hasattr(self.process.manager, "enqueue_recovery"))

    def test_numeric_worker_owner_mismatch_refuses_even_with_matching_static_pin(self):
        request_id = self.fixture.approval.job.request_id
        for changed in ("User", "Group"):
            row = observed(jobs.recovery_unit(request_id), self.invocation, "/synthetic/worker.service")
            row.update(MainPID=str(self.pid), User=str(os.geteuid()), Group=str(os.getegid()))
            row[changed] = str(os.geteuid() + 1)
            binding = jobs.RecoveryJobBinding(request_id, row["FragmentPath"], "f" * 64,
                durable.digest(durable.canonical(manager.static_properties(row))))
            self.job = jobs.SystemdRecoveryJobs(systemctl="/synthetic/systemctl",
                commands=SimpleNamespace(run=lambda *a, **kw: encoded(row)), binding=binding,
                boot_id=lambda: self.owner["boot_id"], clock=lambda: self.fixture.now,
                read_fragment_hash=lambda _: "f" * 64, read_process_cgroup=lambda _: row["ControlGroup"])
            with self.subTest(changed=changed), self.assertRaises(durable.Rejected):
                self.serve()
            self.assertFalse((self.installation.journal / "reconcile-worker.json").exists())
        self.unlocked()

    def test_actual_ipc_with_real_parsers_scripted_manager_and_no_host_operation(self):
        supervisor_row = self.fixture.manager_fixture()
        self.owner = durable.decode((self.installation.journal / "reconcile-request.json").read_bytes())["owner"]
        fragment = self.installation.root / "worker.service"
        fragment.write_bytes(b"synthetic worker unit, never installed\n")
        fragment.chmod(0o600)
        row = observed(jobs.recovery_unit(self.fixture.approval.job.request_id), "c" * 32,
                       "/synthetic/worker.service")
        row.update(FragmentPath=str(fragment), MainPID="123", User=str(os.geteuid()), Group=str(os.getegid()))
        self.fixture.approval = replace(self.fixture.approval, job=replace(self.fixture.approval.job,
            fragment_path=str(fragment), fragment_sha256=durable.digest(fragment.read_bytes()),
            properties_sha256=durable.digest(durable.canonical(manager.static_properties(row)))))
        children, calls = [], []
        def cleanup():
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                for stream in (child.stdin, child.stdout, child.stderr):
                    stream.close()
        self.addCleanup(cleanup)
        actual_identity = bootstrap.SystemdSupervisorIdentity
        def identity(**kwargs):
            return actual_identity(**kwargs, read_process_cgroup=lambda pid: supervisor_row["ControlGroup"])
        actual_jobs = jobs.SystemdRecoveryJobs
        def observer(**kwargs):
            return actual_jobs(**kwargs, read_process_cgroup=lambda pid: row["ControlGroup"])
        def run(argv, *, deadline):
            calls.append(argv)
            self.assertEqual(argv[1:3], ("--no-pager", "show"))
            self.assertIn(argv[-1], (supervisor_row["Id"], row["Id"]))
            return encoded(supervisor_row if argv[-1] == supervisor_row["Id"] else row)
        def listener(path, **kwargs):
            value = worker.WorkerListener(path, **kwargs)
            # The descriptor-relative path is deliberately short even when the
            # protected synthetic directory has a long absolute pathname.
            child = subprocess.Popen([sys.executable, "-I", "-c", CLIENT, str(ROOT), path, str(os.getpid()),
                json.dumps(self.owner), self.fixture.approval.job.request_id,
                self.fixture.approval.recovery.intent_sha256], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            row["MainPID"] = str(child.pid)
            children.append(child)
            return value
        original = self.original()
        with patch.object(launch, "SystemdSupervisorIdentity", side_effect=identity), \
                patch.object(broker, "SystemdRecoveryJobs", side_effect=observer), \
                patch.object(broker, "WorkerListener", side_effect=listener):
            result = broker.serve_claim(self.fixture.approval, endpoint=self.endpoint_approval,
                deadline=1055.0, fence=self.fence, persist_alert=self.persist,
                transport_alert=lambda notice: self.notices.append(notice) or True, clock=lambda: self.fixture.now,
                boot_id=lambda: test_bootstrap.BOOT, commands=SimpleNamespace(run=run))
        self.assert_no_grants(result)
        self.assertEqual(original, self.original())
        child = children[0]
        with selectors.DefaultSelector() as wait:
            wait.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(wait.select(5), "worker did not receive claim")
        claim = json.loads(child.stdout.readline())
        self.assertEqual(claim["peer"]["pid"], child.pid)
        self.assertEqual(claim, durable.decode((self.installation.journal / "reconcile-worker.json").read_bytes()))
        self.assertIs(claim["start_permission"], False)
        child.stdin.write(b"done\n")
        child.stdin.flush()
        self.assertEqual(child.wait(timeout=5), 0)
        self.assertTrue(calls)
        self.assertEqual(self.notices, [])
        self.unlocked()
        # Retained socket inode and saved claim are not an invitation to retry.
        self.assertTrue((self.endpoint / ("claim-" + result["request_id"] + ".sock")).is_socket())

    def test_actual_broker_sigkill_after_durable_claim_keeps_lock_until_exit_and_cannot_replay(self):
        supervisor_row = self.fixture.manager_fixture()
        request = durable.decode((self.installation.journal / "reconcile-request.json").read_bytes())
        self.owner = request["owner"]
        fragment = self.installation.root / "worker.service"
        fragment.write_bytes(b"synthetic worker unit, never installed\n")
        fragment.chmod(0o600)
        row = observed(jobs.recovery_unit(request["request_id"]), "c" * 32, "/synthetic/worker.service")
        row.update(FragmentPath=str(fragment), User=str(os.geteuid()), Group=str(os.getegid()))
        self.fixture.approval = replace(self.fixture.approval, job=replace(self.fixture.approval.job,
            fragment_path=str(fragment), fragment_sha256=durable.digest(fragment.read_bytes()),
            properties_sha256=durable.digest(durable.canonical(manager.static_properties(row)))))
        payload = {"approval": {"schema": "host-recovery-launch-v1", **asdict(self.fixture.approval)},
                   "endpoint": asdict(self.endpoint_approval), "supervisor": supervisor_row, "worker": row,
                   "boot": test_bootstrap.BOOT}
        source = r'''
import json,os,sys
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
from host_recovery import bootstrap,broker,jobs,launch,worker
from host_recovery.durable import canonical
from host_recovery.installation import DirectoryApproval
value=json.loads(sys.argv[2])
parent,child=value['supervisor'],value['worker']
parent['MainPID']=str(os.getpid())
approval=launch.parse_launch(canonical(value['approval']))
actual_identity=bootstrap.SystemdSupervisorIdentity
actual_jobs=jobs.SystemdRecoveryJobs
actual_listener=worker.WorkerListener
actual_reply=worker.PeerSession.reply
def identity(**kwargs):
    return actual_identity(**kwargs,read_process_cgroup=lambda pid: parent['ControlGroup'])
def observer(**kwargs):
    return actual_jobs(**kwargs,read_process_cgroup=lambda pid: child['ControlGroup'])
def command(argv,*,deadline):
    assert argv[1:3]==('--no-pager','show')
    assert argv[-1] in (parent['Id'],child['Id'])
    row=parent if argv[-1]==parent['Id'] else child
    return ''.join(key+'='+item+'\n' for key,item in row.items()).encode()
def listener(path,**kwargs):
    result=actual_listener(path,**kwargs)
    print('listening',flush=True)
    child['MainPID']=sys.stdin.readline().strip()
    return result
def reply(self,value,deadline):
    print('claim-durable',flush=True)
    sys.stdin.readline()
    return actual_reply(self,value,deadline)
with patch.object(launch,'SystemdSupervisorIdentity',side_effect=identity), \
     patch.object(broker,'SystemdRecoveryJobs',side_effect=observer), \
     patch.object(broker,'WorkerListener',side_effect=listener), \
     patch.object(worker.PeerSession,'reply',reply):
    broker.serve_claim(approval,endpoint=DirectoryApproval(**value['endpoint']),deadline=1055.0,
        fence=lambda *a,**kw: True,persist_alert=lambda _: None,transport_alert=lambda _: True,
        clock=lambda: 1050.0,boot_id=lambda: value['boot'],commands=SimpleNamespace(run=command))
'''
        children = []
        def cleanup():
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                for stream in (child.stdin, child.stdout, child.stderr):
                    stream.close()
        self.addCleanup(cleanup)
        def line(child):
            with selectors.DefaultSelector() as wait:
                wait.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(wait.select(8), "broker synchronization failed")
            result = child.stdout.readline()
            if not result:
                self.fail("broker exited: " + child.stderr.read().decode())
            return result
        server = subprocess.Popen([sys.executable, "-I", "-c", source, str(ROOT), json.dumps(payload)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(server)
        self.assertEqual(line(server), b"listening\n")
        path = str(self.endpoint / ("claim-" + request["request_id"] + ".sock"))
        client = subprocess.Popen([sys.executable, "-I", "-c", CLIENT, str(ROOT), path, str(server.pid),
            json.dumps(self.owner), request["request_id"], request["intent_sha256"]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(client)
        server.stdin.write((str(client.pid) + "\n").encode())
        server.stdin.flush()
        self.assertEqual(line(server), b"claim-durable\n")
        self.locked()
        claim_path = self.installation.journal / "reconcile-worker.json"
        saved = claim_path.read_bytes()
        self.assertEqual(durable.decode(saved)["peer"]["pid"], client.pid)
        server.kill()
        self.assertEqual(server.wait(timeout=5), -9)
        self.assertEqual(line(client), b"Rejected\n")
        self.assertEqual(client.wait(timeout=5), 2)
        self.unlocked()
        self.assertEqual(saved, claim_path.read_bytes())
        self.identity.bootstrap.return_value = {"owner": self.owner}
        self.identity.observe_owner.return_value = self.owner
        with self.assertRaises(durable.Rejected):
            self.serve()
        self.assertEqual(self.listeners, [])
        self.assertEqual(saved, claim_path.read_bytes())
        self.assertTrue(Path(path).is_socket())
