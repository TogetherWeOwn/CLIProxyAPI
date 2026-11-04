"""Real Linux peer IPC/process loss; SCRIPTED manager/fence, not systemd recovery."""
import copy
import errno
import io
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from host_recovery import alert, durable, jobs, manager, supervisor, worker
import test_alert
from test_manager import encoded, observed
import test_supervisor


class WorkerObservationTests(unittest.TestCase):
    def setUp(self):
        self.request_id = "d" * 64
        self.group = "/recovery/worker.service"
        self.pid = os.getpid()
        self.row = observed(jobs.recovery_unit(self.request_id), "b" * 32, self.group)
        self.row["MainPID"] = str(self.pid)
        self.binding = jobs.RecoveryJobBinding(self.request_id, self.row["FragmentPath"], "f" * 64,
            durable.digest(durable.canonical(manager.static_properties(self.row))))
        self.reader = lambda _: self.group
        self.engine = jobs.SystemdRecoveryJobs(systemctl="/scripted/systemctl",
            commands=SimpleNamespace(run=lambda *a, **kw: encoded(self.row)), binding=self.binding,
            boot_id=lambda: "boot-a", clock=lambda: 1050, read_fragment_hash=lambda _: "f" * 64,
            read_process_cgroup=lambda pid: self.reader(pid))

    def observe(self):
        return self.engine.observe_worker(self.request_id, pid=self.pid, deadline=1100)

    def test_observes_pinned_running_mainpid_and_actual_cgroup_boundary(self):
        value = self.observe()
        jobs.validate_worker(value, self.request_id, "boot-a", self.pid)
        self.assertEqual(value["cgroup"], self.group)
        self.assertEqual(value["pid"], self.pid)

    def test_wrong_mainpid_cgroup_or_pending_job_refuses(self):
        for change in ({"MainPID": str(self.pid + 1)}, {"ControlGroup": "/other"}, {"Job": "5"},
                       {"ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}):
            with self.subTest(change=change):
                self.setUp()
                self.row.update(change)
                with self.assertRaises(durable.Rejected):
                    self.observe()

    def test_process_membership_loss_or_migration_refuses(self):
        calls = []
        def read(pid):
            calls.append(pid)
            return self.group if len(calls) == 1 else "/other"
        self.reader = read
        with self.assertRaises(durable.Rejected):
            self.observe()
        self.reader = lambda _: (_ for _ in ()).throw(OSError(errno.ENOENT, "gone"))
        with self.assertRaises(OSError):
            self.observe()

    def test_kernel_reader_requires_single_unified_safe_cgroup(self):
        for raw in (b"0::/recovery/worker.service\n",):
            with patch("builtins.open", return_value=io.BytesIO(raw)):
                self.assertEqual(jobs.process_cgroup(self.pid), self.group)
        for raw in (b"0::/\n", b"0::/a/../b\n", b"1:cpu:/a\n", b"0::/a\n1:cpu:/b\n", b"0::/a", b"\xff"):
            with self.subTest(raw=raw), patch("builtins.open", return_value=io.BytesIO(raw)):
                with self.assertRaises(durable.Rejected):
                    jobs.process_cgroup(self.pid)
        for pid in (True, 0, -1, "1", 2147483648):
            with self.subTest(pid=pid), self.assertRaises(durable.Rejected):
                jobs.process_cgroup(pid)

    def test_worker_observation_schema_never_coerces_numeric_or_state_fields(self):
        value = self.observe()
        for change in ({"pid": True}, {"pid": str(self.pid)}, {"job_id": False}, {"state": "pending"},
                       {"cgroup": "/a/../b"}, {"extra": True}, {"invocation_id": ""}):
            with self.subTest(change=change), self.assertRaises(durable.Rejected):
                jobs.validate_worker({**value, **change}, self.request_id, "boot-a", self.pid)


class WorkerClaimTests(unittest.TestCase):
    def setUp(self):
        self.case = test_supervisor.SupervisorTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.pid = os.getpid()
        self.peer = {"pid": self.pid, "uid": os.geteuid(), "gid": os.getegid()}
        self.alive = True
        self.change = lambda: None
        self.group = "/recovery/worker.service"
        self.invocation = "b" * 32
        self.claims = 0
        self.observer = SimpleNamespace(observe=self.observe, observe_worker=self.observe_worker)

    def observe(self, request_id, *, deadline):
        return {"schema": "host-recovery-job-observation-v1", "request_id": request_id,
                "boot_id": "boot-a", "unit": jobs.recovery_unit(request_id), "invocation_id": self.invocation,
                "state": "running", "job_id": 0}

    def observe_worker(self, request_id, *, pid, deadline):
        self.claims += 1
        self.change()
        return {**self.observe(request_id, deadline=deadline), "pid": pid, "cgroup": self.group}

    def claim(self, process, **kw):
        return process.claim_worker(peer=kw.get("peer", self.peer), nonce=kw.get("nonce", "synthetic-nonce"),
            observer=self.observer, peer_alive=lambda: self.alive, deadline=1100)

    def test_durable_identity_claim_has_no_restoration_or_start_grant(self):
        with self.case.open() as process:
            process.reconcile(deadline=1100)
            value = self.claim(process)
            self.assertEqual(durable.decode((self.case.root / "reconcile-worker.json").read_bytes()), value)
            self.assertEqual(value["supervisor_owner"], self.case.owner)
            self.assertFalse(value["restoration_permission"])
            self.assertFalse(value["start_permission"])
            self.case.assert_fenced(process.status())
            self.assertEqual(process._observe_pending(observer=self.observer, deadline=1100)["state"],
                             "recovery_job_running")
            with self.assertRaises(durable.Rejected):
                self.claim(process)
        with self.case.open() as reopened:
            with self.assertRaises(durable.Rejected):
                self.claim(reopened)
        with supervisor.recovery_owner(str(self.case.root), owner=self.case.owner, manager=self.case.manager,
                clock=lambda: self.case.now, boot_id=lambda: self.case.boot, persist_alert=lambda _: None,
                transport_alert=lambda _: True, observe_existing=True) as reopened:
            self.assertIsNone(reopened.error)
            self.assertTrue(reopened.status()["saved_claim_observed"])
            self.assertFalse(reopened.status()["saved_peer_liveness_proven"])
            self.assertTrue(reopened.worker_attempted)

    def test_no_claim_before_dispatch_or_after_close(self):
        with self.case.open() as process:
            with self.assertRaises(durable.Rejected):
                self.claim(process)
            process.reconcile(deadline=1100)
        with self.assertRaises(durable.Rejected):
            self.claim(process)
        self.assertFalse((self.case.root / "reconcile-worker.json").exists())

    def test_peer_or_nonce_schema_refuses_and_cannot_be_retried(self):
        for peer, nonce in (({**self.peer, "uid": 0}, "ok"), ({**self.peer, "pid": True}, "ok"),
                            ({**self.peer, "extra": 1}, "ok"), (self.peer, "bad\nnonce")):
            with self.subTest(peer=peer, nonce=nonce):
                self.setUp()
                with self.case.open() as process:
                    process.reconcile(deadline=1100)
                    with self.assertRaises(durable.Rejected):
                        self.claim(process, peer=peer, nonce=nonce)
                    with self.assertRaises(durable.Rejected):
                        self.claim(process)
                    self.assertTrue(process.status()["alert"]["transport_delivered"])
                self.assertFalse((self.case.root / "reconcile-worker.json").exists())

    def test_peer_invocation_clock_fence_and_file_changes_refuse(self):
        for kind in ("peer", "invocation", "clock", "fence", "file", "group"):
            with self.subTest(kind=kind):
                self.setUp()
                with self.case.open() as process:
                    process.reconcile(deadline=1100)
                    def change():
                        if kind == "peer":
                            self.alive = False
                        elif kind == "invocation":
                            self.invocation = "c" * 32
                        elif kind == "clock":
                            self.case.now = 1100
                        elif kind == "fence":
                            self.case.manager.fenced = False
                        elif kind == "file":
                            (self.case.root / "reconcile-request.json").write_bytes(b"{}\n")
                        else:
                            self.group = "/other" if self.claims == 2 else self.group
                    self.change = change
                    with self.assertRaises(durable.Rejected):
                        self.claim(process)
                    self.case.assert_fenced(process.status())
                self.assertFalse((self.case.root / "reconcile-worker.json").exists())

    def test_each_claim_persistence_fault_refuses_acknowledgment_and_retains_intent(self):
        for phase in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
            for code in (errno.EIO, errno.ENOSPC):
                with self.subTest(phase=phase, code=code):
                    self.setUp()
                    with self.case.open() as process:
                        process.reconcile(deadline=1100)
                        def fault(point):
                            if point == phase:
                                raise OSError(code, "restricted synthetic path")
                        process._observe_pending(observer=self.observer, deadline=1100)
                        process.log.fault = fault
                        with self.assertRaises(durable.Rejected):
                            self.claim(process)
                        self.assertTrue(process.log.uncertain)
                        self.assertTrue(process.status()["alert"]["transport_delivered"])
                    self.assertEqual((self.case.root / "intent.json").read_bytes(), self.case.original)

    def test_post_persistence_peer_loss_or_tamper_prevents_reply(self):
        for kind in ("peer", "claim", "fence", "binding"):
            with self.subTest(kind=kind):
                self.setUp()
                with self.case.open() as process:
                    process.reconcile(deadline=1100)
                    def change():
                        if self.claims == 3:
                            if kind == "peer":
                                self.alive = False
                            elif kind == "claim":
                                (self.case.root / "reconcile-worker.json").write_bytes(b"{}\n")
                            elif kind == "binding":
                                (self.case.root / "reconcile-observed.json").write_bytes(b"{}\n")
                            else:
                                self.case.manager.fenced = False
                    self.change = change
                    with self.assertRaises(durable.Rejected):
                        self.claim(process)
                    self.assertTrue((self.case.root / "reconcile-worker.json").exists())
                    self.case.assert_fenced(process.status())


CLIENT = r'''
import json,os,sys,time
sys.path.insert(0,sys.argv[1])
from host_recovery.worker import WorkerClient
client=WorkerClient(sys.argv[2], supervisor_uid=os.geteuid(), supervisor_pid=int(sys.argv[3]),
                    supervisor_owner=json.loads(sys.argv[4]),request_id=sys.argv[5],intent_sha256=sys.argv[6])
try:
    value=client.claim(deadline=time.monotonic()+8)
    print(json.dumps(value),flush=True)
    sys.stdin.readline()
except Exception as failure:
    print(type(failure).__name__,flush=True)
    sys.exit(2)
'''


class WorkerIPCTests(unittest.TestCase):
    def setUp(self):
        self.case = WorkerClaimTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.temp = tempfile.TemporaryDirectory(prefix="worker-ipc-")
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "worker.sock")
        self.listener = worker.WorkerListener(self.path, worker_uid=os.geteuid())
        self.addCleanup(self.listener.close)
        self.children = []
        self.addCleanup(self.stop_children)

    def stop_children(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream:
                    stream.close()

    def start(self, process, source=CLIENT, *args):
        child = subprocess.Popen([sys.executable, "-I", "-c", source,
            str(Path(__file__).resolve().parent.parent), self.path, str(os.getpid()),
            json.dumps(process.owner), process.pending_request["request_id"], process.intent_sha256, *args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(child)
        self.case.pid = child.pid
        return child

    def read(self, child):
        with selectors.DefaultSelector() as wait:
            wait.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(wait.select(10), "worker did not finish handshake")
        return child.stdout.readline()

    def prepare(self):
        now = time.monotonic()
        self.case.case.now = now
        with durable.directory(self.case.case.root, private=True) as fd:
            value = durable.decode((self.case.case.root / "arm.json").read_bytes())
            value["arm"]["monotonic"] = now - 1
            durable.atomic_write(fd, "arm.json", durable.canonical(value))

    def serve(self, process):
        return self.listener.accept_once(supervisor=process, observer=self.case.observer,
                                         deadline=process.pending_request["deadline"])

    def test_real_separate_process_peer_claim_is_durable_and_lock_is_retained(self):
        self.prepare()
        with self.case.case.open() as process:
            process.reconcile(deadline=self.case.case.now + 8)
            child = self.start(process)
            claim = self.serve(process)
            value = json.loads(self.read(child))
            self.assertEqual(value, claim)
            self.assertEqual(claim["peer"]["pid"], child.pid)
            self.assertEqual(claim["worker"]["pid"], child.pid)
            self.assertFalse(claim["start_permission"])
            with self.assertRaises(BlockingIOError), self.case.case.open():
                self.fail("supervisor lock lost during worker handshake")
            with self.assertRaises(durable.Rejected):
                self.serve(process)
            child.stdin.write(b"done\n")
            child.stdin.flush()
            self.assertEqual(child.wait(timeout=5), 0)
        self.assertEqual(durable.decode((self.case.case.root / "reconcile-worker.json").read_bytes()), claim)

    def test_dead_connecting_peer_is_not_replaced_by_numeric_pid_lookup(self):
        self.prepare()
        source = "import socket,sys\ns=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)\ns.connect(sys.argv[2])\n"
        with self.case.case.open() as process:
            process.reconcile(deadline=self.case.case.now + 8)
            child = self.start(process, source)
            self.assertEqual(child.wait(timeout=5), 0)
            with self.assertRaises((durable.Rejected, OSError)):
                self.serve(process)
            self.assertFalse((self.case.case.root / "reconcile-worker.json").exists())

    def test_wrong_manager_mainpid_cannot_claim_despite_same_uid(self):
        self.prepare()
        with self.case.case.open() as process:
            process.reconcile(deadline=self.case.case.now + 8)
            child = self.start(process)
            original = self.case.observe_worker
            self.case.observer.observe_worker = lambda *a, **kw: {**original(*a, **kw), "pid": child.pid + 1}
            with self.assertRaises(durable.Rejected):
                self.serve(process)
            self.assertEqual(self.read(child), b"Rejected\n")
            self.assertFalse((self.case.case.root / "reconcile-worker.json").exists())

    def test_connected_descriptor_passed_to_descendant_is_not_message_identity(self):
        self.prepare()
        source = r'''
import os,socket,sys,json
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
s.connect(sys.argv[2])
pid=os.fork()
if pid==0:
    s.send(json.dumps({"schema":"host-recovery-worker-request-v1","request_id":sys.argv[5],"nonce":"forked"}).encode())
    sys.stdin.readline()
    os._exit(0)
os.waitpid(pid,0)
'''
        with self.case.case.open() as process:
            process.reconcile(deadline=self.case.case.now + 8)
            child = self.start(process, source)
            # Parent exits only once its descendant is done; both share the test
            # pipe, so cleanup can release it without leaving an orphan.
            try:
                with self.assertRaises((durable.Rejected, OSError)):
                    self.serve(process)
                self.assertFalse((self.case.case.root / "reconcile-worker.json").exists())
            finally:
                child.stdin.write(b"done\n")
                child.stdin.flush()
                child.wait(timeout=5)

    def test_sigkill_supervisor_after_durable_claim_does_not_ack_or_replay(self):
        self.prepare()
        path = str(Path(self.temp.name) / "crash.sock")
        source = r'''
import json,os,sys,time
from types import SimpleNamespace
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tests"]
from host_recovery import supervisor,worker,jobs
from test_supervisor import ScriptedManager
owner=json.loads(sys.argv[4])
listener=worker.WorkerListener(sys.argv[2],worker_uid=os.geteuid())
def observe(request_id,**kw):
    return {"schema":"host-recovery-job-observation-v1","request_id":request_id,"boot_id":"boot-a",
            "unit":jobs.recovery_unit(request_id),"invocation_id":"b"*32,"state":"running","job_id":0}
def observe_worker(request_id,*,pid,deadline):
    return {**observe(request_id),"pid":pid,"cgroup":"/scripted/recovery.service"}
def hold_reply(self,value,deadline):
    print("CLAIMED",flush=True)
    sys.stdin.readline()
worker.PeerSession.reply=hold_reply
with supervisor.recovery_owner(sys.argv[3],owner=owner,manager=ScriptedManager(),clock=time.monotonic,
        boot_id=lambda:"boot-a",persist_alert=lambda _:None,transport_alert=lambda _:True) as process:
    process.reconcile(deadline=time.monotonic()+15)
    print(json.dumps({"request_id":process.pending_request["request_id"],"intent_sha256":process.intent_sha256}),flush=True)
    listener.accept_once(supervisor=process,observer=SimpleNamespace(observe=observe,observe_worker=observe_worker),
                         deadline=process.pending_request["deadline"])
'''
        tests = Path(__file__).resolve().parent
        server = subprocess.Popen([sys.executable, "-I", "-c", source, str(tests.parent), path,
                                   str(self.case.case.root), json.dumps(self.case.case.owner)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(server)
        pins = json.loads(self.read(server))
        client = subprocess.Popen([sys.executable, "-I", "-c", CLIENT, str(tests.parent), path, str(server.pid),
                                   json.dumps(self.case.case.owner), pins["request_id"], pins["intent_sha256"]],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(client)
        self.assertEqual(self.read(server), b"CLAIMED\n")
        self.assertTrue((self.case.case.root / "reconcile-worker.json").exists())
        with self.assertRaises(BlockingIOError), self.case.case.open():
            self.fail("supervisor lost lock before claim ACK")
        server.kill()
        self.assertEqual(server.wait(timeout=5), -9)
        self.assertEqual(self.read(client), b"Rejected\n")
        self.assertEqual(client.wait(timeout=5), 2)
        with supervisor.recovery_owner(str(self.case.case.root), owner=self.case.case.owner,
                manager=self.case.case.manager, clock=time.monotonic, boot_id=lambda: "boot-a",
                persist_alert=lambda _: None, transport_alert=lambda _: True, observe_existing=True) as reopened:
            self.assertIsNone(reopened.error)
            self.assertTrue(reopened.status()["saved_claim_observed"])
            self.assertFalse(reopened.status()["saved_peer_liveness_proven"])
            self.assertTrue(reopened.worker_attempted)
        self.assertEqual(self.case.case.enqueues(), [])

    def test_wrong_expected_supervisor_pid_or_intent_reply_is_not_accepted(self):
        for field in ("pid", "intent"):
            with self.subTest(field=field):
                self.setUp()
                self.prepare()
                with self.case.case.open() as process:
                    process.reconcile(deadline=self.case.case.now + 8)
                    source = CLIENT.replace("int(sys.argv[3])", "int(sys.argv[3])+1") if field == "pid" else CLIENT.replace(
                        "intent_sha256=sys.argv[6]", "intent_sha256='e'*64")
                    child = self.start(process, source)
                    if field == "pid":
                        self.assertEqual(self.read(child), b"Rejected\n")
                        with self.assertRaises(durable.Rejected):
                            self.serve(process)
                        self.assertFalse((self.case.case.root / "reconcile-worker.json").exists())
                    else:
                        # Sending the identity reply may race the now-rejecting
                        # worker exit; either server result still grants nothing.
                        try:
                            self.serve(process)
                        except durable.Rejected:
                            pass
                        self.assertEqual(self.read(child), b"Rejected\n")

    def test_malformed_or_oversized_request_never_creates_claim(self):
        for packet in (b"{}", b'{"schema":"unknown","request_id":"wrong","nonce":"test"}', b"x" * 4097,
                       b'{"schema":"a","schema":"b"}'):
            with self.subTest(packet=packet[:80]):
                self.setUp()
                self.prepare()
                source = "import socket,sys\ns=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)\ns.connect(sys.argv[2])\ns.send(" + repr(packet) + ")\nsys.stdin.readline()\n"
                with self.case.case.open() as process:
                    process.reconcile(deadline=self.case.case.now + 8)
                    child = self.start(process, source)
                    try:
                        with self.assertRaises(durable.Rejected):
                            self.serve(process)
                        self.assertFalse((self.case.case.root / "reconcile-worker.json").exists())
                        self.assertTrue(process.status()["alert"]["transport_delivered"])
                    finally:
                        child.stdin.write(b"done\n")
                        child.stdin.flush()
                        child.wait(timeout=5)

    def test_foreign_nonce_owner_or_permission_in_reply_never_passes_client(self):
        for change in ({"nonce": "foreign"}, {"supervisor_owner": {}}, {"restoration_permission": True},
                       {"start_permission": 0}, {"extra": "unsupported"}, {"peer": {}},
                       {"worker": {"state": "running"}}):
            with self.subTest(change=change):
                self.setUp()
                self.prepare()
                with self.case.case.open() as process:
                    process.reconcile(deadline=self.case.case.now + 8)
                    child = self.start(process)
                    original = worker.PeerSession.reply
                    def changed(session, value, deadline):
                        return original(session, {**value, **change}, deadline)
                    with patch.object(worker.PeerSession, "reply", changed):
                        try:
                            self.serve(process)
                        except durable.Rejected:
                            pass
                    self.assertEqual(self.read(child), b"Rejected\n")
                    self.assertEqual(child.wait(timeout=5), 2)
                    self.case.case.assert_fenced(process.status())

    def test_client_and_listener_deadlines_do_not_create_new_allowance_or_retry(self):
        self.prepare()
        with self.case.case.open() as process:
            process.reconcile(deadline=self.case.case.now + 8)
            client = worker.WorkerClient(self.path, supervisor_uid=os.geteuid(), supervisor_pid=os.getpid(),
                supervisor_owner=process.owner, request_id=process.pending_request["request_id"],
                intent_sha256=process.intent_sha256, clock=lambda: 1100)
            with self.assertRaises(durable.Rejected):
                client.claim(deadline=1100)
            with self.assertRaises(durable.Rejected):
                client.claim(deadline=1200)
            with self.assertRaises(durable.Rejected):
                self.listener.accept_once(supervisor=process, observer=self.case.observer, deadline=time.monotonic() - 1)
            self.assertFalse((self.case.case.root / "reconcile-worker.json").exists())

    def test_send_expiry_or_clock_regression_is_uncertain_even_when_bytes_arrive(self):
        for value in (1100.0, 999.0, float("nan"), True):
            with self.subTest(value=value):
                left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                now = [1000.0]
                session = worker.PeerSession(left, uid=os.geteuid(), clock=lambda: now[0])
                try:
                    send = worker.send
                    def changed(sock, body):
                        send(sock, body)
                        now[0] = value
                    with patch.object(worker, "send", changed), self.assertRaises(durable.Rejected):
                        session.reply({"synthetic": True}, 1100.0)
                    self.assertEqual(durable.decode(right.recv(4096)), {"synthetic": True})
                finally:
                    session.close()
                    left.close()
                    right.close()

    def test_unsupported_kernel_has_no_numeric_pid_fallback(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        real = left.getsockopt
        def get(level, option, length):
            if option == 77:
                raise OSError(errno.ENOPROTOOPT, "unsupported")
            return real(level, option, length)
        wrapped = SimpleNamespace(getsockopt=get)
        with patch("os.pidfd_open", side_effect=AssertionError("unsafe numeric fallback")):
            with self.assertRaises(OSError):
                worker.PeerSession(wrapped, uid=os.geteuid())

    def test_packet_ancillary_fds_are_closed_and_refused(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        fd = os.open("/dev/null", os.O_RDONLY)
        try:
            right.sendmsg([b"{}"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))])
        finally:
            os.close(fd)
        before = len(os.listdir("/proc/self/fd"))
        with self.assertRaises(durable.Rejected):
            worker.credential_packet(left, worker.peer(left, os.geteuid()))
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_endpoint_is_not_replaced_or_removed_and_wrong_uid_refuses(self):
        with self.assertRaises(OSError):
            worker.WorkerListener(self.path, worker_uid=os.geteuid())
        self.listener.close()
        self.assertTrue(Path(self.path).is_socket())
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        with self.assertRaises(durable.Rejected):
            worker.PeerSession(left, uid=os.geteuid() + 1)


class SupervisorAlertIntegrationTests(unittest.TestCase):
    def test_actual_supervisor_notices_conform_to_transport_contract(self):
        case = test_supervisor.SupervisorTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.manager.fenced = False
        with case.open() as process:
            process.reconcile(deadline=1100)
        self.assertEqual(len(case.notices), 1)
        alert.validate_notice(case.notices[0])

    def test_all_supervisor_fixed_errors_are_transportable_but_arbitrary_text_is_not(self):
        case = test_supervisor.SupervisorTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        with case.open() as process:
            for code in alert.SUPERVISOR_ERRORS:
                with self.subTest(code=code):
                    process._fail(durable.Rejected(code), "supervisor-state-unavailable")
                    alert.validate_notice(case.notices[-1])
                    self.assertEqual(case.notices[-1]["recovery_error"], code)
            process._fail(OSError("restricted path or token"), "supervisor-state-unavailable")
            alert.validate_notice(case.notices[-1])
            self.assertNotIn("restricted", str(case.notices[-1]))
        value = copy.deepcopy(case.notices[-1])
        value["recovery_error"] = "supervisor-unreviewed-error"
        with self.assertRaises(durable.Rejected):
            alert.validate_notice(value)

    def test_actual_local_alert_admission_despite_supervisor_receipt_disk_failure(self):
        route = test_alert.AlertTests()
        route.setUp()
        self.addCleanup(route.doCleanups)
        route.start()
        route.preflight()
        case = test_supervisor.SupervisorTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.manager.fenced = False
        def persist(_):
            raise OSError(errno.ENOSPC, "restricted")
        with supervisor.recovery_owner(str(case.root), owner=case.owner, manager=case.manager,
                clock=lambda: case.now, boot_id=lambda: case.boot, persist_alert=persist,
                transport_alert=lambda value: route.deliver(value)) as process:
            state = process.reconcile(deadline=1100)
        self.assertFalse(state["alert"]["receipt_persisted"])
        self.assertTrue(state["alert"]["transport_delivered"])
        route.stop()
        self.assertEqual(route.listener.drain()["original_cause"], "supervisor-restart-recovery-required")
