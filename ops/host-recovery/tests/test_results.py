"""Actual journal/peer IPC; SCRIPTED manager/fence/oracle, not host recovery."""
import copy
import errno
import json
import os
from pathlib import Path
import sys
import subprocess
import time
import unittest

from host_recovery import alert, durable, outcomes, supervisor, worker
import test_worker


class ResultTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_worker.WorkerClaimTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.case = self.fixture.case
        self.oracle_calls = []

    def prepare(self, process):
        process.reconcile(deadline=1100)
        claim = self.fixture.claim(process)
        return {"schema": "host-recovery-worker-result-v1", "request_id": process.pending_request["request_id"],
                "intent_sha256": process.intent_sha256, "claim_sha256": durable.digest(durable.canonical(claim)),
                "outcome": "baseline_restored", "evidence_sha256": "e" * 64}

    def record(self, process, result):
        return process.record_worker_result(result, peer=self.fixture.peer, observer=self.fixture.observer,
                                            peer_alive=lambda: self.fixture.alive, deadline=1100)

    def oracle(self, intent, result, *, deadline):
        self.oracle_calls.append((copy.deepcopy(intent), copy.deepcopy(result), deadline))
        return outcomes.expected_oracle(intent, result)

    def observe(self, process, oracle=None):
        return process.observe_result(observer=self.fixture.observer, oracle=oracle or self.oracle, deadline=1100)

    def reopen(self):
        return supervisor.recovery_owner(str(self.case.root), owner=self.case.owner, manager=self.case.manager,
            clock=lambda: self.case.now, boot_id=lambda: self.case.boot, persist_alert=self.case.persist,
            transport_alert=lambda n: self.case.notices.append(n) or True, observe_existing=True)

    def assert_no_grant(self, process):
        state = process.status()
        for key in ("start_permission", "forward_allowed", "recovery_completed", "installation_settled",
                    "installation_start_fence_proven", "production_acceptance"):
            self.assertIs(state[key], False)
        self.assertEqual((self.case.root / "intent.json").read_bytes(), self.case.original)

    def test_report_requires_independent_oracle_and_never_settles(self):
        with self.case.open() as process:
            result = self.prepare(process)
            self.assertEqual(self.record(process, result), result)
            self.assertFalse(process.status()["worker_result_observed"])
            state = self.observe(process)
            self.assertTrue(state["worker_result_observed"])
            self.assertEqual(state["state"], "recovery_result_observed_unsettled")
            self.assert_no_grant(process)
            with self.assertRaises(BlockingIOError), self.case.open():
                self.fail("installation lock lost")
            with self.assertRaises(durable.Rejected):
                self.record(process, result)
            with self.assertRaises(durable.Rejected):
                self.observe(process)
        self.assertEqual(len(self.oracle_calls), 1)

    def test_unknown_coerced_or_unbound_report_is_not_recorded(self):
        for change in ({"extra": True}, {"schema": "old"}, {"request_id": "0" * 64},
                       {"intent_sha256": "0" * 64}, {"claim_sha256": "0" * 64},
                       {"outcome": True}, {"outcome": "candidate_verified"}, {"evidence_sha256": "secret/path"}):
            with self.subTest(change=change):
                self.setUp()
                with self.case.open() as process:
                    result = self.prepare(process)
                    with self.assertRaises(durable.Rejected):
                        self.record(process, {**result, **change})
                    self.assert_no_grant(process)
                    self.assertFalse((self.case.root / "reconcile-result.json").exists())

    def test_no_report_without_claim_or_after_close(self):
        with self.case.open() as process:
            with self.assertRaises(durable.Rejected):
                self.record(process, {})
            result = self.prepare(process)
        with self.assertRaises(durable.Rejected):
            self.record(process, result)

    def test_peer_invocation_cgroup_fence_and_clock_loss_refuse(self):
        for kind in ("peer", "invocation", "cgroup", "fence", "clock"):
            with self.subTest(kind=kind):
                self.setUp()
                with self.case.open() as process:
                    result = self.prepare(process)
                    if kind == "peer": self.fixture.alive = False
                    elif kind == "invocation": self.fixture.invocation = "c" * 32
                    elif kind == "cgroup": self.fixture.group = "/other"
                    elif kind == "fence": self.case.manager.fenced = False
                    else: self.case.now = 1100
                    with self.assertRaises(durable.Rejected):
                        self.record(process, result)
                    self.assert_no_grant(process)

    def test_wrong_connected_peer_cannot_submit_saved_claim(self):
        with self.case.open() as process:
            result = self.prepare(process)
            with self.assertRaises(durable.Rejected):
                process.record_worker_result(result, peer={**self.fixture.peer, "pid": os.getpid() + 1},
                    observer=self.fixture.observer, peer_alive=lambda: True, deadline=1100)
            self.assertFalse((self.case.root / "reconcile-result.json").exists())

    def test_failure_report_never_calls_success_oracle(self):
        with self.case.open() as process:
            result = self.prepare(process)
            result["outcome"] = "recovery_unresolved"
            self.record(process, result)
            state = self.observe(process)
            self.assertEqual(state["state"], "recovery_unresolved")
            self.assertEqual(self.oracle_calls, [])
            self.assertTrue(state["alert"]["transport_delivered"])
            alert.validate_notice(self.case.notices[-1])
            self.assert_no_grant(process)

    def test_every_oracle_field_is_required_without_boolean_coercion(self):
        expected_keys = outcomes.expected_oracle(self.case.value, {"evidence_sha256": "e" * 64}).keys()
        for key in expected_keys:
            with self.subTest(key=key):
                self.setUp()
                with self.case.open() as process:
                    result = self.prepare(process)
                    self.record(process, result)
                    def bad(intent, value, *, deadline):
                        receipt = self.oracle(intent, value, deadline=deadline)
                        receipt[key] = 1 if receipt[key] is True else "wrong"
                        return receipt
                    self.assertFalse(self.observe(process, bad)["worker_result_observed"])
                    self.assert_no_grant(process)
                    self.assertFalse((self.case.root / "reconcile-result-observed.json").exists())

    def test_exited_same_invocation_still_requires_independent_oracle(self):
        with self.case.open() as process:
            result = self.prepare(process)
            self.record(process, result)
            original = self.fixture.observer.observe
            self.fixture.observer.observe = lambda *a, **kw: {**original(*a, **kw), "state": "inactive_unverified"}
            self.assertTrue(self.observe(process)["worker_result_observed"])
            self.assert_no_grant(process)
        self.assertEqual(len(self.oracle_calls), 1)

    def test_missing_pending_or_replaced_invocation_never_uses_exit_as_success(self):
        for change in ({"invocation_id": ""}, {"invocation_id": "c" * 32}, {"state": "pending", "job_id": 5}):
            with self.subTest(change=change):
                self.setUp()
                with self.case.open() as process:
                    result = self.prepare(process)
                    self.record(process, result)
                    original = self.fixture.observer.observe
                    self.fixture.observer.observe = lambda *a, **kw: {**original(*a, **kw), **change}
                    self.assertFalse(self.observe(process)["worker_result_observed"])
                    self.assertEqual(self.oracle_calls, [])

    def test_oracle_cannot_rewrite_report_request_claim_arm_or_intent(self):
        for name in ("reconcile-result.json", "reconcile-request.json", "reconcile-worker.json", "arm.json", "intent.json"):
            with self.subTest(name=name):
                self.setUp()
                with self.case.open() as process:
                    result = self.prepare(process)
                    self.record(process, result)
                    def drift(intent, value, *, deadline):
                        receipt = self.oracle(intent, value, deadline=deadline)
                        (self.case.root / name).write_bytes(b"{}\n")
                        return receipt
                    self.assertFalse(self.observe(process, drift)["worker_result_observed"])
                    self.assertFalse((self.case.root / "reconcile-result-observed.json").exists())

    def test_last_manager_callback_cannot_change_request_after_persistence(self):
        with self.case.open() as process:
            result = self.prepare(process)
            self.record(process, result)
            calls = []
            def fence(intent, *, deadline):
                if (self.case.root / "reconcile-result-observed.json").exists():
                    calls.append(True)
                    if len(calls) == 2:
                        (self.case.root / "reconcile-request.json").write_bytes(b"{}\n")
                return True
            self.case.manager.fence = fence
            state = self.observe(process)
            self.assertEqual(len(calls), 2)
            self.assertFalse(state["worker_result_observed"])
            self.assertEqual(state["state"], "recovery_unresolved")

    def test_each_result_and_observation_write_fault_is_reached_and_alerted(self):
        for target in ("result", "observation"):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                for code in (errno.EIO, errno.ENOSPC):
                    with self.subTest(target=target, point=point, code=code):
                        self.setUp()
                        with self.case.open() as process:
                            result = self.prepare(process)
                            if target == "observation": self.record(process, result)
                            reached = []
                            def fault(stage):
                                if stage == point:
                                    reached.append(stage)
                                    raise OSError(code, "restricted secret text")
                            process.log.fault = fault
                            self.case.persist = lambda _: (_ for _ in ()).throw(OSError(code, "disk failed"))
                            process.persist_alert = self.case.persist
                            if target == "result":
                                with self.assertRaises(durable.Rejected): self.record(process, result)
                            else:
                                self.assertFalse(self.observe(process)["worker_result_observed"])
                            self.assertEqual(reached, [point])
                            self.assertTrue(process.log.uncertain)
                            self.assertTrue(process.status()["alert"]["transport_delivered"])
                            self.assertFalse(process.status()["alert"]["receipt_persisted"])
                            self.assertNotIn("secret", str(process.status()))
                            alert.validate_notice(self.case.notices[-1])
                            self.assert_no_grant(process)

    def test_post_write_deadline_expiry_never_observes_result(self):
        with self.case.open() as process:
            result = self.prepare(process)
            self.record(process, result)
            process.log.fault = lambda point: setattr(self.case, "now", 1100) if point == "readback" else None
            self.assertFalse(self.observe(process)["worker_result_observed"])
            self.assert_no_grant(process)

    def test_reopen_never_reuses_saved_observation_or_live_peer_authority(self):
        with self.case.open() as process:
            result = self.prepare(process)
            self.record(process, result)
            self.assertTrue(self.observe(process)["worker_result_observed"])
        original = (self.case.root / "reconcile-result-observed.json").read_bytes()
        self.case.owner["invocation_id"] = "c" * 32
        with self.reopen() as process:
            self.assertIsNone(process.error)
            self.assertFalse(process.status()["worker_result_observed"])
            self.assertFalse(process.status()["saved_peer_liveness_proven"])
            with self.assertRaises(durable.Rejected): self.record(process, result)
            self.assertTrue(self.observe(process)["worker_result_observed"])
            self.assert_no_grant(process)
        self.assertEqual((self.case.root / "reconcile-result-observed.json").read_bytes(), original)
        self.assertEqual(len(self.oracle_calls), 2)

    def test_reopened_torn_staged_or_unbound_result_remains_unresolved(self):
        for kind in ("torn", "staged", "claim", "observation", "orphan"):
            with self.subTest(kind=kind):
                self.setUp()
                with self.case.open() as process:
                    result = self.prepare(process)
                    self.record(process, result)
                    self.observe(process)
                if kind == "staged": (self.case.root / ".stage-reconcile-result.json").write_bytes(b"partial")
                elif kind == "claim": (self.case.root / "reconcile-worker.json").write_bytes(b"{}")
                elif kind == "orphan": (self.case.root / "reconcile-result.json").unlink()
                else:
                    name = "reconcile-result.json" if kind == "torn" else "reconcile-result-observed.json"
                    (self.case.root / name).write_bytes(b"{\"torn\":")
                with self.reopen() as process:
                    self.assertEqual(process.status()["state"], "recovery_unresolved")
                    self.assert_no_grant(process)


RESULT_SERVER = r'''
import json,os,sys,time
from types import SimpleNamespace
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tests"]
from host_recovery import jobs,outcomes,supervisor,worker
from test_supervisor import ScriptedManager
owner=json.loads(sys.argv[4])
listener=worker.WorkerListener(sys.argv[2],worker_uid=os.geteuid())
def observe(request_id,**kw):
    return {"schema":"host-recovery-job-observation-v1","request_id":request_id,"boot_id":"boot-a",
            "unit":jobs.recovery_unit(request_id),"invocation_id":"b"*32,"state":"running","job_id":0}
def observe_worker(request_id,*,pid,deadline):
    return {**observe(request_id),"pid":pid,"cgroup":"/recovery/worker.service"}
reply=worker.PeerSession.reply
def hold_reply(self,value,deadline):
    if value['schema']=='host-recovery-worker-result-receipt-v1':
        print("RESULT-SAVED",flush=True)
        os.read(0,1)
    return reply(self,value,deadline)
worker.PeerSession.reply=hold_reply
with supervisor.recovery_owner(sys.argv[3],owner=owner,manager=ScriptedManager(),clock=time.monotonic,
        boot_id=lambda:"boot-a",persist_alert=lambda _:None,transport_alert=lambda _:True) as process:
    process.reconcile(deadline=time.monotonic()+15)
    print(json.dumps({"request_id":process.pending_request["request_id"],"intent_sha256":process.intent_sha256}),flush=True)
    listener.accept_once(supervisor=process,observer=SimpleNamespace(observe=observe,observe_worker=observe_worker),
        deadline=process.pending_request['deadline'],result_oracle=lambda intent,result,**kw:outcomes.expected_oracle(intent,result))
'''


RESULT_CLIENT = test_worker.CLIENT.replace(
    'value=client.claim(deadline=time.monotonic()+8)',
    '''value=client.claim(deadline=time.monotonic()+8, result_provider=lambda claim,**kw:
        {"outcome":"baseline_restored","evidence_sha256":"e"*64})\n    value={"claim":value,"receipt":client.result_receipt}''')


class ResultIPCTests(unittest.TestCase):
    def setUp(self):
        self.ipc = test_worker.WorkerIPCTests()
        self.ipc.setUp()
        self.addCleanup(self.ipc.doCleanups)
        self.ipc.prepare()
        self.case = self.ipc.case.case

    def serve(self, process, oracle=None):
        return self.ipc.listener.accept_once(supervisor=process, observer=self.ipc.case.observer,
            deadline=process.pending_request["deadline"], result_oracle=oracle or (
                lambda intent, result, **kw: outcomes.expected_oracle(intent, result)))

    def test_separate_process_result_is_durable_before_receipt_and_retains_lock(self):
        with self.case.open() as process:
            process.reconcile(deadline=self.case.now + 8)
            child = self.ipc.start(process, RESULT_CLIENT)
            claim = self.serve(process)
            value = json.loads(self.ipc.read(child))
            self.assertEqual(value["claim"], claim)
            report = durable.decode((self.case.root / "reconcile-result.json").read_bytes())
            self.assertEqual(value["receipt"]["result_sha256"], durable.digest(durable.canonical(report)))
            self.assertTrue(process.status()["worker_result_observed"])
            self.assertTrue((self.case.root / "reconcile-result-observed.json").exists())
            self.assertFalse(value["receipt"]["start_permission"])
            with self.assertRaises(BlockingIOError), self.case.open(): self.fail("lock released")
            child.stdin.write(b"done\n"); child.stdin.flush()
            self.assertEqual(child.wait(timeout=5), 0)

    def test_claim_without_result_cannot_pass_oracle_protocol(self):
        with self.case.open() as process:
            process.reconcile(deadline=self.case.now + 8)
            # Exit immediately after claim; EOF/death is not a recovery result.
            source = test_worker.CLIENT.replace('sys.stdin.readline()', 'sys.exit(0)')
            child = self.ipc.start(process, source)
            with self.assertRaises(durable.Rejected): self.serve(process)
            self.assertEqual(child.wait(timeout=5), 0)
            self.assertFalse(process.status()["worker_result_observed"])
            self.assertFalse((self.case.root / "reconcile-result.json").exists())

    def test_sigkill_supervisor_after_observation_never_replays_receipt_or_redispatches(self):
        root = Path(__file__).resolve().parent.parent
        path = str(Path(self.ipc.temp.name) / "result.sock")
        server = subprocess.Popen([sys.executable, "-I", "-c", RESULT_SERVER, str(root), path,
            str(self.case.root), json.dumps(self.case.owner)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.ipc.children.append(server)
        pins = json.loads(self.ipc.read(server))
        child = subprocess.Popen([sys.executable, "-I", "-c", RESULT_CLIENT, str(root), path, str(server.pid),
            json.dumps(self.case.owner), pins["request_id"], pins["intent_sha256"]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.ipc.children.append(child)
        self.assertEqual(self.ipc.read(server), b"RESULT-SAVED\n")
        self.assertTrue((self.case.root / "reconcile-result-observed.json").exists())
        with self.assertRaises(BlockingIOError), self.case.open(): self.fail("lock lost before receipt")
        server.kill()
        self.assertEqual(server.wait(timeout=5), -9)
        self.assertEqual(self.ipc.read(child), b"Rejected\n")
        self.assertEqual(child.wait(timeout=5), 2)
        self.case.owner["invocation_id"] = "c" * 32
        with supervisor.recovery_owner(str(self.case.root), owner=self.case.owner, manager=self.case.manager,
                clock=time.monotonic, boot_id=lambda: "boot-a", persist_alert=lambda _: None,
                transport_alert=lambda _: True, observe_existing=True) as process:
            self.assertIsNone(process.error)
            self.assertFalse(process.status()["worker_result_observed"])
            self.assertFalse(process.status()["saved_peer_liveness_proven"])
            with self.assertRaises(durable.Rejected): process.reconcile(deadline=time.monotonic()+10)
            state = process.observe_result(observer=self.ipc.case.observer,
                oracle=lambda intent,result,**kw: outcomes.expected_oracle(intent,result),
                deadline=process.pending_request["deadline"])
            self.assertTrue(state["worker_result_observed"])
            self.assertFalse(state["recovery_completed"])
            self.assertFalse(state["installation_settled"])
        self.assertEqual(self.case.enqueues(), [])

    def test_worker_death_after_report_persistence_prevents_ack(self):
        with self.case.open() as process:
            process.reconcile(deadline=self.case.now + 8)
            child = self.ipc.start(process, RESULT_CLIENT)
            def die(intent, result, **kw):
                child.kill(); child.wait(timeout=5)
                return outcomes.expected_oracle(intent, result)
            with self.assertRaises(durable.Rejected): self.serve(process, die)
            self.assertEqual(child.returncode, -9)
            self.assertTrue((self.case.root / "reconcile-result.json").exists())
            self.assertFalse(process.status()["worker_result_observed"])
            self.assertEqual(process.status()["state"], "recovery_unresolved")
            with self.assertRaises(durable.Rejected): self.serve(process)


class ManagedResultIPCTests(unittest.TestCase):
    def test_worker_bootstrap_revalidates_manager_through_result_receipt(self):
        import test_worker_bootstrap
        fixture = test_worker_bootstrap.ManagedWorkerIPCTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        root = Path(__file__).resolve().parent.parent
        source = test_worker_bootstrap.PROCESS.replace(
            "result = case.engine.claim(sys.argv[3], deadline=case.request['deadline'])",
            "result = case.engine.claim(sys.argv[3], deadline=case.request['deadline'], "
            "result_provider=lambda claim,**kw: {'outcome':'baseline_restored','evidence_sha256':'e'*64})\n"
            "    result={'claim':result,'receipt':case.engine.result_receipt}")
        with fixture.open() as process:
            process.reconcile(deadline=fixture.now + 8)
            child = subprocess.Popen([sys.executable, "-I", "-c", source, str(root), str(root / "tests"), fixture.path,
                json.dumps(process.pending_request), str(os.getpid()), "0"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={**os.environ, "INVOCATION_ID": "forged", "MAINPID": "1"})
            fixture.children.append(child)
            fixture.pid = child.pid
            claim = fixture.listener.accept_once(supervisor=process, observer=fixture.observer,
                deadline=process.pending_request["deadline"],
                result_oracle=lambda intent,result,**kw: outcomes.expected_oracle(intent,result))
            received = json.loads(fixture.read(child))
            self.assertEqual(received["claim"], claim)
            self.assertTrue(received["receipt"]["observed"])
            self.assertFalse(received["receipt"]["installation_settled"])
            self.assertFalse(received["receipt"]["start_permission"])
            child.stdin.write(b"done\n"); child.stdin.flush()
            self.assertEqual(child.wait(timeout=5), 0)
