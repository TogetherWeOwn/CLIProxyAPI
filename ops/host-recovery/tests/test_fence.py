"""Synthetic AuthZ callbacks and real private disk; no Docker or installed fence."""
import copy
import errno
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest

from host_recovery import durable, fence, journal
from test_recovery_state import intent, candidate


def observation(value, record, running=True):
    return {**record, "installation_id": value["installation_id"], "running": running,
            "paused": False, "restarting": False, "dead": False,
            "status": "running" if running else "exited", "restart_retries": 0, "auto_remove": False}


PENDING_HOLD = r'''
import os
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, str(Path(sys.argv[1]) / "tests"))
from host_recovery import durable, fence, journal
from test_recovery_state import intent, candidate
from test_fence import observation
value = intent()
with durable.installation_lock(sys.argv[2], value["owner"]) as (fd, owner):
    log = journal.Journal(fd)
    log.prepare(value)
    log.arm({"boot_id": "boot-a", "monotonic": 1000.0})
    record = candidate(value)
    log.register(record)
    log.revoke_forward()
    gate = fence.RecoveryAuthorization(log, principal="fixture-supervisor", api_version="1.47",
                                        clock=lambda: 1000.0, boot_id=lambda: "boot-a")
    gate.bind(old_image_id="1" * 64, candidates=[record])
    operation = gate.prepare_kill(observation(value, record), deadline=1010.0)
    request = {"User": "fixture-supervisor", "UserAuthNMethod": "TLS", "RequestMethod": "POST",
               "RequestURI": operation["uri"], "RequestBody": "",
               "RequestHeaders": {fence.OPERATION_HEADER: operation["operation_id"]}}
    response = gate.request(durable.canonical(request))
    os.write(1, durable.canonical({"request": request, "response": response, "status": gate.status()}))
    os.read(0, 1)
'''


def pending_loss_drill():
    """Actual separate-process loss, but entirely synthetic daemon callbacks."""
    with tempfile.TemporaryDirectory(prefix="host-recovery-authorization-loss-") as path:
        root = Path(__file__).resolve().parent.parent
        proc = subprocess.Popen((sys.executable, "-I", "-c", PENDING_HOLD, str(root), path),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                close_fds=True, cwd="/")
        try:
            with selectors.DefaultSelector() as wait:
                wait.register(proc.stdout, selectors.EVENT_READ)
                if not wait.select(10):
                    raise RuntimeError("synthetic-authorizer-not-ready")
                raw = os.read(proc.stdout.fileno(), 16384)
            receipt = durable.decode(raw)
            if receipt["response"]["Allow"] is not True:
                raise RuntimeError("synthetic-authorizer-not-allowed")
            # Do not send a response callback or let a fake stop receipt drain it.
            proc.kill()
            proc.wait(timeout=10)
            with durable.installation_lock(path, intent()["owner"]) as (fd, _):
                log = journal.Journal(fd)
                gate = fence.RecoveryAuthorization(log, principal="fixture-supervisor", api_version="1.47",
                                                    clock=lambda: 1001.0, boot_id=lambda: "boot-a")
                gate.seal()
                pending, _ = durable.read_file(fd, "daemon-operation-001-pending.json")
                return {"schema": "synthetic-authorization-process-loss-v1", "before_loss": receipt,
                        "child_returncode": proc.returncode, "pending_record": durable.decode(pending),
                        "reopened": gate.status(), "repeated_request": gate.request(durable.canonical(receipt["request"])),
                        "actual_daemon": False, "production_acceptance": False}
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="host-recovery-authorization-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.now = 1000.0
        self.boot = "boot-a"
        self.value = intent()
        self.log = journal.Journal(self.fd)
        self.log.prepare(self.value)
        self.log.arm({"boot_id": self.boot, "monotonic": self.now})
        self.record = candidate(self.value)
        self.log.register(self.record)
        self.log.revoke_forward()
        self.gate = self.make_gate()
        self.gate.bind(old_image_id="1" * 64, candidates=[self.record])
        self.seen = observation(self.value, self.record)

    def make_gate(self, log=None):
        return fence.RecoveryAuthorization(log or self.log, principal="fixture-supervisor", api_version="1.47",
                                           clock=lambda: self.now, boot_id=lambda: self.boot)

    def request(self, operation=None, **updates):
        value = {"User": "fixture-supervisor", "UserAuthNMethod": "TLS", "RequestMethod": "GET",
                 "RequestURI": "/v1.47/containers/" + self.record["object_id"] + "/json",
                 "RequestHeaders": {}, "RequestBody": ""}
        if operation is not None:
            value.update(RequestMethod=operation["method"], RequestURI=operation["uri"],
                         RequestHeaders={fence.OPERATION_HEADER: operation["operation_id"]})
        value.update(updates)
        return value

    def response(self, operation=None, **updates):
        return {**self.request(operation), "ResponseStatusCode": 204, "ResponseHeaders": {},
                "ResponseBody": "", **updates}

    def prepare(self):
        return self.gate.prepare_kill(self.seen, deadline=self.now + 10)

    def allow(self, value):
        self.assertIs(self.gate.request(durable.canonical(value))["Allow"], True)

    def deny(self, value):
        self.assertIs(self.gate.request(durable.canonical(value))["Allow"], False)

    def authorize(self):
        operation = self.prepare()
        self.allow(self.request(operation))
        return operation

    def returned(self, operation):
        self.assertIs(self.gate.response(durable.canonical(self.response(operation)))["Allow"], True)

    def test_all_start_and_bypass_routes_are_denied_even_for_principal(self):
        object_id = self.record["object_id"]
        for uri in ("/v1.47/containers/" + object_id + "/" + op for op in
                    ("start", "restart", "update", "rename", "exec", "attach", "unpause", "archive")):
            self.deny(self.request(RequestMethod="POST", RequestURI=uri))
        for method, uri in (("POST", "/v1.47/containers/create"), ("DELETE", "/v1.47/containers/" + object_id),
                            ("POST", "/v1.47/build"), ("POST", "/v1.47/services/create"),
                            ("POST", "/v1.47/plugins/enable"), ("POST", "/v1.47/exec/unknown/start"),
                            ("GET", "/v1.47/containers/json"), ("GET", "/v1.47/events"),
                            ("POST", "/containers/" + object_id + "/start")):
            self.deny(self.request(RequestMethod=method, RequestURI=uri))
        self.assertEqual(self.gate.sequence, 0)

    def test_exact_bound_inspection_only_without_mutation(self):
        before = sorted(os.listdir(self.fd))
        self.allow(self.request())
        self.allow(self.request(RequestURI="/v1.47/containers/" + self.value["old_object_id"] + "/json"))
        self.assertEqual(before, sorted(os.listdir(self.fd)))
        self.assertFalse(self.gate.status()["pending_operation"])

    def test_unbound_reads_query_traversal_encoded_and_version_aliases_deny(self):
        target = self.request()["RequestURI"]
        for uri in (target + "?size=1", target + "/", target.replace("1.47", "1.48"),
                    target.replace("/json", "/../json"), target.replace("containers", "%63ontainers"),
                    target.replace(self.record["object_id"], "a" * 12),
                    target.replace(self.record["object_id"], "0" * 64), "https://example.invalid" + target):
            with self.subTest(uri=uri):
                self.deny(self.request(RequestURI=uri))

    def test_authenticated_daemon_user_required_not_an_operation_header(self):
        operation = self.prepare()
        for updates in ({"User": ""}, {"UserAuthNMethod": ""}, {"User": "other"},
                        {"UserAuthNMethod": "tls"}, {"User": ["fixture-supervisor"]}):
            with self.subTest(updates=updates):
                self.deny(self.request(operation, **updates))
                self.deny(self.request(**updates))
        self.assertIsNone(self.gate.pending)
        self.allow(self.request(operation))

    def test_preparation_requires_durable_arm_and_revoked_forward(self):
        self.log.forward_revoked = False
        with self.assertRaises(durable.Rejected):
            self.prepare()
        self.log.revoke_forward()
        self.log.armed = None
        with self.assertRaises(durable.Rejected):
            self.prepare()

    def test_exact_one_shot_kill_pending_before_allow(self):
        operation = self.authorize()
        name = "daemon-operation-001-pending.json"
        value = durable.decode((self.root / name).read_bytes())
        self.assertEqual(value["operation_id"], operation["operation_id"])
        self.assertEqual(value["state"], "pending")
        self.assertTrue(self.gate.status()["pending_operation"])
        self.deny(self.request(operation))
        with self.assertRaises(durable.Rejected):
            self.prepare()
        self.assertEqual(self.gate.sequence, 1)

    def test_kill_method_path_signal_body_and_correlation_cannot_change(self):
        operation = self.prepare()
        for updates in ({"RequestMethod": "DELETE"}, {"RequestMethod": "post"},
                        {"RequestURI": operation["uri"].replace("KILL", "TERM")},
                        {"RequestURI": operation["uri"] + "&signal=KILL"},
                        {"RequestURI": operation["uri"].replace(self.record["object_id"], "0" * 64)},
                        {"RequestBody": "e30="}, {"RequestHeaders": {}},
                        {"RequestHeaders": {fence.OPERATION_HEADER: "0" * 64}}):
            with self.subTest(updates=updates):
                self.deny(self.request(operation, **updates))
        self.allow(self.request(operation))

    def test_duplicate_casefolded_headers_and_non_string_headers_deny(self):
        operation = self.prepare()
        for headers in ({fence.OPERATION_HEADER: operation["operation_id"],
                         fence.OPERATION_HEADER.lower(): operation["operation_id"]},
                        {"Host": "one", "host": "two", fence.OPERATION_HEADER: operation["operation_id"]},
                        {fence.OPERATION_HEADER: [operation["operation_id"]]}):
            self.deny(self.request(operation, RequestHeaders=headers))
        self.allow(self.request(operation, RequestHeaders={fence.OPERATION_HEADER.lower(): operation["operation_id"]}))

    def test_protocol_malformed_duplicate_unknown_fields_deny_without_echo(self):
        for raw in (b"", b"null", b"[]", b"{}", b'{"User":"secret","User":"secret"}',
                    b"x" * (durable.MAX_FILE_BYTES + 1), durable.canonical({**self.request(), "extra": "restricted"})):
            response = self.gate.request(raw)
            self.assertEqual(response, fence.reply(False, "recovery-authorization-denied"))
            self.assertNotIn("restricted", str(response))
            self.assertNotIn("secret", str(response))

    def test_missing_request_fields_deny(self):
        for field in fence.REQUEST_FIELDS:
            value = self.request()
            del value[field]
            self.deny(value)

    def test_candidate_binding_requires_actual_durable_registration(self):
        for record in ({**self.record, "object_id": "0" * 64},
                       {**self.record, "image_id": "0" * 64},
                       {**self.record, "running": True}):
            with self.subTest(record=record), self.assertRaises(durable.Rejected):
                self.make_gate().bind(old_image_id="1" * 64, candidates=[record])
        with self.assertRaises(durable.Rejected):
            self.make_gate().bind(old_image_id="1" * 64, candidates=[self.record, self.record])

    def test_observation_wrong_image_ownership_or_unsafe_state_refuses_kill(self):
        for updates in ({"object_id": "a" * 12}, {"image_id": "0" * 64}, {"ownership_id": "foreign"},
                        {"installation_id": "foreign"}, {"paused": True}, {"dead": True},
                        {"restarting": True}, {"restart_policy": "always"}, {"auto_remove": True},
                        {"restart_retries": True}, {"running": 1}, {"running": False},
                        {"status": "exited"}, {"unexpected": True}):
            with self.subTest(updates=updates), self.assertRaises(durable.Rejected):
                self.gate.prepare_kill({**self.seen, **updates}, deadline=self.now + 10)
        self.assertIsNone(self.gate.pending)

    def test_old_object_kill_requires_its_own_image_pin(self):
        old = {**self.seen, "object_id": self.value["old_object_id"], "image_id": "1" * 64,
               "ownership_id": None, "installation_id": None}
        operation = self.gate.prepare_kill(old, deadline=self.now + 10)
        self.allow(self.request(operation))
        self.assertEqual(self.gate.pending["image_id"], "1" * 64)

    def test_http_success_does_not_drain_pending(self):
        operation = self.authorize()
        self.returned(operation)
        self.assertTrue(self.gate.status()["operation_returned"])
        self.assertTrue(self.gate.status()["pending_operation"])
        with self.assertRaises(durable.Rejected):
            self.gate.reconcile_stopped(self.seen, deadline=self.now + 10)
        self.assertTrue(self.gate.status()["pending_operation"])

    def test_inspection_without_return_does_not_drain_pending(self):
        self.authorize()
        with self.assertRaises(durable.Rejected):
            self.gate.reconcile_stopped({**self.seen, "running": False, "status": "exited"}, deadline=self.now + 10)

    def test_wrong_or_duplicate_response_cannot_settle_operation(self):
        operation = self.authorize()
        for updates in ({"User": "foreign"}, {"RequestURI": "wrong"}, {"ResponseStatusCode": True},
                        {"ResponseStatusCode": 99}, {"ResponseStatusCode": 600},
                        {"RequestHeaders": {fence.OPERATION_HEADER: "0" * 64}}):
            with self.subTest(updates=updates):
                self.assertFalse(self.gate.response(durable.canonical(self.response(operation, **updates)))["Allow"])
                self.assertFalse(self.gate.returned)
        self.returned(operation)
        self.assertFalse(self.gate.response(durable.canonical(self.response(operation)))["Allow"])
        self.assertTrue(self.gate.status()["pending_operation"])

    def test_error_return_still_needs_independent_stop_observation(self):
        operation = self.authorize()
        self.assertTrue(self.gate.response(durable.canonical(self.response(operation, ResponseStatusCode=500)))["Allow"])
        self.assertTrue(self.gate.status()["pending_operation"])
        self.gate.reconcile_stopped({**self.seen, "running": False, "status": "exited"}, deadline=self.now + 10)
        self.assertFalse(self.gate.status()["pending_operation"])
        self.assertTrue((self.root / "daemon-operation-001-pending.json").exists())
        self.assertTrue((self.root / "daemon-operation-001-returned.json").exists())
        self.assertTrue((self.root / "daemon-operation-001-observed-stopped.json").exists())
        self.deny(self.request(operation))

    def test_read_response_cannot_settle_mutation(self):
        self.authorize()
        self.assertTrue(self.gate.response(durable.canonical(self.response()))["Allow"])
        self.assertFalse(self.gate.returned)
        self.assertTrue(self.gate.status()["pending_operation"])

    def test_reconcile_wrong_object_or_image_never_drains(self):
        operation = self.authorize()
        self.returned(operation)
        for updates in ({"object_id": "0" * 64}, {"image_id": "0" * 64}, {"ownership_id": "foreign"}):
            with self.subTest(updates=updates), self.assertRaises(durable.Rejected):
                self.gate.reconcile_stopped({**self.seen, "running": False, "status": "exited", **updates},
                                            deadline=self.now + 10)
        self.assertTrue(self.gate.status()["pending_operation"])

    def test_prepare_is_not_authorization_and_expiry_does_not_allow_kill(self):
        operation = self.prepare()
        self.now = operation["deadline"]
        self.deny(self.request(operation))
        self.assertEqual(self.gate.sequence, 0)
        self.assertFalse(self.gate.status()["pending_operation"])

    def test_reboot_or_regression_irreversibly_closes_prepared_mutation(self):
        for change in ("boot", "clock"):
            with self.subTest(change=change):
                gate = self.make_gate()
                gate.bind(old_image_id="1" * 64, candidates=[self.record])
                operation = gate.prepare_kill(self.seen, deadline=self.now + 10)
                if change == "boot":
                    self.boot = "boot-b"
                else:
                    self.now -= 1
                self.assertFalse(gate.request(durable.canonical(self.request(operation)))["Allow"])
                self.boot, self.now = "boot-a", 1000.0
                self.assertFalse(gate.request(durable.canonical(self.request(operation)))["Allow"])
                self.assertTrue(gate.status()["uncertain"])

    def test_reopen_even_completed_receipts_never_rearms(self):
        operation = self.authorize()
        self.returned(operation)
        self.gate.reconcile_stopped({**self.seen, "running": False, "status": "exited"}, deadline=self.now + 10)
        reopened = self.make_gate(journal.Journal(self.fd))
        self.assertTrue(reopened.status()["uncertain"])
        self.assertFalse(reopened.request(durable.canonical(self.request(operation)))["Allow"])
        with self.assertRaises(durable.Rejected):
            reopened.bind(old_image_id="1" * 64, candidates=[])

    def test_every_pending_persistence_fault_denies_and_latches(self):
        original = (self.root / "intent.json").read_bytes()
        for code in (errno.EIO, errno.ENOSPC):
            for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(code=code, point=point), tempfile.TemporaryDirectory() as path:
                    with durable.directory(path, private=True) as fd:
                        log = journal.Journal(fd)
                        log.prepare(self.value)
                        log.arm({"boot_id": self.boot, "monotonic": self.now})
                        log.register(self.record)
                        log.revoke_forward()
                        gate = self.make_gate(log)
                        gate.bind(old_image_id="1" * 64, candidates=[self.record])
                        operation = gate.prepare_kill(self.seen, deadline=self.now + 10)
                        def fail(stage):
                            if stage == point:
                                raise OSError(code, "restricted-error")
                        log.fault = fail
                        response = gate.request(durable.canonical(self.request(operation)))
                        self.assertEqual(response, fence.reply(False, "recovery-authorization-denied"))
                        self.assertTrue(gate.status()["uncertain"])
                        self.assertTrue(gate.status()["pending_operation"])
                        log.fault = None
                        self.assertFalse(gate.request(durable.canonical(self.request(operation)))["Allow"])
                        self.assertEqual((Path(path) / "intent.json").read_bytes(), original)
                        self.assertTrue(journal.Journal(fd).reopened)

    def test_return_and_stop_receipt_faults_retain_pending(self):
        operation = self.authorize()
        def fail(stage):
            if stage == "directory-fsync":
                raise OSError(errno.EIO, "injected")
        self.log.fault = fail
        self.assertFalse(self.gate.response(durable.canonical(self.response(operation)))["Allow"])
        self.assertFalse(self.gate.returned)
        self.assertTrue(self.gate.status()["uncertain"])
        self.assertTrue(self.gate.status()["pending_operation"])

    def test_stop_receipt_fault_cannot_drain_after_successful_return(self):
        operation = self.authorize()
        self.returned(operation)
        def fail(stage):
            if stage == "readback":
                raise OSError(errno.ENOSPC, "injected")
        self.log.fault = fail
        with self.assertRaises(OSError):
            self.gate.reconcile_stopped({**self.seen, "running": False, "status": "exited"}, deadline=self.now + 10)
        self.assertTrue(self.gate.status()["pending_operation"])
        self.assertTrue(self.gate.status()["uncertain"])

    def test_operation_limit_and_rebinding_are_refused(self):
        with self.assertRaises(durable.Rejected):
            self.gate.bind(old_image_id="1" * 64, candidates=[self.record])
        self.gate.sequence = fence.MAX_OPERATIONS
        with self.assertRaises(durable.Rejected):
            self.prepare()

    def test_deadline_after_pending_write_denies_but_keeps_pending(self):
        operation = self.prepare()
        def delay(stage):
            if stage == "readback":
                self.now = operation["deadline"]
        self.log.fault = delay
        self.deny(self.request(operation))
        self.assertTrue(self.gate.status()["pending_operation"])
        self.assertTrue((self.root / "daemon-operation-001-pending.json").exists())

    def test_status_never_claims_complete_host_or_internal_restart_fence(self):
        state = self.gate.status()
        self.assertIs(state["starts_denied"], True)
        for key in ("daemon_configuration_verified", "internal_restart_fenced", "installation_start_fence_proven",
                    "production_acceptance"):
            self.assertIs(state[key], False)
        self.assertNotIn(self.record["object_id"], str(state))

    def test_intent_change_or_uncertain_journal_closes_prepared_operation(self):
        operation = self.prepare()
        self.log.intent["package_sha256"] = "0" * 64
        self.deny(self.request(operation))
        self.assertTrue(self.gate.status()["uncertain"])

    def test_caller_mutation_cannot_change_prepared_scope(self):
        operation = self.prepare()
        original = copy.deepcopy(operation)
        operation["object_id"] = "0" * 64
        self.seen["object_id"] = "0" * 64
        self.assertEqual(self.gate.planned, original)
        self.allow(self.request(original))

    def test_second_engine_cannot_overwrite_first_pending_evidence(self):
        second = self.make_gate()
        second.bind(old_image_id="1" * 64, candidates=[self.record])
        other = second.prepare_kill(self.seen, deadline=self.now + 10)
        self.authorize()
        original = (self.root / "daemon-operation-001-pending.json").read_bytes()
        self.assertFalse(second.request(durable.canonical(self.request(other)))["Allow"])
        self.assertTrue(second.status()["uncertain"])
        self.assertEqual(original, (self.root / "daemon-operation-001-pending.json").read_bytes())

    def test_seal_revokes_prepared_operation_and_is_not_reversible(self):
        operation = self.prepare()
        self.assertFalse(self.gate.status()["pending_drained"])
        self.gate.seal()
        self.assertTrue(self.gate.status()["pending_drained"])
        self.deny(self.request(operation))
        with self.assertRaises(durable.Rejected):
            self.prepare()

    def test_seal_never_discards_pending_daemon_work(self):
        operation = self.authorize()
        self.gate.seal()
        self.assertFalse(self.gate.status()["pending_drained"])
        self.returned(operation)
        self.assertFalse(self.gate.status()["pending_drained"])
        self.gate.reconcile_stopped({**self.seen, "running": False, "status": "exited"}, deadline=self.now + 10)
        self.assertTrue(self.gate.status()["pending_drained"])
        self.assertFalse(self.gate.status()["installation_start_fence_proven"])

    def test_seal_with_unknown_or_lost_receipt_never_claims_drain(self):
        operation = self.authorize()
        self.returned(operation)
        (self.root / "daemon-operation-001-pending.json").unlink()
        self.gate.seal()
        self.assertTrue(self.gate.status()["uncertain"])
        self.assertFalse(self.gate.status()["pending_drained"])

    def test_every_return_and_reconcile_persistence_fault_retains_pending(self):
        for phase in ("returned", "observed-stopped"):
            for code in (errno.EIO, errno.ENOSPC):
                for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                    with self.subTest(phase=phase, code=code, point=point), tempfile.TemporaryDirectory() as path:
                        with durable.directory(path, private=True) as fd:
                            log = journal.Journal(fd)
                            log.prepare(self.value)
                            log.arm({"boot_id": self.boot, "monotonic": self.now})
                            log.register(self.record)
                            log.revoke_forward()
                            gate = self.make_gate(log)
                            gate.bind(old_image_id="1" * 64, candidates=[self.record])
                            operation = gate.prepare_kill(self.seen, deadline=self.now + 10)
                            self.assertTrue(gate.request(durable.canonical(self.request(operation)))["Allow"])
                            if phase == "observed-stopped":
                                self.assertTrue(gate.response(durable.canonical(self.response(operation)))["Allow"])
                            def fail(stage):
                                if stage == point:
                                    raise OSError(code, "injected")
                            log.fault = fail
                            if phase == "returned":
                                self.assertFalse(gate.response(durable.canonical(self.response(operation)))["Allow"])
                            else:
                                with self.assertRaises(OSError):
                                    gate.reconcile_stopped({**self.seen, "running": False, "status": "exited"},
                                                           deadline=self.now + 10)
                            gate.seal()
                            self.assertTrue(gate.status()["pending_operation"])
                            self.assertTrue(gate.status()["uncertain"])
                            self.assertFalse(gate.status()["pending_drained"])

    def test_discontinuity_during_clock_read_stays_latched_after_clock_restored(self):
        operation = self.prepare()
        times = iter((1000.0, 999.0))
        self.gate.clock = lambda: next(times)
        self.deny(self.request(operation))
        self.gate.clock = lambda: self.now
        self.deny(self.request(operation))
        self.assertTrue(self.gate.status()["uncertain"])

    def test_fault_during_final_observation_deadline_never_drains(self):
        operation = self.authorize()
        self.returned(operation)
        def expire(stage):
            if stage == "readback":
                self.now = 1010.0
        self.log.fault = expire
        with self.assertRaises(durable.Rejected):
            self.gate.reconcile_stopped({**self.seen, "running": False, "status": "exited"}, deadline=1010.0)
        self.gate.seal()
        self.assertFalse(self.gate.status()["pending_drained"])

    def test_sigkill_after_allow_keeps_durable_pending_and_refuses_replay(self):
        receipt = pending_loss_drill()
        self.assertEqual(receipt["child_returncode"], -9)
        self.assertTrue(receipt["before_loss"]["response"]["Allow"])
        self.assertEqual(receipt["pending_record"]["state"], "pending")
        self.assertTrue(receipt["reopened"]["uncertain"])
        self.assertFalse(receipt["reopened"]["pending_drained"])
        self.assertFalse(receipt["repeated_request"]["Allow"])
        self.assertFalse(receipt["actual_daemon"])
        self.assertFalse(receipt["production_acceptance"])

    def test_protocol_responses_do_not_write_daemon_response_contents(self):
        operation = self.authorize()
        self.assertTrue(self.gate.response(durable.canonical(self.response(
            operation, ResponseBody="restricted-response", ResponseHeaders={"secret": "restricted-header"})))["Allow"])
        raw = (self.root / "daemon-operation-001-returned.json").read_bytes()
        self.assertNotIn(b"restricted-response", raw)
        self.assertNotIn(b"restricted-header", raw)
