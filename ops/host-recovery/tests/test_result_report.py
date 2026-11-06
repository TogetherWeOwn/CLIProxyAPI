"""Real report files/publication; SCRIPTED manager, fence and current-state oracle."""
import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fixture_home import fixture_home
from host_recovery import durable, outcomes, result_report, worker_recovery
from test_installation import approve
import test_results
import test_worker_recovery


class WorkerReportTests(unittest.TestCase):
    def setUp(self):
        self.case = test_results.ResultTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        temp = tempfile.TemporaryDirectory(prefix=".result-report-", dir=fixture_home())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.directory = approve(self.root)
        self.live = True
        self.reached = []

    def gate(self, **changes):
        args = dict(directory=self.directory, oracle=self.case.oracle,
                    check=lambda **kw: self.live, clock=lambda: self.case.case.now)
        args.update(changes)
        return result_report.WorkerEvidenceOracle(**args)

    def prepare(self, process, mutate=None):
        result = self.case.prepare(process)
        intent = process.log.intent
        report = {"schema": "host-recovery-worker-evidence-v1", "request_id": result["request_id"],
            "intent_sha256": result["intent_sha256"], "claim_sha256": result["claim_sha256"],
            "status": {"outcome": "baseline_restored", "recovery_error": None, "alert_error": None,
                "evidence_error": None, "start_fenced": True, "installation_settled": False,
                "production_acceptance": False, "alert": {"receipt_persisted": True,
                    "transport_delivered": True, "human_acknowledged": False,
                    "receipt_error": None, "transport_error": None}},
            "stopped_receipt": {"baseline_sha256": intent["baseline_sha256"], "object_id": intent["old_object_id"],
                "original_image": True, "original_replay": True, "new_plugin_absent": True,
                "complete_write_set": True, "metadata_verified": True, "all_writers_stopped": True},
            "timing_events": [{"phase": "detection", "direction": "recovery", "event": "completed", "monotonic": 1005.}],
            "worker_report_only": True, "start_permission": False, "recovery_completed": False,
            "installation_settled": False}
        if mutate is not None:
            mutate(report)
        writer = worker_recovery.WorkerEvidence(self.directory, result["request_id"], clock=lambda: self.case.case.now)
        result["evidence_sha256"] = writer.write(report, deadline=1100, check=lambda **kw: True)
        self.path = self.root / ("worker-evidence-" + result["request_id"] + ".json")
        self.case.record(process, result)
        return result

    def observe(self, process, gate=None):
        return self.case.observe(process, oracle=gate or self.gate())

    def test_exact_report_readback_and_independent_oracle_leave_installation_unsettled(self):
        with self.case.case.open() as process:
            result = self.prepare(process)
            gate = self.gate()
            state = self.observe(process, gate)
            self.assertTrue(state["worker_result_observed"])
            self.assertEqual(self.case.oracle_calls[0][1], result)
            self.assertEqual(len(self.case.oracle_calls), 1)
            self.case.assert_no_grant(process)
            self.assertTrue(gate.attempted)
            self.assertFalse(gate.failed)

    def test_actual_worker_recovery_report_round_trips_without_upgrading_worker_facts(self):
        worker = test_worker_recovery.WorkerRecoveryTests()
        worker.setUp()
        self.addCleanup(worker.doCleanups)
        result = worker.run_recovery()
        envelope = {"schema": "host-recovery-worker-result-v1", "request_id": worker.request["request_id"],
            "intent_sha256": worker.request["intent_sha256"], "claim_sha256": durable.digest(durable.canonical(worker.claim)),
            **result}
        gate = self.gate(directory=approve(worker.root), clock=lambda: worker.case.time)
        receipt = gate(worker.intent, envelope, deadline=1100)
        self.assertEqual(receipt, outcomes.expected_oracle(worker.intent, envelope))
        self.assertFalse(worker.report()["recovery_completed"])
        self.assertFalse(worker.report()["installation_settled"])

    def test_missing_or_changed_hash_never_reaches_current_state_oracle(self):
        for change in (lambda p: p.unlink(), lambda p: p.write_bytes(b"{}")):
            with self.subTest(change=change):
                self.setUp()
                with self.case.case.open() as process:
                    self.prepare(process)
                    change(self.path)
                    self.assertFalse(self.observe(process)["worker_result_observed"])
                    self.assertEqual(self.case.oracle_calls, [])
                    self.case.assert_no_grant(process)

    def test_repinned_worker_claims_and_authorizing_flags_are_not_accepted(self):
        mutations = [lambda r: r.update(extra=True), lambda r: r.update(claim_sha256="a" * 64),
            lambda r: r.update(worker_report_only=1), lambda r: r.update(start_permission=0),
            lambda r: r.update(recovery_completed=True), lambda r: r.update(installation_settled=True),
            lambda r: r["status"].update(production_acceptance=True),
            lambda r: r["status"].update(recovery_error="restore-failed"),
            lambda r: r["status"]["alert"].update(transport_delivered=1),
            lambda r: r["stopped_receipt"].update(new_plugin_absent=1),
            lambda r: r.update(timing_events=[])]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.setUp()
                with self.case.case.open() as process:
                    self.prepare(process, mutation)
                    self.assertFalse(self.observe(process)["worker_result_observed"])
                    self.assertEqual(self.case.oracle_calls, [])

    def test_receipt_disk_failure_remains_distinct_from_transport_delivery(self):
        with self.case.case.open() as process:
            self.prepare(process, lambda r: r["status"]["alert"].update(
                receipt_persisted=False, receipt_error="alert-persistence-failed"))
            self.assertTrue(self.observe(process)["worker_result_observed"])
            self.case.assert_no_grant(process)

    def test_partial_stage_or_nonprivate_file_refuses(self):
        for mode in ("stage", "public", "link", "fifo"):
            with self.subTest(mode=mode):
                self.setUp()
                with self.case.case.open() as process:
                    self.prepare(process)
                    if mode == "stage":
                        self.path.with_name(".stage-" + self.path.name).write_bytes(b"incomplete")
                    elif mode == "public":
                        self.path.chmod(0o644)
                    else:
                        original = self.path.with_name("retained.json")
                        self.path.rename(original)
                        if mode == "link":
                            self.path.symlink_to(original)
                        else:
                            os.mkfifo(self.path)
                    self.assertFalse(self.observe(process)["worker_result_observed"])
                    self.assertEqual(self.case.oracle_calls, [])

    def test_replacement_or_same_inode_mutation_during_oracle_refuses(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                self.setUp()
                with self.case.case.open() as process:
                    self.prepare(process)
                    def oracle(intent, result, **kw):
                        self.reached.append("oracle")
                        if replacement:
                            raw = self.path.read_bytes()
                            self.path.unlink()
                            self.path.write_bytes(raw)
                            self.path.chmod(0o600)
                        else:
                            self.path.write_bytes(b"{}")
                        return outcomes.expected_oracle(intent, result)
                    self.assertFalse(self.observe(process, self.gate(oracle=oracle))["worker_result_observed"])
                    self.assertEqual(self.reached, ["oracle"])

    def test_report_is_revalidated_after_supervisor_observation_publication(self):
        with self.case.case.open() as process:
            self.prepare(process)
            def fault(point):
                if point == "readback":
                    self.reached.append(point)
                    self.path.write_bytes(b"{}")
            process.log.fault = fault
            state = self.observe(process)
            self.assertEqual(self.reached, ["readback"])
            self.assertEqual(len(self.case.oracle_calls), 1)
            self.assertTrue((self.case.case.root / "reconcile-result-observed.json").exists())
            self.assertFalse(state["worker_result_observed"])
            self.assertEqual(state["state"], "recovery_unresolved")
            self.case.assert_no_grant(process)

    def test_read_faults_are_reached_and_do_not_call_oracle(self):
        for code in (errno.EIO, errno.ENOSPC):
            with self.subTest(code=code):
                self.setUp()
                with self.case.case.open() as process:
                    self.prepare(process)
                    def read(*args):
                        self.reached.append(code)
                        raise OSError(code, "restricted diagnostic")
                    with patch.object(result_report.ProtectedFile, "read_at", read):
                        state = self.observe(process)
                    self.assertEqual(self.reached, [code])
                    self.assertFalse(state["worker_result_observed"])
                    self.assertNotIn("restricted", str(state))
                    self.assertEqual(self.case.oracle_calls, [])

    def test_callback_reentrancy_is_sticky_even_when_inner_refusal_is_caught(self):
        with self.case.case.open() as process:
            result = self.prepare(process)
            gate = None
            def oracle(intent, saved, **kw):
                with self.assertRaises(durable.Rejected):
                    gate(intent, saved, **kw)
                self.reached.append("caught")
                return outcomes.expected_oracle(intent, saved)
            gate = self.gate(oracle=oracle)
            self.assertFalse(self.observe(process, gate)["worker_result_observed"])
            self.assertEqual(self.reached, ["caught"])
            self.assertTrue(gate.failed)
            with self.assertRaises(durable.Rejected):
                gate(process.log.intent, result, deadline=1100)

    def test_incomplete_oracle_or_changed_observer_configuration_refuses(self):
        for mode in ("missing-fact", "check", "clock", "directory", "oracle", "expired", "backward"):
            with self.subTest(mode=mode):
                self.setUp()
                with self.case.case.open() as process:
                    self.prepare(process)
                    gate = None
                    def oracle(intent, result, **kw):
                        self.reached.append(mode)
                        receipt = outcomes.expected_oracle(intent, result)
                        if mode == "missing-fact": del receipt["old_ready"]
                        elif mode == "check": gate.check = lambda **kw: True
                        elif mode == "clock": gate.clock = lambda: 1005.
                        elif mode == "directory": gate.directory = None
                        elif mode == "oracle": gate.oracle = self.case.oracle
                        elif mode == "expired": self.case.case.now = 1100.
                        elif mode == "backward": self.case.case.now -= 1.
                        return receipt
                    gate = self.gate(oracle=oracle)
                    self.assertFalse(self.observe(process, gate)["worker_result_observed"])
                    self.assertEqual(self.reached, [mode])
                    self.case.assert_no_grant(process)

    def test_retained_descriptor_closes_after_success_or_failed_final_validation(self):
        for failure in (False, True):
            with self.subTest(failure=failure):
                self.setUp()
                with self.case.case.open() as process:
                    result = self.prepare(process)
                    gate = self.gate()
                    descriptors = set(os.listdir("/proc/self/fd"))
                    try:
                        with gate.observe(process.log.intent, result, deadline=1100):
                            if failure:
                                self.live = False
                    except durable.Rejected:
                        self.assertTrue(failure)
                    self.assertEqual(set(os.listdir("/proc/self/fd")), descriptors)
