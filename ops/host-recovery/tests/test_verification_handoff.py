"""Scripted gate/oracle callbacks only; no helper build, daemon or old start."""
import copy
import unittest

from host_recovery import baseline_gate, deployment, durable
from test_deployment import Oracle
from test_recovery_state import intent


class InputGate(baseline_gate.RestoredInputGate):
    def __init__(self):
        self.hook, self.calls = None, 0

    def verify(self, value, *, deadline):
        self.calls += 1
        if self.hook:
            self.hook(value)
        return True


class DeploymentGate(deployment.OldDeploymentGate):
    def __init__(self):
        self.hook, self.calls = None, 0

    def verify(self, value, *, deadline):
        self.calls += 1
        if self.hook:
            self.hook(value)
        return {"deployment_matches": True, "start_authorized": False}


class VerificationHandoffTests(unittest.TestCase):
    def cases(self):
        for wrapper, gate_type in ((baseline_gate.RecoveredInputBoundary, InputGate),
                                   (deployment.RecoveredDeploymentBoundary, DeploymentGate)):
            self.value, self.oracle, self.gate = intent(), Oracle(), gate_type()
            self.boundary = wrapper(self.oracle, self.gate)
            yield wrapper.__name__

    def stopped(self):
        return self.boundary.verify_baseline_stopped(self.value, deadline=50)

    def start(self, receipt):
        return self.boundary.start_old(self.value, receipt, deadline=50)

    def test_original_receipt_is_detached_before_gate_callback(self):
        for _ in self.cases():
            self.gate.hook = lambda value: self.oracle.receipt.update(new_plugin_absent=False)
            receipt = self.stopped()
            self.assertIs(receipt["new_plugin_absent"], True)
            self.assertIs(self.start(receipt), True)
            self.assertEqual(self.oracle.starts, 1)

    def test_oracle_callback_cannot_rebind_caller_intent(self):
        for _ in self.cases():
            def observe(value, *, deadline):
                self.value["package_sha256"] = "0" * 64
                return copy.deepcopy(self.oracle.receipt)
            self.oracle.verify_baseline_stopped = observe
            with self.assertRaises(durable.Rejected):
                self.stopped()
            self.assertEqual(self.gate.calls, 0)
            self.assertEqual(self.oracle.starts, 0)

    def test_gate_callback_cannot_rebind_caller_intent(self):
        for _ in self.cases():
            self.gate.hook = lambda value: self.value.update(package_sha256="0" * 64)
            with self.assertRaises(durable.Rejected):
                self.stopped()
            self.assertEqual(self.gate.calls, 1)
            with self.assertRaises(durable.Rejected):
                self.start(self.oracle.receipt)
            self.assertEqual(self.oracle.starts, 0)

    def test_start_gate_cannot_mutate_caller_intent_or_receipt(self):
        for _ in self.cases():
            for target in ("intent", "receipt"):
                with self.subTest(target=target):
                    self.boundary = type(self.boundary)(self.oracle, self.gate)
                    receipt = self.stopped()
                    def mutate(value):
                        if target == "intent":
                            self.value["package_sha256"] = "0" * 64
                        else:
                            receipt["new_plugin_absent"] = False
                    self.gate.hook = mutate
                    with self.assertRaises(durable.Rejected):
                        self.start(receipt)
                    self.assertEqual(self.oracle.starts, 0)
                    with self.assertRaises(durable.Rejected):
                        self.start(receipt)
                    self.gate.hook = None
                    self.value = intent()

    def test_gate_cannot_validate_a_mutated_disposable_input(self):
        for _ in self.cases():
            def change_gate_input(value):
                value["package_sha256"] = "0" * 64
            self.gate.hook = change_gate_input
            with self.assertRaises(durable.Rejected):
                self.stopped()
            self.assertEqual(self.oracle.starts, 0)
            self.assertNotEqual(self.value["package_sha256"], "0" * 64)

    def test_oracle_cannot_validate_a_mutated_disposable_input(self):
        for _ in self.cases():
            def observe(value, *, deadline):
                value["package_sha256"] = "0" * 64
                return copy.deepcopy(self.oracle.receipt)
            self.oracle.verify_baseline_stopped = observe
            with self.assertRaises(durable.Rejected):
                self.stopped()
            self.assertEqual(self.gate.calls, 0)
            self.assertEqual(self.oracle.starts, 0)

    def test_start_gate_cannot_validate_a_mutated_disposable_input(self):
        for _ in self.cases():
            receipt = self.stopped()
            self.gate.hook = lambda value: value.update(package_sha256="0" * 64)
            with self.assertRaises(durable.Rejected):
                self.start(receipt)
            self.assertEqual(self.oracle.starts, 0)

    def test_unchanged_handoff_delegates_exact_original_values_once(self):
        for _ in self.cases():
            receipt, received = self.stopped(), []
            def start(value, proof, *, deadline):
                received.append((value, proof, deadline))
                return True
            self.oracle.start_old = start
            self.assertTrue(self.start(receipt))
            self.assertEqual(received, [(self.value, receipt, 50)])
            with self.assertRaises(durable.Rejected):
                self.start(receipt)
            self.assertEqual(len(received), 1)

    def test_oracle_and_gate_replacement_during_observation_refuse(self):
        for _ in self.cases():
            for target in ("boundary", "gate"):
                with self.subTest(target=target):
                    self.boundary = type(self.boundary)(self.oracle, self.gate)
                    def replace(value):
                        setattr(self.boundary, target, Oracle() if target == "boundary" else type(self.gate)())
                    self.gate.hook = replace
                    with self.assertRaises(durable.Rejected):
                        self.stopped()
                    self.assertEqual(self.oracle.starts, 0)

    def test_verified_oracle_and_gate_cannot_be_replaced_before_start(self):
        for _ in self.cases():
            for target in ("boundary", "gate"):
                with self.subTest(target=target):
                    self.boundary = type(self.boundary)(self.oracle, self.gate)
                    receipt = self.stopped()
                    replacement = Oracle() if target == "boundary" else type(self.gate)()
                    setattr(self.boundary, target, replacement)
                    with self.assertRaises(durable.Rejected):
                        self.start(receipt)
                    self.assertEqual(self.oracle.starts, 0)
                    if target == "boundary":
                        self.assertEqual(replacement.starts, 0)

    def test_oracle_and_gate_replacement_during_start_refuse(self):
        for _ in self.cases():
            for target in ("boundary", "gate"):
                with self.subTest(target=target):
                    self.gate.hook = None
                    self.boundary = type(self.boundary)(self.oracle, self.gate)
                    receipt = self.stopped()
                    replacement = Oracle() if target == "boundary" else type(self.gate)()
                    self.gate.hook = lambda value: setattr(self.boundary, target, replacement)
                    with self.assertRaises(durable.Rejected):
                        self.start(receipt)
                    self.assertEqual(self.oracle.starts, 0)
                    if target == "boundary":
                        self.assertEqual(replacement.starts, 0)

    def test_caught_reentrant_refusal_cannot_be_promoted_to_verified(self):
        for _ in self.cases():
            def reenter(value):
                with self.assertRaises(durable.Rejected):
                    self.stopped()
            self.gate.hook = reenter
            with self.assertRaises(durable.Rejected):
                self.stopped()
            self.assertEqual(self.gate.calls, 1)
            self.assertEqual(self.oracle.starts, 0)

    def test_caught_reentrant_start_refusal_cannot_delegate_outer_start(self):
        for _ in self.cases():
            receipt = self.stopped()
            def reenter(value):
                with self.assertRaises(durable.Rejected):
                    self.start(receipt)
            self.gate.hook = reenter
            with self.assertRaises(durable.Rejected):
                self.start(receipt)
            self.assertEqual(self.oracle.starts, 0)

    def test_returned_receipt_edit_is_not_a_new_verification(self):
        for _ in self.cases():
            receipt = self.stopped()
            receipt["original_image"] = False
            with self.assertRaises(durable.Rejected):
                self.start(receipt)
            self.assertEqual(self.oracle.starts, 0)
