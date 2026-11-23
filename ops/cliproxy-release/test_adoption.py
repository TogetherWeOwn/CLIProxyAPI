"""Exercise protected first-adoption admission and recovery."""

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from adoption import transact
from adoption_ingress import IngressFile
import production
from production import Gate, ReleaseError, adoption_binding, read_json, save_json

SHA = "a" * 40
DIGEST = "b" * 64
BINDING = "c" * 64


class FixtureGate(Gate):
    def __init__(self):
        self.state = None

    def read(self, method="GET", path="/status"):
        if self.state is None:
            raise FileNotFoundError
        if method == "POST":
            verb, generation, epoch = path.split("/")[1:]
            assert (generation, int(epoch)) == (self.state["generation"], self.state["epoch"])
            self.state.update(closed=verb == "close", epoch=int(epoch) + 1)
        return self.state.copy()


class AdoptionTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.journal, self.release_journal = root / "adoption.json", root / "release.json"
        self.root = root
        self.gate = FixtureGate()
        self.layout = "legacy"
        self.calls = []
        self.fail = set()

    def run_action(self, action="adopt"):
        transact(self.gate, self.adapter, self.site, self.journal, self.release_journal,
                 action, DIGEST, BINDING, drain_seconds=1)

    def site(self, verb, digest, binding):
        self.assertEqual((digest, binding), (DIGEST, BINDING))
        self.calls.append(verb)
        if verb == "isolate":
            self.layout = "closed-legacy"
        if verb in self.fail:
            raise ReleaseError(f"injected failure at {verb}")
        if verb == "isolate":
            self.gate.state = {"generation": "d" * 32, "epoch": 0, "closed": True, "active": 0}
        elif verb == "restore":
            self.assertTrue(self.gate.state is None or self.gate.read()["closed"])
            self.layout = "closed-legacy"
            self.gate.state = None
        elif verb == "resume":
            self.assertEqual(self.layout, "closed-legacy")
            self.layout = "legacy"

    def adapter(self, verb, digest, phase, *, fence=None):
        self.assertEqual((digest, phase), (DIGEST, "baseline"))
        self.calls.append(verb)
        if verb == "switch":
            self.gate.require(fence, empty=True)
            self.layout = "pinned"
        if verb in self.fail:
            raise ReleaseError(f"injected failure at {verb}")

    def test_success_is_single_use_and_release_has_its_own_journal(self):
        self.run_action()
        self.assertEqual(self.layout, "pinned")
        self.assertFalse(self.gate.read()["closed"])
        self.assertEqual(self.calls, ["prepared", "legacy", "isolate", "isolated", "switch", "ready", "isolated", "serving"])
        self.assertEqual(read_json(self.journal)["phase"], "adopted")
        self.assertFalse(self.release_journal.exists())
        with self.assertRaisesRegex(ReleaseError, "already attempted"):
            self.run_action()
        self.run_action("undo-adoption")
        self.assertEqual(self.layout, "legacy")
        self.assertEqual(read_json(self.journal)["phase"], "undone")

    def test_readiness_failure_restores_legacy_and_reports_failure(self):
        self.fail.add("ready")
        with self.assertRaisesRegex(ReleaseError, "failed and legacy ingress was restored"):
            self.run_action()
        self.assertEqual(self.layout, "legacy")
        self.assertEqual(self.calls[-3:], ["undo-isolate", "restore", "resume"])
        self.assertEqual(read_json(self.journal)["phase"], "undone")

    def test_post_open_validation_failure_closes_gate_and_restores(self):
        self.fail.add("serving")
        with self.assertRaisesRegex(ReleaseError, "failed and legacy ingress was restored"):
            self.run_action()
        self.assertEqual(self.layout, "legacy")
        self.assertEqual(read_json(self.journal)["phase"], "undone")

    def test_write_failure_during_cutover_still_fences_both_layouts(self):
        for failed_phase, prior in (("validated", "changing"), ("adopted", "validated")):
            with self.subTest(failed_phase=failed_phase):
                self.journal.unlink(missing_ok=True)
                self.calls.clear()

                def write(path, record):
                    if record["phase"] in (failed_phase, "undoing"):
                        raise OSError("synthetic journal write failure")
                    save_json(path, record)

                with patch("adoption.save_json", side_effect=write), self.assertRaises(OSError):
                    self.run_action()
                state = self.gate.read()
                self.assertTrue(state["closed"])
                self.assertEqual(state["epoch"], 0 if failed_phase == "validated" else 2)
                self.assertEqual(read_json(self.journal)["phase"], prior)
                self.assertIn("undo-isolate", self.calls)
                self.assertNotIn("restore", self.calls)
                self.assertEqual("serving" in self.calls, failed_phase == "adopted")
                self.run_action("undo-adoption")

    def test_interruption_after_validation_record_can_resume_undo(self):
        with patch.object(self.gate, "change", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.run_action()
        self.assertEqual(read_json(self.journal)["phase"], "validated")
        self.assertTrue(self.gate.read()["closed"])
        self.run_action("undo-adoption")
        self.assertEqual(self.layout, "legacy")

    def test_isolation_failure_recovers_without_a_gate_or_switch(self):
        self.fail.add("isolate")
        with self.assertRaisesRegex(ReleaseError, "failed and legacy ingress was restored"):
            self.run_action()
        self.assertNotIn("switch", self.calls)
        self.assertEqual(self.layout, "legacy")

    def test_failed_restore_keeps_admission_closed_until_protected_undo(self):
        self.fail.update(("ready", "restore"))
        with self.assertRaisesRegex(ReleaseError, "failure at restore"):
            self.run_action()
        self.assertTrue(self.gate.read()["closed"])
        self.assertEqual(read_json(self.journal)["phase"], "undoing")
        self.assertNotIn("resume", self.calls)
        self.fail.clear()
        self.run_action("undo-adoption")
        self.assertEqual(self.layout, "legacy")

    def test_wrong_binding_or_started_release_cannot_undo(self):
        self.run_action()
        with self.assertRaisesRegex(ReleaseError, "no matching"):
            transact(self.gate, self.adapter, self.site, self.journal, self.release_journal,
                     "undo-adoption", DIGEST, "e" * 64)
        save_json(self.release_journal, {"phase": "changing", "digest": DIGEST})
        with self.assertRaisesRegex(ReleaseError, "unused release pair"):
            self.run_action("undo-adoption")
        self.assertFalse(self.gate.read()["closed"])

    def test_ingress_restore_preserves_metadata_and_refuses_unknown_writes(self):
        live, original, adopted = (self.root / name for name in ("live", "original", "adopted"))
        live.write_bytes(b"legacy Caddy config")
        live.chmod(0o640)
        original.write_bytes(live.read_bytes())
        adopted.write_bytes(b"pinned Caddy config")
        binding = IngressFile(live, original, adopted, hashlib.sha256(original.read_bytes()).hexdigest(),
                              hashlib.sha256(adopted.read_bytes()).hexdigest(),
                              (live.stat().st_uid, live.stat().st_gid, 0o640))
        binding.verify(adopted=False)
        binding.apply(adopted=True)
        binding.verify(adopted=True)
        binding.apply(adopted=False)
        binding.verify(adopted=False)
        live.write_bytes(b"operator changed config")
        with self.assertRaisesRegex(ReleaseError, "drift"):
            binding.apply(adopted=True)
        self.assertEqual(live.read_bytes(), b"operator changed config")

    def test_separate_approval_binds_machine_workflow_and_manifest(self):
        approval = self.root / "adoption-approved.json"
        manifest = self.root / "adoption.json"
        machine = Path("/etc/machine-id").read_text(encoding="ascii").strip()
        with patch.object(production, "HOST_ROOT", self.root):
            with self.assertRaisesRegex(ReleaseError, "disabled"):
                adoption_binding("adopt", SHA, DIGEST)
            manifest.write_bytes(b"synthetic binding")
            binding = hashlib.sha256(manifest.read_bytes()).hexdigest()
            record = {"machine_id": machine, "workflow_sha": SHA, "bundle_sha256": DIGEST,
                      "binding_sha256": binding}
            save_json(approval, dict(record, machine_id="0" * 32))
            with self.assertRaisesRegex(ReleaseError, "not approved"):
                adoption_binding("adopt", SHA, DIGEST)
            save_json(approval, record)
            self.assertEqual(adoption_binding("adopt", SHA, DIGEST), binding)
            with self.assertRaisesRegex(ReleaseError, "not approved"):
                adoption_binding("adopt", "f" * 40, DIGEST)
            self.assertEqual(adoption_binding("undo-adoption", "f" * 40, DIGEST), binding)
            manifest.write_bytes(b"drift")
            with self.assertRaisesRegex(ReleaseError, "binding changed"):
                adoption_binding("undo-adoption", SHA, DIGEST)


if __name__ == "__main__":
    unittest.main()
