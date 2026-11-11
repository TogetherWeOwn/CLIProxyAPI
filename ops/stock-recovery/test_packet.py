"""Offline source-binding tests. These do not qualify a runtime or recovery."""

import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("stock_packet", ROOT / "packet.py")
packet = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packet)


class SourcePacketTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest = json.loads((ROOT / "manifest.json").read_text())
        for name in self.manifest["files"]:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def test_bound_source_is_still_hold_and_not_service_evidence(self):
        result = packet.verify(self.manifest, self.root)
        self.assertEqual(result["source_binding"], "BOUND")
        self.assertEqual(result["qualification"], "HOLD")
        self.assertEqual(result["service_recovery"], "NOT_TESTED")
        self.assertIs(result["execution_authorized"], False)
        self.assertEqual(result["unresolved_bindings"], list(packet.REQUIRED_BINDINGS))

    def test_refusal_never_admits_recovery_writes(self):
        result = packet.refusal_report(possibly_submitted=True, observation_available=True,
                                       service_unavailable=False)
        self.assertEqual(result["outcome"], "RECOVERY_NOT_PROVEN")
        self.assertIs(result["recovery_write_admitted"], False)
        self.assertIs(result["recovery_success"], False)
        self.assertIs(result["execution_authorized"], False)

    def test_refusal_classifies_observation_loss_and_service_failure(self):
        for submitted, observable, unavailable, expected in (
            (False, True, False, "ABORT_UNCHANGED"),
            (True, False, False, "UNKNOWN"),
            (True, False, True, "UNKNOWN"),
            (True, True, True, "FUNCTIONAL_FAIL"),
        ):
            with self.subTest(expected=expected, observable=observable):
                result = packet.refusal_report(possibly_submitted=submitted, observation_available=observable,
                                               service_unavailable=unavailable)
                self.assertEqual(result["outcome"], expected)
                self.assertFalse(result["recovery_write_admitted"])
                self.assertFalse(result["recovery_success"])
        with self.assertRaises(packet.PacketError):
            packet.refusal_report(possibly_submitted=None, observation_available=True,
                                  service_unavailable=False)

    def test_index_digest_is_not_a_docker_image_id(self):
        self.manifest["candidate"]["docker_image_id"] = self.manifest["candidate"]["index_digest"]
        with self.assertRaisesRegex(packet.PacketError, "config digest"):
            packet.verify(self.manifest, self.root)

    def test_manifest_digest_is_not_a_docker_image_id(self):
        self.manifest["candidate"]["docker_image_id"] = self.manifest["candidate"]["manifest_digest"]
        with self.assertRaisesRegex(packet.PacketError, "config digest"):
            packet.verify(self.manifest, self.root)

    def test_platform_mismatch_is_rejected(self):
        self.manifest["candidate"]["platform"]["architecture"] = "arm64"
        with self.assertRaisesRegex(packet.PacketError, "platform"):
            packet.verify(self.manifest, self.root)

    def test_unqualified_alternative_recovery_target_is_rejected(self):
        self.manifest["candidate"]["recovery_manifest_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(packet.PacketError, "separate qualification"):
            packet.verify(self.manifest, self.root)

    def test_each_missing_acceptance_gate_is_rejected(self):
        for gate in packet.REQUIRED_BINDINGS:
            with self.subTest(gate=gate):
                changed = copy.deepcopy(self.manifest)
                changed["unresolved_bindings"].remove(gate)
                with self.assertRaisesRegex(packet.PacketError, "every unresolved"):
                    packet.verify(changed, self.root)

    def test_source_tampering_is_rejected(self):
        name = next(iter(self.manifest["files"]))
        (self.root / name).write_bytes(b"not the frozen source")
        with self.assertRaisesRegex(packet.PacketError, "hash mismatch"):
            packet.verify(self.manifest, self.root)

    def test_oci_digest_tampering_is_rejected(self):
        for kind in ("index", "manifest", "config"):
            with self.subTest(kind=kind):
                changed = copy.deepcopy(self.manifest)
                changed["candidate"][kind + "_digest"] = "sha256:" + "0" * 64
                with self.assertRaisesRegex(packet.PacketError, "digest mismatch"):
                    packet.verify(changed, self.root)

    def test_oci_inputs_must_be_source_bound(self):
        del self.manifest["files"][self.manifest["candidate"]["config_file"]]
        with self.assertRaisesRegex(packet.PacketError, "source-bound"):
            packet.verify(self.manifest, self.root)

    def test_symlink_input_is_rejected(self):
        (self.root / "outside").symlink_to(ROOT / "packet.py")
        with self.assertRaisesRegex(packet.PacketError, "symlinks"):
            packet.checked_file(self.root, "outside")

    def test_path_traversal_and_absolute_inputs_are_rejected(self):
        for name in ("../packet.py", "/etc/passwd", "oci/../../packet.py", "oci/./index.json", "", "oci//index.json"):
            with self.subTest(name=name), self.assertRaises(packet.PacketError):
                packet.checked_file(self.root, name)

    def test_bounded_input(self):
        (self.root / "large").write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaisesRegex(packet.PacketError, "one MiB"):
            packet.checked_file(self.root, "large")

    def test_cli_does_not_expose_invalid_input_contents(self):
        invalid = self.root / "invalid.json"
        for value in ('{"fake-secret": "do-not-print-this",', '[]', 'null', '"do-not-print-this"'):
            with self.subTest(value=value):
                invalid.write_text(value)
                result = subprocess.run(
                    [sys.executable, "-I", str(ROOT / "packet.py"), str(invalid)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("do-not-print-this", result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)["qualification"], "HOLD")


if __name__ == "__main__":
    unittest.main()
