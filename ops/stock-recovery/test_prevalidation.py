"""Identity-prevalidation controls. These verify fail-closed identity binding only."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("prevalidation", ROOT / "prevalidation.py")
prevalidation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prevalidation)

PACKET_SPEC = importlib.util.spec_from_file_location("stock_packet", ROOT / "packet.py")
packet = importlib.util.module_from_spec(PACKET_SPEC)
PACKET_SPEC.loader.exec_module(packet)


def make_observed(manifest, **overrides):
    candidate = manifest["candidate"]
    observed = {
        "repository": candidate["repository"],
        "platform": dict(candidate["platform"]),
        "index_digest": candidate["index_digest"],
        "manifest_digest": candidate["manifest_digest"],
        "config_digest": candidate["config_digest"],
        "docker_image_id": candidate["docker_image_id"],
        "recovery_manifest_digest": candidate["recovery_manifest_digest"],
    }
    observed.update(overrides)
    return observed


class PrevalidationTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((ROOT / "manifest.json").read_text())
        self.observed = make_observed(self.manifest)

    def test_gate_list_mirrors_packet(self):
        self.assertEqual(list(packet.REQUIRED_BINDINGS), list(prevalidation.REQUIRED_BINDINGS))

    def test_matching_frozen_identities_still_hold(self):
        result = prevalidation.prevalidate(self.manifest, self.observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["source_binding"], "BOUND")
        self.assertEqual(result["qualification"], "HOLD")
        self.assertEqual(result["service_recovery"], "NOT_TESTED")
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["unresolved_bindings"], list(packet.REQUIRED_BINDINGS))

    def test_optional_host_identity_may_be_supplied_validated(self):
        observed = make_observed(self.manifest, compose_config_digest="sha256:" + "1" * 64)
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["qualification"], "HOLD")

    def test_missing_host_identity_stays_a_gate_not_a_default(self):
        result = prevalidation.prevalidate(self.manifest, self.observed)
        self.assertIn("compose_config", result["unresolved_bindings"])
        self.assertIn("provider_artifacts", result["unresolved_bindings"])
        self.assertIn("host_platform", result["unresolved_bindings"])

    def test_index_digest_mismatch_fails_closed(self):
        observed = make_observed(self.manifest, index_digest="sha256:" + "0" * 64)
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "index digest"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_manifest_digest_mismatch_fails_closed(self):
        observed = make_observed(self.manifest, manifest_digest="sha256:" + "0" * 64)
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "manifest digest"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_config_digest_mismatch_fails_closed(self):
        observed = make_observed(self.manifest, config_digest="sha256:" + "0" * 64)
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "config digest"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_index_as_image_id_fails_closed(self):
        observed = make_observed(
            self.manifest,
            docker_image_id=self.manifest["candidate"]["index_digest"],
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "image ID"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_manifest_as_image_id_fails_closed(self):
        observed = make_observed(
            self.manifest,
            docker_image_id=self.manifest["candidate"]["manifest_digest"],
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "image ID"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_alternative_recovery_target_fails_closed(self):
        observed = make_observed(self.manifest, recovery_manifest_digest="sha256:" + "0" * 64)
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "separate qualification"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_platform_mismatch_fails_closed(self):
        observed = make_observed(self.manifest, platform={"os": "linux", "architecture": "arm64"})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "platform"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_repository_mismatch_fails_closed(self):
        observed = make_observed(self.manifest, repository="docker.io/other/cli-proxy-api")
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "repository"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_matching_source_digests_still_hold(self):
        supplied = {
            name: self.manifest["files"][name]
            for name in ("packet.py", "attempt.py", "README.md")
        }
        observed = make_observed(self.manifest, source_digests=supplied)
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["qualification"], "HOLD")
        self.assertIn("compose_config", result["unresolved_bindings"])

    def test_missing_source_digests_stays_a_gate_not_a_default(self):
        result = prevalidation.prevalidate(self.manifest, self.observed)
        self.assertIn("compose_config", result["unresolved_bindings"])
        self.assertFalse(result["execution_authorized"])

    def test_source_digest_mismatch_fails_closed(self):
        supplied = {"packet.py": "sha256:" + "0" * 64}
        observed = make_observed(self.manifest, source_digests=supplied)
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "does not match the frozen packet"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_source_digest_tag_fails_closed(self):
        supplied = {"packet.py": "v8.0.60"}
        observed = make_observed(self.manifest, source_digests=supplied)
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "source digest"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_source_digest_unknown_file_fails_closed(self):
        supplied = {"not-a-packet-file.py": "sha256:" + "1" * 64}
        observed = make_observed(self.manifest, source_digests=supplied)
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "not in the frozen packet"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_empty_source_digests_fails_closed(self):
        observed = make_observed(self.manifest, source_digests={})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_non_object_source_digests_fails_closed(self):
        observed = make_observed(self.manifest, source_digests=["packet.py"])
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_secret_shaped_source_digest_key_fails_closed(self):
        supplied = {"provider_token.txt": "sha256:" + "1" * 64}
        observed = make_observed(self.manifest, source_digests=supplied)
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "not in the frozen packet"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_missing_required_identity_fails_closed(self):
        observed = dict(self.observed)
        del observed["config_digest"]
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "missing: config_digest"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_tag_as_identity_fails_closed(self):
        observed = make_observed(self.manifest, index_digest="v8.0.60")
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "index digest"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_malformed_host_identity_fails_closed(self):
        observed = make_observed(self.manifest, compose_config_digest="latest")
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "host-only identity"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_secret_shaped_key_fails_closed(self):
        observed = make_observed(self.manifest, provider_token="sha256:" + "1" * 64)
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "secrets"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_non_object_observed_fails_closed(self):
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be an object"):
            prevalidation.prevalidate(self.manifest, ["not", "an", "object"])

    def test_wrong_schema_fails_closed(self):
        changed = copy.deepcopy(self.manifest)
        changed["schema"] = "other/v1"
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "schema"):
            prevalidation.prevalidate(changed, self.observed)

    def test_removed_gate_fails_closed(self):
        changed = copy.deepcopy(self.manifest)
        changed["unresolved_bindings"].remove("compose_config")
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "every unresolved"):
            prevalidation.prevalidate(changed, self.observed)

    def test_non_digest_candidate_fails_closed(self):
        changed = copy.deepcopy(self.manifest)
        changed["candidate"]["index_digest"] = "v8.0.60"
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "index digest"):
            prevalidation.prevalidate(changed, self.observed)

    def test_main_accepts_matching_files(self):
        with tempfile.TemporaryDirectory() as scratch:
            manifest_path = Path(scratch) / "manifest.json"
            observed_path = Path(scratch) / "observed.json"
            manifest_path.write_text(json.dumps(self.manifest))
            observed_path.write_text(json.dumps(self.observed))
            code = prevalidation.main(["--manifest", str(manifest_path), "--observed", str(observed_path)])
            self.assertEqual(code, 0)

    def test_main_rejects_mismatched_files(self):
        with tempfile.TemporaryDirectory() as scratch:
            manifest_path = Path(scratch) / "manifest.json"
            observed_path = Path(scratch) / "observed.json"
            manifest_path.write_text(json.dumps(self.manifest))
            observed_path.write_text(json.dumps(make_observed(self.manifest, config_digest="sha256:" + "0" * 64)))
            code = prevalidation.main(["--manifest", str(manifest_path), "--observed", str(observed_path)])
            self.assertEqual(code, 1)

    def test_main_rejects_oversized_observed(self):
        with tempfile.TemporaryDirectory() as scratch:
            manifest_path = Path(scratch) / "manifest.json"
            observed_path = Path(scratch) / "observed.json"
            manifest_path.write_text(json.dumps(self.manifest))
            observed_path.write_bytes(b" " * (prevalidation.MAX_OBSERVED_BYTES + 1))
            code = prevalidation.main(["--manifest", str(manifest_path), "--observed", str(observed_path)])
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
