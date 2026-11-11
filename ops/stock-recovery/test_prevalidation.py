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
        self.assertIn("authoritative_store", result["unresolved_bindings"])
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

    def test_nested_digest_host_identity_may_be_supplied(self):
        observed = make_observed(
            self.manifest,
            provider_artifacts={"claude": "sha256:" + "1" * 64, "codex": "sha256:" + "2" * 64},
        )
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertIn("provider_artifacts", result["unresolved_bindings"])

    def test_nested_secret_shaped_host_key_fails_closed(self):
        observed = make_observed(
            self.manifest,
            provider_artifacts={"provider_token": "sha256:" + "1" * 64},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "not a supported channel"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_nested_tag_host_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            provider_artifacts={"codex": "latest"},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "provider artifact"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_unknown_provider_artifact_channel_fails_closed(self):
        observed = make_observed(
            self.manifest,
            provider_artifacts={"openai": "sha256:" + "1" * 64},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "not a supported channel"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_empty_provider_artifacts_fails_closed(self):
        observed = make_observed(self.manifest, provider_artifacts={})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_matching_compose_config_still_hold(self):
        observed = make_observed(
            self.manifest,
            compose_config={
                "compose_digest": "sha256:" + "3" * 64,
                "config_digest": "sha256:" + "4" * 64,
            },
        )
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["qualification"], "HOLD")
        self.assertIn("compose_config", result["unresolved_bindings"])

    def test_partial_compose_config_fails_closed(self):
        observed = make_observed(
            self.manifest,
            compose_config={"compose_digest": "sha256:" + "3" * 64},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_unknown_compose_config_role_fails_closed(self):
        observed = make_observed(
            self.manifest,
            compose_config={
                "compose_digest": "sha256:" + "3" * 64,
                "config_digest": "sha256:" + "4" * 64,
                "service_tag": "v8.0.60",
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_compose_config_tag_fails_closed(self):
        observed = make_observed(
            self.manifest,
            compose_config={
                "compose_digest": "latest",
                "config_digest": "sha256:" + "4" * 64,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "compose/config digest"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_empty_compose_config_fails_closed(self):
        observed = make_observed(self.manifest, compose_config={})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_matching_authoritative_store_still_hold(self):
        observed = make_observed(
            self.manifest,
            authoritative_store={"postgres": "sha256:" + "5" * 64},
        )
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["qualification"], "HOLD")
        self.assertIn("authoritative_store", result["unresolved_bindings"])

    def test_two_authoritative_stores_fails_closed(self):
        observed = make_observed(
            self.manifest,
            authoritative_store={
                "file": "sha256:" + "5" * 64,
                "postgres": "sha256:" + "6" * 64,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly one backend"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_unknown_authoritative_store_fails_closed(self):
        observed = make_observed(
            self.manifest,
            authoritative_store={"memory": "sha256:" + "5" * 64},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "not a supported backend"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_config_as_authoritative_store_fails_closed(self):
        observed = make_observed(
            self.manifest,
            authoritative_store={"config": "sha256:" + "5" * 64},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "not a supported backend"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_authoritative_store_tag_fails_closed(self):
        observed = make_observed(
            self.manifest,
            authoritative_store={"file": "latest"},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "authoritative store digest"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_empty_authoritative_store_fails_closed(self):
        observed = make_observed(self.manifest, authoritative_store={})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_matching_policy_still_hold(self):
        observed = make_observed(
            self.manifest,
            policy={
                "disable_codex_cloaking": True,
                "disable_claude_cloak_mode": False,
                "disable_cloaking_model_list": True,
            },
        )
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["qualification"], "HOLD")

    def test_partial_policy_fails_closed(self):
        observed = make_observed(
            self.manifest,
            policy={"disable_codex_cloaking": True},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the cloak policy roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_unknown_policy_role_fails_closed(self):
        observed = make_observed(
            self.manifest,
            policy={
                "disable_codex_cloaking": True,
                "disable_claude_cloak_mode": False,
                "disable_cloaking_model_list": True,
                "quota_auto_reset": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the cloak policy roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_policy_string_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            policy={
                "disable_codex_cloaking": "off",
                "disable_claude_cloak_mode": False,
                "disable_cloaking_model_list": True,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_policy_digest_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            policy={
                "disable_codex_cloaking": "sha256:" + "5" * 64,
                "disable_claude_cloak_mode": False,
                "disable_cloaking_model_list": True,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_empty_policy_fails_closed(self):
        observed = make_observed(self.manifest, policy={})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_non_object_policy_fails_closed(self):
        observed = make_observed(self.manifest, policy=["disable_codex_cloaking"])
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_matching_quota_cooling_still_hold(self):
        observed = make_observed(
            self.manifest,
            quota_cooling={"codex_model_level_cooling": True, "claude_model_level_cooling": False},
        )
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["qualification"], "HOLD")

    def test_partial_quota_cooling_fails_closed(self):
        observed = make_observed(
            self.manifest,
            quota_cooling={"codex_model_level_cooling": True},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the quota cooling roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_unknown_quota_cooling_role_fails_closed(self):
        observed = make_observed(
            self.manifest,
            quota_cooling={
                "codex_model_level_cooling": True,
                "claude_model_level_cooling": False,
                "quota_auto_reset": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the quota cooling roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_quota_cooling_string_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            quota_cooling={"codex_model_level_cooling": "off", "claude_model_level_cooling": False},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_quota_cooling_digest_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            quota_cooling={"codex_model_level_cooling": "sha256:" + "5" * 64, "claude_model_level_cooling": False},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_empty_quota_cooling_fails_closed(self):
        observed = make_observed(self.manifest, quota_cooling={})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_non_object_quota_cooling_fails_closed(self):
        observed = make_observed(self.manifest, quota_cooling=["codex_model_level_cooling"])
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_matching_cooldown_still_hold(self):
        observed = make_observed(
            self.manifest,
            cooldown={"disable_cooling": False, "save_cooldown_status": False},
        )
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["qualification"], "HOLD")

    def test_partial_cooldown_fails_closed(self):
        observed = make_observed(
            self.manifest,
            cooldown={"disable_cooling": True},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the cooldown roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_unknown_cooldown_role_fails_closed(self):
        observed = make_observed(
            self.manifest,
            cooldown={
                "disable_cooling": False,
                "save_cooldown_status": False,
                "quota_auto_reset": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the cooldown roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_cooldown_string_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            cooldown={"disable_cooling": "off", "save_cooldown_status": False},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_cooldown_digest_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            cooldown={"disable_cooling": "sha256:" + "5" * 64, "save_cooldown_status": False},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_empty_cooldown_fails_closed(self):
        observed = make_observed(self.manifest, cooldown={})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_non_object_cooldown_fails_closed(self):
        observed = make_observed(self.manifest, cooldown=["disable_cooling"])
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_matching_routing_still_hold(self):
        observed = make_observed(
            self.manifest,
            routing={
                "session_affinity": False,
                "session_affinity_subagents": True,
                "force_model_prefix": False,
            },
        )
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["qualification"], "HOLD")

    def test_partial_routing_fails_closed(self):
        observed = make_observed(
            self.manifest,
            routing={"session_affinity": True},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the routing roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_unknown_routing_role_fails_closed(self):
        observed = make_observed(
            self.manifest,
            routing={
                "session_affinity": False,
                "session_affinity_subagents": True,
                "force_model_prefix": False,
                "quota_auto_reset": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the routing roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_routing_string_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            routing={
                "session_affinity": "on",
                "session_affinity_subagents": True,
                "force_model_prefix": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_routing_digest_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            routing={
                "session_affinity": "sha256:" + "5" * 64,
                "session_affinity_subagents": True,
                "force_model_prefix": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_empty_routing_fails_closed(self):
        observed = make_observed(self.manifest, routing={})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_non_object_routing_fails_closed(self):
        observed = make_observed(self.manifest, routing=["session_affinity"])
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_matching_management_still_hold(self):
        observed = make_observed(
            self.manifest,
            management={
                "allow_remote": False,
                "disable_control_panel": False,
                "disable_auto_update_panel": False,
            },
        )
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["qualification"], "HOLD")

    def test_partial_management_fails_closed(self):
        observed = make_observed(
            self.manifest,
            management={"allow_remote": False},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the management roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_unknown_management_role_fails_closed(self):
        observed = make_observed(
            self.manifest,
            management={
                "allow_remote": False,
                "disable_control_panel": False,
                "disable_auto_update_panel": False,
                "quota_auto_reset": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the management roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_management_string_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            management={
                "allow_remote": "on",
                "disable_control_panel": False,
                "disable_auto_update_panel": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_management_digest_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            management={
                "allow_remote": "sha256:" + "5" * 64,
                "disable_control_panel": False,
                "disable_auto_update_panel": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_empty_management_fails_closed(self):
        observed = make_observed(self.manifest, management={})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_non_object_management_fails_closed(self):
        observed = make_observed(self.manifest, management=["allow_remote"])
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_matching_server_still_hold(self):
        observed = make_observed(
            self.manifest,
            server={
                "commercial_mode": False,
                "tls_enable": False,
                "response_compression_enabled": True,
                "discovery_enabled": False,
                "discovery_auth_required": True,
            },
        )
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["qualification"], "HOLD")

    def test_partial_server_fails_closed(self):
        observed = make_observed(
            self.manifest,
            server={"commercial_mode": False},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the server roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_unknown_server_role_fails_closed(self):
        observed = make_observed(
            self.manifest,
            server={
                "commercial_mode": False,
                "tls_enable": False,
                "response_compression_enabled": True,
                "discovery_enabled": False,
                "discovery_auth_required": True,
                "quota_auto_reset": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the server roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_server_string_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            server={
                "commercial_mode": "on",
                "tls_enable": False,
                "response_compression_enabled": True,
                "discovery_enabled": False,
                "discovery_auth_required": True,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_server_digest_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            server={
                "commercial_mode": "sha256:" + "5" * 64,
                "tls_enable": False,
                "response_compression_enabled": True,
                "discovery_enabled": False,
                "discovery_auth_required": True,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_empty_server_fails_closed(self):
        observed = make_observed(self.manifest, server={})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_non_object_server_fails_closed(self):
        observed = make_observed(self.manifest, server=["commercial_mode"])
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_matching_client_still_hold(self):
        observed = make_observed(
            self.manifest,
            client={
                "codex_enable_apply_patch": False,
                "codex_optimize_multi_agent_v2": False,
                "codex_web_search_result_cache_enabled": False,
                "claude_show_codex_commentary": False,
            },
        )
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["qualification"], "HOLD")

    def test_partial_client_fails_closed(self):
        observed = make_observed(
            self.manifest,
            client={"codex_enable_apply_patch": False},
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the client roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_unknown_client_role_fails_closed(self):
        observed = make_observed(
            self.manifest,
            client={
                "codex_enable_apply_patch": False,
                "codex_optimize_multi_agent_v2": False,
                "codex_web_search_result_cache_enabled": False,
                "claude_show_codex_commentary": False,
                "quota_auto_reset": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "exactly the client roles"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_client_string_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            client={
                "codex_enable_apply_patch": "on",
                "codex_optimize_multi_agent_v2": False,
                "codex_web_search_result_cache_enabled": False,
                "claude_show_codex_commentary": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_client_digest_value_fails_closed(self):
        observed = make_observed(
            self.manifest,
            client={
                "codex_enable_apply_patch": "sha256:" + "5" * 64,
                "codex_optimize_multi_agent_v2": False,
                "codex_web_search_result_cache_enabled": False,
                "claude_show_codex_commentary": False,
            },
        )
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_empty_client_fails_closed(self):
        observed = make_observed(self.manifest, client={})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_non_object_client_fails_closed(self):
        observed = make_observed(self.manifest, client=["codex_enable_apply_patch"])
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_matching_disabled_providers_still_hold(self):
        observed = make_observed(
            self.manifest,
            disabled_providers={"openrouter": True, "custom-provider": False},
        )
        result = prevalidation.prevalidate(self.manifest, observed)
        self.assertTrue(result["identity_match"])
        self.assertEqual(result["qualification"], "HOLD")

    def test_empty_disabled_providers_fails_closed(self):
        observed = make_observed(self.manifest, disabled_providers={})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_non_object_disabled_providers_fails_closed(self):
        observed = make_observed(self.manifest, disabled_providers=["openrouter"])
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "non-empty object"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_disabled_provider_string_value_fails_closed(self):
        observed = make_observed(self.manifest, disabled_providers={"openrouter": "true"})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_disabled_provider_digest_value_fails_closed(self):
        observed = make_observed(self.manifest, disabled_providers={"openrouter": "sha256:" + "5" * 64})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must be a boolean"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_secret_shaped_disabled_provider_fails_closed(self):
        observed = make_observed(self.manifest, disabled_providers={"api_key_provider": True})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "must not carry secrets"):
            prevalidation.prevalidate(self.manifest, observed)

    def test_malformed_disabled_provider_name_fails_closed(self):
        observed = make_observed(self.manifest, disabled_providers={1: True})
        with self.assertRaisesRegex(prevalidation.PrevalidationError, "key is malformed"):
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
