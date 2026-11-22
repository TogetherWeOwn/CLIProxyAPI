"""Deterministic fixtures and focused tests for the offline verifier."""

import copy
import json
import unittest

import preflight as p


def attempt(number):
    return p.digest({"run": "fixture-run", "attempt": number})


def record(key, claims):
    return {"claims": claims, "seal": p.seal(key, claims)}


def envelope(number=1):
    rollback = {
        field: p.digest(f"fixture-{field}")
        for field in ("source", "build", "oci", "image", "binary", "compose", "config", "runtime_config")
    }
    rollback.update(platform="linux/amd64", plugins=[{
        "filename": "fixture-provider.so", "abi": "fixture-abi-1",
        "library": p.digest("fixture-library-old"),
        "registrations": ["fixture-route"], "disabled_providers": ["fixture-disabled"],
    }])
    candidate = copy.deepcopy(rollback)
    candidate["plugins"][0]["library"] = p.digest("fixture-library-new")
    manifest = {"version": 1, "workflow": p.digest("fixture-preflight-workflow-v1"),
                "candidate": candidate, "rollback": rollback}
    return signed_envelope(manifest, number)


def signed_envelope(manifest, number):
    receipt = record(p.STAGING_KEY, {
        "issuer": "fixture-staging-issuer", "workflow": p.digest("fixture-staging-workflow-v1"),
        "manifest": p.digest(manifest), "attempt": attempt(number), "issued": 100, "expires": 300,
        "artifact": p.digest(f"fixture-artifact-{number}"),
        "qualification": p.digest("fixture-qualification"),
        "config_compatibility": p.digest("fixture-config-compatibility"),
        "checks": {name: True for name in (
            "source_checks", "source_reviews", "readiness", "registrations",
            "disabled_providers", "write_cohort_a", "write_cohort_b",
            "zero_internal_499s", "fresh_routes", "rollback_rehearsal",
        )},
    })
    approval = record(p.ACCEPTANCE_KEY, {
        "issuer": "fixture-acceptance-issuer", "decision": "APPROVE", "manifest": p.digest(manifest),
        "attempt": attempt(number), "receipt": p.digest(receipt), "issued": 150, "expires": 250,
    })
    return {"manifest": manifest, "staging_receipt": receipt, "release_approval": approval}


class PreflightTests(unittest.TestCase):
    def verdict(self, data, number=1):
        return p.verify(json.dumps(data).encode("ascii"), attempt(number))

    def test_plugin_only_and_canonical_key_order(self):
        data = envelope()
        candidate, rollback = (data["manifest"][key] for key in ("candidate", "rollback"))
        self.assertEqual(candidate["image"], rollback["image"])
        self.assertNotEqual(candidate["plugins"], rollback["plugins"])
        self.assertEqual(self.verdict(data), "fixture-match")
        self.assertEqual(p.verify(p.canonical(data), attempt(1)), "fixture-match")

    def test_each_bundle_identity_is_bound(self):
        for side in ("candidate", "rollback"):
            original = envelope()["manifest"][side]
            for field in original.keys() - {"plugins", "platform"}:
                with self.subTest(side=side, field=field):
                    data = envelope()
                    data["manifest"][side][field] = p.digest("fixture-substitution")
                    self.assertEqual(self.verdict(data), "fixture-staging-rejected")
            for field, value in {
                "filename": "fixture-other.so", "abi": "fixture-abi-2",
                "library": p.digest("fixture-other-library"),
                "registrations": ["fixture-other-route"], "disabled_providers": [],
            }.items():
                with self.subTest(side=side, field=field):
                    data = envelope()
                    data["manifest"][side]["plugins"][0][field] = value
                    self.assertEqual(self.verdict(data), "fixture-staging-rejected")

    def test_refuse_malformed_and_partial_input(self):
        valid = p.canonical(envelope())
        for raw in (
            b"", valid[:-1], valid + b"{}", b"\xff", b" " * p.MAX_BYTES + valid,
            valid.replace(b'"version":1', b'"version":1,"versi\\u006fn":1'),
            valid.replace(b'"version":1', b'"version":1.0'),
            valid.replace(b'"version":1', b'"version":100000000000'),
        ):
            self.assertEqual(p.verify(raw, attempt(1)), "fixture-envelope-rejected")
        rollback = envelope()["manifest"]["rollback"]
        for fields in ({"version": 2}, {"version": True}, {"unknown": None}, {"rollback": None},
                       {"workflow": p.digest("fixture-wrong-workflow")}, {"candidate": rollback}):
            manifest = envelope()["manifest"] | fields
            self.assertEqual(self.verdict(signed_envelope(manifest, 1)), "fixture-manifest-rejected")
        plugin = rollback["plugins"][0]
        for change in (
            {"platform": "linux/arm64"}, {"image": "fixture-invalid"}, {"plugins": [plugin, plugin]},
            {"plugins": [dict(plugin, filename=f"fixture-plugin-{n:02}.so") for n in range(17)]},
        ):
            data = envelope()
            data["manifest"]["candidate"].update(change)
            self.assertEqual(self.verdict(data), "fixture-manifest-rejected")
        for change in (
            {"filename": "../fixture-provider.so"}, {"filename": "fixture-é.so"},
            {"abi": "fixture-abi-3"}, {"library": "fixture-invalid"}, {"registrations": ["invalid"]},
            {"registrations": [f"fixture-route-{n:02}" for n in range(17)]},
            {"registrations": ["fixture-route", "fixture-route"]},
            {"disabled_providers": ["fixture-z", "fixture-a"]},
        ):
            data = envelope()
            data["manifest"]["candidate"]["plugins"][0].update(change)
            self.assertEqual(self.verdict(data), "fixture-manifest-rejected")
        data = envelope()
        del data["staging_receipt"]["claims"]["checks"]["rollback_rehearsal"]
        self.assertEqual(self.verdict(data), "fixture-staging-rejected")
        data = envelope()
        data["release_approval"]["extra"] = data["release_approval"]["claims"]
        self.assertEqual(self.verdict(data), "fixture-acceptance-rejected")

    def test_refuse_stale_invalid_or_wrong_issuer_evidence(self):
        staging_cases = ({"workflow": p.digest("fixture-other-workflow")}, {"artifact": "fixture-invalid"},
                         {"issued": -1, "expires": 201})
        for name, key, expected, extra in (
            ("staging_receipt", p.STAGING_KEY, "fixture-staging-rejected", staging_cases),
            ("release_approval", p.ACCEPTANCE_KEY, "fixture-acceptance-rejected", ({"issued": 99}, {"decision": "BLOCK"})),
        ):
            for changed in ({"expires": p.FIXTURE_NOW}, {"issued": p.FIXTURE_NOW + 1},
                            {"expires": 451}, {"issuer": "fixture-foreign"}, {"issued": [[[0]]]}, *extra):
                with self.subTest(record=name, changed=changed):
                    data = envelope()
                    claims = data[name]["claims"] | changed
                    data[name] = record(key, claims)
                    self.assertEqual(self.verdict(data), expected)
            data = envelope()
            data[name]["seal"] = "é" * 64
            self.assertEqual(self.verdict(data), expected)
        data = envelope()
        data["release_approval"]["claims"]["expires"] += 1
        self.assertEqual(self.verdict(data), "fixture-acceptance-rejected")
        data = envelope()
        data["release_approval"] = record(p.STAGING_KEY, data["release_approval"]["claims"])
        self.assertEqual(self.verdict(data), "fixture-acceptance-rejected")
        data = envelope()
        claims = data["staging_receipt"]["claims"]
        claims["checks"]["rollback_rehearsal"] = False
        data["staging_receipt"] = record(p.STAGING_KEY, claims)
        self.assertEqual(self.verdict(data), "fixture-staging-rejected")

    def test_refuse_cross_attempt_replay_and_receipt_substitution(self):
        second = envelope(2)
        self.assertEqual(self.verdict(second, 2), "fixture-match")
        self.assertEqual(self.verdict(envelope(), 2), "fixture-staging-rejected")
        for name, expected in (("staging_receipt", "fixture-staging-rejected"),
                               ("release_approval", "fixture-acceptance-rejected")):
            data = envelope()
            data[name] = second[name]
            self.assertEqual(self.verdict(data), expected)
        for changed in ({"attempt": attempt(2)}, {"manifest": p.digest("fixture-other-manifest")}):
            data = envelope()
            claims = data["release_approval"]["claims"] | changed
            data["release_approval"] = record(p.ACCEPTANCE_KEY, claims)
            self.assertEqual(self.verdict(data), "fixture-acceptance-rejected")
        data = envelope()
        claims = data["staging_receipt"]["claims"] | {"artifact": p.digest("fixture-other-artifact")}
        data["staging_receipt"] = record(p.STAGING_KEY, claims)
        self.assertEqual(self.verdict(data), "fixture-acceptance-rejected")


if __name__ == "__main__":
    # Hosted logs report a fixed verdict without test data or exception details.
    result = unittest.defaultTestLoader.loadTestsFromTestCase(PreflightTests).run(unittest.TestResult())
    passed = result.testsRun > 0 and result.wasSuccessful() and not (result.skipped or result.expectedFailures)
    print("fixture-preflight-pass" if passed else "fixture-preflight-fail")
    raise SystemExit(0 if passed else 1)
