"""Actions-identity controls. These verify evidence binding only."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("actions_identity", ROOT / "actions_identity.py")
actions_identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(actions_identity)

SHA = "a" * 40


def source_env(**overrides):
    env = {
        "HEAD_SHA": SHA,
        "GITHUB_RUN_ID": "42883570020",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "source-packet",
    }
    env.update(overrides)
    return env


def bootstrap_env(**overrides):
    env = source_env(GITHUB_JOB="runtime-bootstrap", JOB_STATUS="success")
    env.update(overrides)
    return env


class ActionsIdentityTests(unittest.TestCase):
    def test_source_identity_binds_exact_head_and_holds(self):
        result = actions_identity.build_identity("source", source_env())
        self.assertEqual(result, {
            "head_sha": SHA,
            "run_id": "42883570020",
            "run_attempt": "1",
            "job": "source-packet",
            "qualification": "HOLD",
            "service_recovery": "NOT_TESTED",
        })

    def test_bootstrap_identity_binds_exact_head_and_holds(self):
        result = actions_identity.build_identity("bootstrap", bootstrap_env())
        self.assertEqual(result, {
            "HEAD_SHA": SHA,
            "GITHUB_RUN_ID": "42883570020",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_JOB": "runtime-bootstrap",
            "JOB_STATUS": "success",
            "qualification": "HOLD",
            "service_recovery": "NOT_TESTED",
            "journal_matrix": "NOT_RUN",
        })

    def test_unknown_mode_fails_closed(self):
        with self.assertRaisesRegex(actions_identity.ActionsIdentityError, "unknown actions identity mode"):
            actions_identity.build_identity("runtime", source_env())

    def test_non_mapping_env_fails_closed(self):
        with self.assertRaises(actions_identity.ActionsIdentityError):
            actions_identity.build_identity("source", ["HEAD_SHA"])

    def test_missing_env_value_fails_closed(self):
        for name in ("HEAD_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB"):
            with self.subTest(name=name):
                env = source_env()
                del env[name]
                with self.assertRaisesRegex(actions_identity.ActionsIdentityError, "missing"):
                    actions_identity.build_identity("source", env)

    def test_bootstrap_missing_job_status_fails_closed(self):
        env = bootstrap_env()
        del env["JOB_STATUS"]
        with self.assertRaisesRegex(actions_identity.ActionsIdentityError, "missing"):
            actions_identity.build_identity("bootstrap", env)

    def test_empty_and_whitespace_env_values_fail_closed(self):
        for value in ("", "  ", " success"):
            with self.subTest(value=value):
                with self.assertRaises(actions_identity.ActionsIdentityError):
                    actions_identity.build_identity("bootstrap", bootstrap_env(JOB_STATUS=value))

    def test_control_characters_in_env_value_fail_closed(self):
        with self.assertRaisesRegex(actions_identity.ActionsIdentityError, "malformed"):
            actions_identity.build_identity("source", source_env(GITHUB_JOB="source\npacket"))

    def test_malformed_head_sha_fails_closed(self):
        for sha in ("a" * 39, "a" * 41, "g" * 40, "A" * 40):
            with self.subTest(sha=sha):
                with self.assertRaisesRegex(actions_identity.ActionsIdentityError, "malformed"):
                    actions_identity.build_identity("source", source_env(HEAD_SHA=sha))

    def test_non_numeric_run_id_and_attempt_fail_closed(self):
        with self.assertRaises(actions_identity.ActionsIdentityError):
            actions_identity.build_identity("source", source_env(GITHUB_RUN_ID="42x"))
        with self.assertRaises(actions_identity.ActionsIdentityError):
            actions_identity.build_identity("source", source_env(GITHUB_RUN_ATTEMPT="-1"))

    def test_unknown_job_status_fails_closed(self):
        with self.assertRaisesRegex(actions_identity.ActionsIdentityError, "unknown job status"):
            actions_identity.build_identity("bootstrap", bootstrap_env(JOB_STATUS="in_progress"))

    def test_error_messages_do_not_echo_env_values(self):
        secret = "do-not-print-this"
        with self.assertRaises(actions_identity.ActionsIdentityError) as caught:
            actions_identity.build_identity("source", source_env(HEAD_SHA=secret))
        self.assertNotIn(secret, str(caught.exception))

    def test_write_identity_is_sorted_and_newline_terminated(self):
        with tempfile.TemporaryDirectory() as name:
            output = actions_identity.write_identity(
                Path(name) / "evidence" / "actions-identity.json",
                actions_identity.build_identity("source", source_env()),
            )
            text = output.read_text(encoding="utf-8")
            self.assertTrue(text.endswith("}\n"))
            self.assertEqual(json.loads(text)["head_sha"], SHA)
            self.assertEqual(text, json.dumps(json.loads(text), sort_keys=True) + "\n")

    def test_write_identity_rejects_wrong_output_name(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaisesRegex(actions_identity.ActionsIdentityError, "must be named"):
                actions_identity.write_identity(Path(name) / "identity.json", {})

    def test_write_identity_rejects_symlink_output(self):
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / "real.json"
            target.write_text("{}")
            link = Path(name) / "actions-identity.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(actions_identity.ActionsIdentityError, "symlink"):
                actions_identity.write_identity(link, {})

    def test_cli_writes_identity_from_environment(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "actions-identity.json"
            env = dict(os.environ)
            env.update(bootstrap_env())
            result = subprocess.run(
                [sys.executable, "-I", str(ROOT / "actions_identity.py"),
                 "--mode", "bootstrap", "--output", str(output)],
                capture_output=True, text=True, check=False, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())["GITHUB_JOB"], "runtime-bootstrap")

    def test_cli_fails_closed_without_exposing_env_values(self):
        secret = "do-not-print-this"
        env = dict(os.environ)
        env.update(source_env(HEAD_SHA=secret))
        result = subprocess.run(
            [sys.executable, "-I", str(ROOT / "actions_identity.py"),
             "--mode", "source", "--output", "/tmp/actions-identity.json"],
            capture_output=True, text=True, check=False, env=env,
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(secret, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
