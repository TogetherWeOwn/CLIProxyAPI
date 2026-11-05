"""Fixture guards only: no root, daemon, process or manager calls."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import runtime_task_fixture as fixture


class RuntimeTaskFixtureNamesTests(unittest.TestCase):
    def test_supported_run_identities_fit_private_shim_socket_limit(self):
        for run, attempt in (("42125447463", "1"), ("9" * 20, "9" * 20), ("1", "1")):
            with self.subTest(run=run, attempt=attempt):
                root, unit, slice_name = fixture.fixture_names(run, attempt)
                self.assertLessEqual(len(str(root / "s")), 42)
                fixture.config_bytes(root)
                self.assertIn("r" + run + "a" + attempt, unit)
                self.assertIn("r" + run + "a" + attempt, slice_name)

    def test_names_are_stable_and_separate_attempts(self):
        first = fixture.fixture_names("42125447463", "1")
        self.assertEqual(first, fixture.fixture_names("42125447463", "1"))
        other = fixture.fixture_names("42125447463", "2")
        self.assertTrue(all(a != b for a, b in zip(first, other)))

    def test_explicit_null_node_has_separate_narrow_device_permission(self):
        spec = fixture.oci_spec("/synthetic/rootfs", "/synthetic/task")
        self.assertEqual(spec["linux"]["devices"][0]["path"], "/dev/null")
        self.assertEqual(spec["linux"]["resources"]["devices"], [
            {"allow": False, "type": "a", "access": "rwm"},
            {"allow": True, "type": "c", "major": 1, "minor": 3, "access": "rwm"}])

    def test_synthetic_spec_has_no_host_mounts_or_process_capabilities(self):
        spec = fixture.oci_spec("/synthetic/rootfs", "/synthetic/task")
        self.assertEqual(spec["linux"]["cgroupsPath"], "/synthetic/task")
        self.assertIs(spec["process"]["noNewPrivileges"], True)
        self.assertTrue(all(value == [] for value in spec["process"]["capabilities"].values()))
        self.assertEqual({mount["type"] for mount in spec["mounts"]}, {"proc", "tmpfs"})
        self.assertEqual({entry["type"] for entry in spec["linux"]["namespaces"]},
                         {"pid", "mount", "ipc", "uts", "network"})

    def test_exact_daemon_stop_completion_required(self):
        unit, job = "synthetic.service", "/org/freedesktop/systemd1/job/42"
        event = {"job_id": 42, "job_path": job, "unit": unit, "result": "done", "sender_cookie": 7}
        fixture.require_stop_completion(event, unit, job)
        for key, value in (("job_id", 43), ("job_id", True), ("job_path", job + "0"),
                           ("unit", "other.service"), ("result", "canceled"), ("result", "failed"),
                           ("sender_cookie", 0), ("sender_cookie", True)):
            with self.subTest(key=key, value=value):
                bad = copy.deepcopy(event)
                bad[key] = value
                with self.assertRaises(AssertionError):
                    fixture.require_stop_completion(bad, unit, job)

    def test_incomplete_or_extended_daemon_completion_refuses(self):
        unit, job = "synthetic.service", "/org/freedesktop/systemd1/job/42"
        event = {"job_id": 42, "job_path": job, "unit": unit, "result": "done", "sender_cookie": 7}
        for key in event:
            bad = dict(event)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(AssertionError):
                fixture.require_stop_completion(bad, unit, job)
        with self.assertRaises(AssertionError):
            fixture.require_stop_completion({**event, "drained": True}, unit, job)

    def test_fixture_receipts_are_durable_readback_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checks = []
            current = lambda: checks.append(True)
            checksum = fixture.fixture_record(root, "pending.json", {"synthetic": True}, current)
            raw = (root / "pending.json").read_bytes()
            self.assertEqual(json.loads(raw), {"synthetic": True})
            self.assertEqual(checksum, fixture.digest(raw))
            self.assertEqual(len(checks), 2)
            self.assertEqual((root / "pending.json").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                fixture.fixture_record(root, "pending.json", {"replaced": True}, current)
            self.assertEqual((root / "pending.json").read_bytes(), raw)

    def test_original_guard_loss_prevents_fixture_pending_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def lost():
                raise fixture.Rejected("synthetic-authority-lost")
            with self.assertRaisesRegex(fixture.Rejected, "synthetic-authority-lost"):
                fixture.fixture_record(root, "pending.json", {"synthetic": True}, lost)
            self.assertEqual(list(root.iterdir()), [])

    def test_ambiguous_or_unbounded_identity_refuses(self):
        for value in ("", "0", "01", "1/2", "1\n", "9" * 21, "１２"):
            with self.subTest(value=value):
                with self.assertRaises(AssertionError):
                    fixture.fixture_names(value, "1")
                with self.assertRaises(AssertionError):
                    fixture.fixture_names("1", value)
