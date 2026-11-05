"""Pure fixture naming regressions: no root, daemon, process or manager calls."""
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

    def test_ambiguous_or_unbounded_identity_refuses(self):
        for value in ("", "0", "01", "1/2", "1\n", "9" * 21, "１２"):
            with self.subTest(value=value):
                with self.assertRaises(AssertionError):
                    fixture.fixture_names(value, "1")
                with self.assertRaises(AssertionError):
                    fixture.fixture_names("1", value)
