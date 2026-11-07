"""Fixture placement only; no production path-validation exemption."""
import os
import pwd
import unittest
from unittest.mock import patch

from fixture_home import fixture_home


class FixtureHomeTests(unittest.TestCase):
    def test_default_is_account_home_not_environment_home(self):
        with patch.dict(os.environ, {"HOME": "/untrusted"}, clear=True):
            self.assertEqual(fixture_home(), pwd.getpwuid(os.geteuid()).pw_dir)

    def test_explicit_absolute_root_is_used_without_mutation(self):
        with patch.dict(os.environ, {"CPA_RECOVERY_TEST_ROOT": "/synthetic-fixtures"}):
            with patch.object(os, "chmod", side_effect=AssertionError("no metadata changes")):
                self.assertEqual(fixture_home(), "/synthetic-fixtures")

    def test_invalid_explicit_root_does_not_fall_back(self):
        for value in ("", "relative"):
            with self.subTest(value=value), patch.dict(os.environ, {"CPA_RECOVERY_TEST_ROOT": value}):
                with self.assertRaisesRegex(ValueError, "absolute component fixture root required"):
                    fixture_home()
