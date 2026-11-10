"""Help-identity controls. These verify candidate identification only."""

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("help_identity", ROOT / "help_identity.py")
help_identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(help_identity)


def make_help(version="v8.0.60", commit="91e0dee", usage=True, config=True, tui=True):
    parts = ["CLIProxyAPI Version: %s, Commit: %s\n" % (version, commit)]
    if usage:
        parts.append("Usage of /CLIProxyAPI\n")
    if config:
        parts.append("  -config string\n")
    if tui:
        parts.append("  -tui\n")
    return "".join(parts).encode("utf-8")


class HelpIdentityTests(unittest.TestCase):
    def test_frozen_candidate_help_passes(self):
        result = help_identity.verify_help_output(make_help())
        self.assertIn("help_sha256", result)
        self.assertEqual(
            result["markers"],
            ["commit", "config flag", "tui flag", "usage", "version"],
        )

    def test_empty_output_fails_closed(self):
        with self.assertRaisesRegex(help_identity.HelpIdentityError, "size out of bounds"):
            help_identity.verify_help_output(b"")

    def test_oversized_output_fails_closed(self):
        with self.assertRaisesRegex(help_identity.HelpIdentityError, "size out of bounds"):
            help_identity.verify_help_output(make_help() + b"x" * 65536)

    def test_non_bytes_input_fails_closed(self):
        with self.assertRaisesRegex(help_identity.HelpIdentityError, "must be bytes"):
            help_identity.verify_help_output("CLIProxyAPI Version: v8.0.60")

    def test_non_utf8_output_fails_closed(self):
        with self.assertRaisesRegex(help_identity.HelpIdentityError, "UTF-8"):
            help_identity.verify_help_output(make_help() + b"\xff\xfe")

    def test_wrong_version_fails_closed(self):
        with self.assertRaisesRegex(help_identity.HelpIdentityError, "version marker"):
            help_identity.verify_help_output(make_help(version="v8.0.59"))

    def test_wrong_commit_fails_closed(self):
        with self.assertRaisesRegex(help_identity.HelpIdentityError, "commit marker"):
            help_identity.verify_help_output(make_help(commit="deadbee"))

    def test_missing_usage_fails_closed(self):
        with self.assertRaisesRegex(help_identity.HelpIdentityError, "usage marker"):
            help_identity.verify_help_output(make_help(usage=False))

    def test_missing_config_flag_fails_closed(self):
        with self.assertRaisesRegex(help_identity.HelpIdentityError, "config flag marker"):
            help_identity.verify_help_output(make_help(config=False))

    def test_missing_tui_flag_fails_closed(self):
        with self.assertRaisesRegex(help_identity.HelpIdentityError, "tui flag marker"):
            help_identity.verify_help_output(make_help(tui=False))

    def test_exit_code_only_output_fails_closed(self):
        # An error string with no candidate identity must never pass.
        with self.assertRaises(help_identity.HelpIdentityError):
            help_identity.verify_help_output(b"chroot: failed to run command")


if __name__ == "__main__":
    unittest.main()
