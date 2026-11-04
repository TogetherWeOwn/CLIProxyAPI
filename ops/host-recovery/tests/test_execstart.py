"""Strict display-projection fixtures, NOT live systemd compatibility evidence."""
from dataclasses import replace
import unittest

from host_recovery import durable, manager
import test_jobs
import test_manager
from test_manager import observed


def completed(raw):
    return raw.replace("start_time=[n/a]", "start_time=[Wed 2026-11-04 06:00:00 UTC]").replace(
        "stop_time=[n/a]", "stop_time=[Wed 2026-11-04 06:00:01 UTC]").replace(
        "pid=0 ; code=(null) ; status=0/0", "pid=789 ; code=exited ; status=0/SUCCESS")


class ExecStartTests(unittest.TestCase):
    def setUp(self):
        self.row = observed()
        self.raw = self.row["ExecStart"]

    def project(self, raw):
        return manager.static_properties({**self.row, "ExecStart": raw})

    def test_telemetry_is_not_part_of_static_command_identity(self):
        self.assertEqual(self.project(self.raw), self.project(completed(self.raw)))
        command = self.project(self.raw)["ExecStart"]
        self.assertEqual(command, {"schema": "host-recovery-execstart-config-v1", "path": "/accepted/helper",
                                  "argv_display": "/accepted/helper", "ignore_errors": "no"})
        self.assertEqual(self.row["ExecStart"], self.raw)

    def test_command_path_argv_and_ignore_errors_all_remain_pinned(self):
        for text in (self.raw.replace("path=/accepted/helper", "path=/changed/helper"),
                     self.raw.replace("argv[]=/accepted/helper", "argv[]=/accepted/helper --changed"),
                     self.raw.replace("ignore_errors=no", "ignore_errors=yes")):
            with self.subTest(text=text):
                self.assertNotEqual(self.project(self.raw), self.project(text))

    def test_displayed_argv_spacing_and_escaping_are_not_normalized(self):
        for suffix in (" --value=x", "  --value=x", r" --value=\x20", " --value='x'"):
            raw = self.raw.replace("argv[]=/accepted/helper", "argv[]=/accepted/helper" + suffix)
            self.assertEqual(self.project(raw)["ExecStart"]["argv_display"], "/accepted/helper" + suffix)

    def test_multiple_commands_and_unknown_suffixes_are_not_stripped(self):
        for text in (self.raw + " " + self.raw, self.raw[:-2] + " ; extra=yes }",
                     self.raw.replace(" ; pid=0", " ; hidden=/changed ; pid=0"), self.raw + "\n",
                     self.raw.replace("argv[]=/accepted/helper", "argv[]=/accepted/helper ; /changed")):
            with self.subTest(text=text), self.assertRaises(durable.Rejected):
                self.project(text)

    def test_partial_old_synthetic_or_future_shapes_refuse(self):
        for text in ("", "{ path=/accepted/helper ; argv[]=/accepted/helper ; }",
                     self.raw.replace(" ; ignore_errors=no", ""), self.raw.replace(" ; stop_time=[n/a]", ""),
                     self.raw.replace("code=(null)", "code=unknown=thing"), self.raw.replace("pid=0", "pid=00"),
                     self.raw.replace("pid=0", "pid=4294967296"), self.raw.replace("status=0/0", "status=-1"),
                     self.raw.replace("[n/a]", "n/a"), "x" * 65537, b"bytes", None):
            with self.subTest(text=str(text)[:80]), self.assertRaises(durable.Rejected):
                self.project(text)

    def test_control_delimiters_or_ambiguous_argv_refuse(self):
        for character in ("\x00", "\n", "\t", "\x7f", ";", "{", "}", "[", "]"):
            for label in ("path=/accepted/helper", "argv[]=/accepted/helper"):
                raw = self.raw.replace(label, label + character + "x")
                with self.subTest(character=character, label=label), self.assertRaises(durable.Rejected):
                    self.project(raw)

    def test_mutator_stop_can_change_telemetry_without_changing_configuration(self):
        case = test_manager.ManagerTests()
        case.setUp()
        after = {**case.stopped, "ExecStart": completed(case.before["ExecStart"])}
        self.assertTrue(case.quiesce(after=after, final=after))

    def test_mutator_old_raw_pin_is_not_silently_reinterpreted(self):
        case = test_manager.ManagerTests()
        case.setUp()
        case.engine.forward = replace(case.forward, properties_sha256=durable.digest(
            durable.canonical({key: case.before[key] for key in manager.STATIC})))
        with self.assertRaises(durable.Rejected):
            case.quiesce()
        self.assertFalse(any("stop" in argv for argv in case.commands.calls))

    def test_job_telemetry_changes_preserve_pin_but_command_changes_refuse(self):
        case = test_jobs.JobTests()
        case.setUp()
        case.row["ExecStart"] = completed(case.row["ExecStart"])
        self.assertEqual(case.observe()["state"], "running")
        case.row["ExecStart"] = case.row["ExecStart"].replace("argv[]=/accepted/helper", "argv[]=/changed")
        with self.assertRaises(durable.Rejected):
            case.observe()

    def test_other_static_settings_still_change_digest(self):
        original = manager.static_properties(self.row)
        for key in manager.STATIC - {"ExecStart"}:
            value = {**self.row, key: self.row[key] + "changed"}
            with self.subTest(key=key):
                self.assertNotEqual(original, manager.static_properties(value))
