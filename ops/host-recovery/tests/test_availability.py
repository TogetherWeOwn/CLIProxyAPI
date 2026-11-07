"""Raw point-sampling evidence; no full-system recovery or downtime claims."""
import copy
import errno
import http.client
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from host_recovery import availability, durable


class AvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="recovery-availability-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.now, self.boot = 1000.0, "synthetic-boot"

    def recorder(self, fault=None):
        return availability.AvailabilityRecorder(self.fd, attempt_id="synthetic-attempt",
            probe_revision="a" * 64, target_sha256="b" * 64, clock=lambda: self.now,
            boot_id=lambda: self.boot, fault=fault)

    def raw(self):
        return (self.root / availability.NAME).read_bytes()

    def observe(self, recorder, value, start, end):
        self.now = start
        def probe():
            self.now = end
            return value
        return recorder.observe(probe)

    def test_raw_times_and_hash_bound_completion_are_not_downtime(self):
        recorder = self.recorder()
        self.observe(recorder, True, 1001, 1002)
        self.observe(recorder, False, 1004, 1006)
        self.observe(recorder, False, 1007, 1008)
        self.observe(recorder, True, 1010, 1011)
        self.now = 1012
        receipt = recorder.finish()
        self.assertEqual(receipt["trace_sha256"], durable.digest(self.raw()))
        report = availability.summarize(self.raw())
        self.assertEqual(report["counts"], {"available": 2, "unavailable": 2, "unknown": 0})
        self.assertEqual(report["maximum_probe_seconds"], 2)
        self.assertEqual(report["maximum_unsampled_gap_seconds"], 2)
        self.assertTrue(report["sampling_window_closed"])
        self.assertFalse(report["unsampled_tail_unbounded"])
        self.assertIsNone(report["continuous_downtime_seconds"])
        self.assertFalse(report["continuous_coverage_proven"])
        self.assertFalse(report["production_acceptance"])
        run = report["unavailable_sample_runs"][0]
        self.assertEqual((run["first_sequence"], run["last_sequence"]), (2, 3))
        self.assertEqual((run["preceding_available_observation"], run["following_available_observation"]), (1002, 1011))
        self.assertFalse(run["left_censored"])
        self.assertFalse(run["right_censored"])
        # Even bracketed failed samples cannot establish a continuous outage.
        self.assertEqual(run["outage_seconds_lower_bound"], 0)
        self.assertIsNone(run["outage_seconds_upper_bound"])
        self.assertEqual((self.root / availability.NAME).stat().st_mode & 0o777, 0o600)

    def test_right_and_left_censoring_never_become_zero_upper_bounds(self):
        recorder = self.recorder()
        self.observe(recorder, False, 1001, 1002)
        self.observe(recorder, False, 1010, 1011)
        report = availability.summarize(self.raw())
        self.assertTrue(report["unsampled_tail_unbounded"])
        run = report["unavailable_sample_runs"][0]
        self.assertTrue(run["left_censored"])
        self.assertTrue(run["right_censored"])
        self.assertIsNone(run["following_available_observation"])
        self.assertIsNone(run["outage_seconds_upper_bound"])
        recorder.finish()
        self.assertTrue(availability.summarize(self.raw())["unavailable_sample_runs"][0]["right_censored"])

    def test_unknown_breaks_streak_and_does_not_supply_available_brackets(self):
        recorder = self.recorder()
        for i, value in enumerate((True, False, None, False, True)):
            self.observe(recorder, value, 1001 + i * 2, 1002 + i * 2)
        report = availability.summarize(self.raw())
        self.assertEqual(report["counts"]["unknown"], 1)
        first, second = report["unavailable_sample_runs"]
        self.assertTrue(first["right_censored"])
        self.assertIsNone(first["following_available_observation"])
        self.assertTrue(second["left_censored"])
        self.assertIsNone(second["preceding_available_observation"])
        self.assertFalse(second["right_censored"])

    def test_empty_and_all_green_traces_do_not_prove_zero_downtime(self):
        recorder = self.recorder()
        for raw in (self.raw(),):
            report = availability.summarize(raw)
            self.assertIsNone(report["continuous_downtime_seconds"])
            self.assertEqual(report["counts"]["available"], 0)
            self.assertIsNone(report["maximum_probe_seconds"])
        self.observe(recorder, True, 1001, 1002)
        recorder.finish()
        report = availability.summarize(self.raw())
        self.assertEqual(report["unavailable_sample_runs"], [])
        self.assertIsNone(report["continuous_downtime_seconds"])
        self.assertFalse(report["continuous_coverage_proven"])

    def test_exceptions_and_truthy_return_payloads_are_unknown_and_secret_free(self):
        recorder = self.recorder()
        def failure():
            raise RuntimeError("restricted-probe-exception")
        recorder.observe(failure)
        for value in (1, 0, "restricted-probe-result", {"token": "restricted-probe-result"}, object()):
            recorder.observe(lambda: value)
        self.assertEqual(availability.summarize(self.raw())["counts"]["unknown"], 6)
        self.assertNotIn(b"restricted", self.raw())
        self.assertNotIn(b"token", self.raw())

    def test_clock_and_boot_discontinuity_revoke_without_a_new_epoch(self):
        for value in (999, True, 0, float("nan"), float("inf"), "1001"):
            with self.subTest(value=value), tempfile.TemporaryDirectory(dir=self.root) as path:
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    recorder = availability.AvailabilityRecorder(fd, attempt_id="attempt", probe_revision="a" * 64,
                        target_sha256="b" * 64, clock=lambda: self.now, boot_id=lambda: self.boot)
                    self.now = value
                    with self.assertRaises(durable.Rejected):
                        recorder.observe(lambda: True)
                    self.now = 1000
                    with self.assertRaises(durable.Rejected):
                        recorder.finish()
                    self.assertTrue(recorder.failed)
                finally:
                    os.close(fd)
        recorder = self.recorder()
        self.boot = "replacement-boot"
        with self.assertRaises(durable.Rejected):
            recorder.observe(lambda: True)
        self.assertIsNone(durable.decode(self.raw())["window_end"])

    def test_callback_cannot_mutate_saved_or_in_memory_samples(self):
        for destination in ("memory", "disk"):
            with self.subTest(destination=destination), tempfile.TemporaryDirectory(dir=self.root) as path:
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    recorder = availability.AvailabilityRecorder(fd, attempt_id="attempt", probe_revision="a" * 64,
                        target_sha256="b" * 64, clock=lambda: self.now, boot_id=lambda: self.boot)
                    recorder.observe(lambda: False)
                    def change():
                        if destination == "memory":
                            recorder.value["samples"][0]["outcome"] = "available"
                        else:
                            value = durable.decode(Path(path, availability.NAME).read_bytes())
                            value["samples"][0]["outcome"] = "available"
                            Path(path, availability.NAME).write_bytes(durable.canonical(value))
                        return True
                    with self.assertRaises(durable.Rejected):
                        recorder.observe(change)
                    self.assertTrue(recorder.failed)
                    with self.assertRaises(durable.Rejected):
                        recorder.finish()
                finally:
                    os.close(fd)

    def test_late_clock_callback_cannot_overwrite_changed_trace_at_finish(self):
        recorder = self.recorder()
        def change():
            (self.root / availability.NAME).write_bytes(b"restricted-changed-evidence")
            return self.now
        recorder.clock = change
        with self.assertRaises(durable.Rejected):
            recorder.finish()
        self.assertEqual(self.raw(), b"restricted-changed-evidence")
        self.assertTrue(recorder.failed)

    def test_reentrancy_invalidates_outer_probe_even_when_callback_swallows_error(self):
        for operation in ("observe", "finish"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(dir=self.root) as path:
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    recorder = availability.AvailabilityRecorder(fd, attempt_id="attempt", probe_revision="a" * 64,
                        target_sha256="b" * 64, clock=lambda: self.now, boot_id=lambda: self.boot)
                    def reenter():
                        try:
                            recorder.finish() if operation == "finish" else recorder.observe(lambda: True)
                        except durable.Rejected:
                            pass
                        return True
                    with self.assertRaises(durable.Rejected):
                        recorder.observe(reenter)
                    self.assertEqual(durable.decode(Path(path, availability.NAME).read_bytes())["samples"], [])
                finally:
                    os.close(fd)

    def test_sample_limit_and_completed_instance_never_reopen_or_reset(self):
        recorder = self.recorder()
        with patch.object(availability, "MAX_SAMPLES", 1):
            recorder.observe(lambda: False)
            with self.assertRaises(durable.Rejected):
                recorder.observe(lambda: True)
        with self.assertRaises(durable.Rejected):
            recorder.finish()
        with self.assertRaises(durable.Rejected):
            self.recorder()

    def test_finished_instance_is_once_only_and_return_values_are_copies(self):
        recorder = self.recorder()
        sample = recorder.observe(lambda: False)
        sample["outcome"] = "available"
        self.assertEqual(durable.decode(self.raw())["samples"][0]["outcome"], "unavailable")
        recorder.finish()
        for action in (recorder.finish, lambda: recorder.observe(lambda: True)):
            with self.assertRaises(durable.Rejected):
                action()

    def test_foreign_entries_permissions_and_reused_directory_refuse(self):
        (self.root / "existing").write_bytes(b"do-not-overwrite")
        with self.assertRaises(durable.Rejected):
            self.recorder()
        self.assertEqual((self.root / "existing").read_bytes(), b"do-not-overwrite")
        for mode in (0o755, 0o770):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=self.root) as path:
                os.chmod(path, mode)
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(durable.Rejected):
                        availability.AvailabilityRecorder(fd, attempt_id="attempt", probe_revision="a" * 64,
                            target_sha256="b" * 64, clock=lambda: self.now, boot_id=lambda: self.boot)
                finally:
                    os.close(fd)

    def test_every_reached_persistence_fault_revokes_completion(self):
        reached = []
        for operation in ("begin", "observe", "finish"):
            for code in (errno.EIO, errno.ENOSPC):
                for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                    with self.subTest(operation=operation, code=code, point=point), tempfile.TemporaryDirectory(dir=self.root) as path:
                        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                        hits = []
                        def fail(stage):
                            if stage == point:
                                hits.append(stage)
                                raise OSError(code, "restricted-storage-error")
                        try:
                            def begin(fault=None):
                                return availability.AvailabilityRecorder(fd, attempt_id="attempt", probe_revision="a" * 64,
                                    target_sha256="b" * 64, clock=lambda: self.now, boot_id=lambda: self.boot, fault=fault)
                            if operation == "begin":
                                with self.assertRaises(OSError):
                                    begin(fail)
                            else:
                                recorder = begin()
                                recorder.fault = fail
                                with self.assertRaises(OSError):
                                    recorder.observe(lambda: True) if operation == "observe" else recorder.finish()
                                self.assertTrue(recorder.failed)
                                recorder.fault = None
                                with self.assertRaises(durable.Rejected):
                                    recorder.finish()
                            self.assertEqual(hits, [point])
                            reached.append({"operation": operation, "errno": code, "point": point})
                        finally:
                            os.close(fd)
        self.assertEqual(len(reached), 36)
        print(durable.canonical({"schema": "availability-storage-fault-tests-v1", "reached": reached,
                                 "full_system_recovery": False}).decode(), end="", flush=True)

    def test_boot_change_during_final_fsync_cannot_issue_completion_receipt(self):
        recorder = self.recorder()
        hits = []
        def changed(stage):
            if stage == "directory-fsync":
                hits.append(stage)
                self.boot = "replacement-boot"
        recorder.fault = changed
        with self.assertRaises(durable.Rejected):
            recorder.finish()
        self.assertEqual(hits, ["directory-fsync"])
        self.assertTrue(recorder.failed)
        with self.assertRaises(durable.Rejected):
            recorder.finish()

    def test_sigkill_mid_probe_retains_open_trace_without_invented_result(self):
        program = '''
import os,signal,sys,time
sys.path.insert(0,sys.argv[1])
from host_recovery.availability import AvailabilityRecorder
fd=os.open(sys.argv[2],os.O_RDONLY|os.O_DIRECTORY)
r=AvailabilityRecorder(fd,attempt_id="synthetic-kill-attempt",probe_revision="a"*64,
    target_sha256="b"*64,clock=time.monotonic,boot_id=lambda:"synthetic-boot")
r.observe(lambda:False)
def pending():
    print("probe-entered",flush=True)
    signal.pause()
r.observe(pending)
'''
        child = subprocess.Popen([sys.executable, "-I", "-c", program,
            str(Path(__file__).resolve().parents[1]), str(self.root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as wait:
                wait.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(wait.select(10), "child did not enter pending probe")
                self.assertEqual(child.stdout.readline(), b"probe-entered\n")
            child.send_signal(signal.SIGKILL)
            _, stderr = child.communicate(timeout=10)
            self.assertEqual(child.returncode, -signal.SIGKILL, stderr.decode())
            report = availability.summarize(self.raw())
            self.assertEqual(report["counts"], {"available": 0, "unavailable": 1, "unknown": 0})
            self.assertFalse(report["sampling_window_closed"])
            self.assertTrue(report["unsampled_tail_unbounded"])
            self.assertIsNone(report["unavailable_sample_runs"][0]["outage_seconds_upper_bound"])
            print(durable.canonical({"schema": "availability-sigkill-test-v1", "exit": child.returncode,
                "trace": durable.decode(self.raw()), "summary": report, "recovery_drill": False}).decode(), end="", flush=True)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)

    def test_strict_parser_rejects_ambiguous_and_reordered_samples(self):
        recorder = self.recorder()
        recorder.observe(lambda: False)
        original = durable.decode(self.raw())
        variants = []
        for key, value in (("window_start", True), ("window_end", 999), ("production_acceptance", True),
                           ("probe_revision", "bad"), ("boot_id", ""), ("samples", {})):
            changed = copy.deepcopy(original)
            changed[key] = value
            variants.append(changed)
        for key, value in (("start", 999), ("end", 999), ("sequence", True), ("sequence", 2),
                           ("outcome", "01"), ("outcome", 1), ("extra", True)):
            changed = copy.deepcopy(original)
            changed["samples"][0][key] = value
            variants.append(changed)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(durable.Rejected):
                availability.summarize(durable.canonical(value))
        for raw in (b'{"schema":1,"schema":2}', b'{"window_start":NaN}', b'[]'):
            with self.subTest(raw=raw), self.assertRaises(durable.Rejected):
                availability.summarize(raw)

    def test_actual_disposable_http_samples_with_no_live_or_credential_access(self):
        program = '''
from http.server import BaseHTTPRequestHandler,HTTPServer
class Handler(BaseHTTPRequestHandler):
    count=0
    def do_GET(self):
        Handler.count+=1
        self.send_response(503 if Handler.count==2 else 200)
        self.send_header("Content-Length","0")
        self.end_headers()
    def log_message(self,*args): pass
server=HTTPServer(("127.0.0.1",0),Handler)
print(server.server_port,flush=True)
for _ in range(3): server.handle_request()
server.server_close()
'''
        child = subprocess.Popen([sys.executable, "-I", "-c", program], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as wait:
                wait.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(wait.select(10), "disposable HTTP listener did not become ready")
                port = int(child.stdout.readline())
            import time
            self.now = time.monotonic()
            recorder = availability.AvailabilityRecorder(self.fd, attempt_id="synthetic-http-attempt", probe_revision="a" * 64,
                target_sha256=durable.digest(b"disposable-child-http-only"), clock=time.monotonic, boot_id=lambda: self.boot)
            def probe():
                connection = http.client.HTTPConnection("127.0.0.1", port)
                try:
                    connection.request("GET", "/synthetic-only")
                    response = connection.getresponse()
                    response.read()
                    return response.status == 200
                finally:
                    connection.close()
            for _ in range(3):
                recorder.observe(probe)
            receipt = recorder.finish()
            _, stderr = child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, stderr.decode())
            report = availability.summarize(self.raw())
            self.assertEqual(report["counts"], {"available": 2, "unavailable": 1, "unknown": 0})
            self.assertIsNone(report["continuous_downtime_seconds"])
            print(durable.canonical({"schema": "availability-disposable-http-test-v1", "trace": durable.decode(self.raw()),
                "receipt": receipt, "summary": report, "recovery_drill": False}).decode(), end="", flush=True)
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGKILL)
                child.communicate(timeout=10)
