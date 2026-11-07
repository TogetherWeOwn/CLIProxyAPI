"""Synthetic owned-tree/journal loading; no installed service or daemon proof."""
import copy
from dataclasses import replace
import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from host_recovery import durable, jobs, loading, supervisor, worker_bootstrap
from test_recovery_state import intent
from test_supervisor import ScriptedManager


class RootTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="recovery-loading-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def write(self, name, raw, mode=0o600):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(mode)
        return path


class ContentTests(RootTests):
    def setUp(self):
        super().setUp()
        self.write("runtime/worker.py", b"raise RuntimeError('must-not-execute')\n", 0o500)
        self.write("runtime/settings.json", b'{"synthetic":true}\n')
        self.index = {"schema": "host-recovery-content-v1", "source_revision": "a" * 40,
            "files": [{"path": path, "sha256": durable.digest((self.root / path).read_bytes()), "mode": mode}
                      for path, mode in (("runtime/worker.py", 0o500), ("runtime/settings.json", 0o600))]}
        self.sign()

    def sign(self, raw=None):
        raw = durable.canonical(self.index) if raw is None else raw
        self.write(loading.INDEX, raw)
        self.approval = loading.ContentApproval(durable.digest(raw), "a" * 40, os.geteuid(), os.getegid())

    def load(self):
        return loading.load_content(self.fd, self.approval)

    def test_exact_snapshot_is_readonly_bytes_and_never_executes(self):
        value = self.load()
        self.assertEqual(value.json("runtime/settings.json"), {"synthetic": True})
        self.assertEqual(value.files["runtime/worker.py"], b"raise RuntimeError('must-not-execute')\n")
        with self.assertRaises(TypeError):
            value.files["runtime/worker.py"] = b"changed"
        self.write("runtime/settings.json", b"replacement")
        self.assertEqual(value.json("runtime/settings.json"), {"synthetic": True})
        with self.assertRaises(durable.Rejected):
            self.load()

    def test_discovered_index_cannot_replace_external_approval(self):
        self.index["source_revision"] = "b" * 40
        self.write(loading.INDEX, durable.canonical(self.index))
        with self.assertRaisesRegex(durable.Rejected, "index-pin"):
            self.load()

    def test_revision_has_to_agree_even_with_matching_index_digest(self):
        self.index["source_revision"] = "b" * 40
        self.sign()
        with self.assertRaisesRegex(durable.Rejected, "content-schema"):
            self.load()

    def test_extra_file_or_empty_directory_refuses(self):
        for name, directory in (("unexpected", False), ("empty", True)):
            with self.subTest(name=name):
                path = self.root / name
                if directory:
                    path.mkdir(mode=0o700)
                else:
                    self.write(name, b"extra")
                with self.assertRaises(durable.Rejected):
                    self.load()
                path.rmdir() if directory else path.unlink()

    def test_missing_file_refuses(self):
        (self.root / "runtime/settings.json").unlink()
        with self.assertRaises(durable.Rejected):
            self.load()

    def test_mismatched_bytes_and_mode_refuse(self):
        for raw, mode in ((b"different", 0o600), (b'{"synthetic":true}\n', 0o644)):
            with self.subTest(mode=mode):
                self.write("runtime/settings.json", raw, mode)
                with self.assertRaises(durable.Rejected):
                    self.load()

    def test_unsafe_or_duplicate_index_paths_refuse(self):
        original = copy.deepcopy(self.index)
        for path in ("../escape", "/absolute", "runtime//file", "runtime/./file", "runtime/../file",
                     "x\x00y", "runtime/\\file", "runtime/worker.py", loading.INDEX, "a/" * 9 + "x"):
            self.index = copy.deepcopy(original)
            self.index["files"].append({"path": path, "sha256": "b" * 64, "mode": 0o600})
            self.sign()
            with self.subTest(path=path), self.assertRaises(durable.Rejected):
                self.load()

    def test_unknown_missing_fields_or_bad_mode_refuse(self):
        original = copy.deepcopy(self.index)
        for change in (lambda x: x.update(extra=True), lambda x: x.pop("schema"),
                       lambda x: x.update(files=[]), lambda x: x["files"][0].update(extra=True),
                       lambda x: x["files"][0].update(mode=True), lambda x: x["files"][0].update(mode=0o777),
                       lambda x: x["files"][0].update(sha256="G" * 64)):
            self.index = copy.deepcopy(original)
            change(self.index)
            self.sign()
            with self.subTest(change=change), self.assertRaises(durable.Rejected):
                self.load()

    def test_duplicate_json_nonfinite_or_nonobject_refuse(self):
        for raw in (b'{"schema":1,"schema":2}', b'{"x":NaN}', b'[]', b'{"x":1e999}'):
            self.sign(raw)
            with self.subTest(raw=raw), self.assertRaises(durable.Rejected):
                self.load()

    def test_symlink_hardlink_and_fifo_refuse_without_follow_or_block(self):
        for kind in ("symlink", "hardlink", "fifo"):
            path = self.root / "unexpected"
            if kind == "symlink":
                path.symlink_to("runtime/worker.py")
            elif kind == "hardlink":
                os.link(self.root / "runtime/worker.py", path)
            else:
                os.mkfifo(path, 0o600)
            with self.subTest(kind=kind), self.assertRaises(durable.Rejected):
                self.load()
            path.unlink()

    def test_nested_symlink_directory_refuses(self):
        path = self.root / "linked"
        path.symlink_to("runtime", target_is_directory=True)
        with self.assertRaises(durable.Rejected):
            self.load()

    def test_owner_mismatch_refuses_without_chown(self):
        self.approval = replace(self.approval, uid=os.geteuid() + 1)
        with self.assertRaises(durable.Rejected):
            self.load()

    def test_writable_or_special_permission_entries_refuse(self):
        for name, mode in (("runtime", 0o777), ("runtime/settings.json", 0o666),
                           ("runtime/worker.py", 0o4500)):
            path = self.root / name
            previous = path.stat().st_mode & 0o7777
            path.chmod(mode)
            with self.subTest(name=name), self.assertRaises(durable.Rejected):
                self.load()
            path.chmod(previous)

    def test_extended_metadata_refuses(self):
        path = self.root / "runtime/settings.json"
        os.setxattr(path, "user.loading-test", b"unsupported")
        with self.assertRaises(durable.Rejected):
            self.load()

    def test_entry_and_total_byte_bounds_refuse(self):
        with patch.object(loading, "MAX_ENTRIES", 3), self.assertRaises(durable.Rejected):
            self.load()
        with patch.object(loading, "MAX_TOTAL_BYTES", 10), self.assertRaises(durable.Rejected):
            self.load()

    def test_per_file_bound_refuses(self):
        raw = b"x" * (durable.MAX_FILE_BYTES + 1)
        self.write("runtime/settings.json", raw)
        self.index["files"][1]["sha256"] = durable.digest(raw)
        self.sign()
        with self.assertRaisesRegex(durable.Rejected, "file-size-limit"):
            self.load()

    def test_change_to_already_read_file_is_detected_by_final_rewalk(self):
        actual = loading.read_relative
        def changed(fd, path):
            result = actual(fd, path)
            if path == "runtime/settings.json":
                (self.root / "runtime/worker.py").chmod(0o700)
                self.write("runtime/worker.py", b"changed after its read", 0o500)
            return result
        with patch.object(loading, "read_relative", side_effect=changed):
            with self.assertRaisesRegex(durable.Rejected, "content-changed"):
                self.load()

    def test_replaced_directory_is_detected(self):
        actual = loading.read_relative
        def changed(fd, path):
            result = actual(fd, path)
            if path == "runtime/settings.json":
                (self.root / "runtime").rename(self.root / "moved")
                (self.root / "runtime").mkdir(mode=0o700)
            return result
        with patch.object(loading, "read_relative", side_effect=changed):
            with self.assertRaises(durable.Rejected):
                self.load()

    def test_read_failure_produces_no_snapshot(self):
        for code in (errno.EIO, errno.EACCES, errno.ENOSPC):
            with patch.object(loading, "read_relative", side_effect=OSError(code, "synthetic")):
                with self.subTest(code=code), self.assertRaises(OSError):
                    self.load()

    def test_invalid_external_approval_refuses(self):
        for args in (("x", "a" * 40, 1000, 1000), ("a" * 64, "main", 1000, 1000),
                     ("a" * 64, "a" * 40, True, 1000)):
            with self.subTest(args=args), self.assertRaises(durable.Rejected):
                loading.ContentApproval(*args)
        with self.assertRaises(durable.Rejected):
            loading.load_content(self.fd, {})


class RecoveryTests(RootTests):
    def setUp(self):
        super().setUp()
        self.value = intent()
        self.value["owner"].update(invocation_id="a" * 32)
        self.intent_pin = durable.digest(durable.canonical(self.value))
        self.approval = loading.RecoveryApproval(self.intent_pin, self.value["package_sha256"],
            self.value["manifest_sha256"], self.value["baseline_sha256"], self.value["policy_sha256"],
            self.value["installation_id"], self.value["attempt_id"], os.geteuid(), os.getegid())
        self.arm = {"schema": "host-recovery-arm-v1", "arm": {"boot_id": "boot-a", "monotonic": 1000.0},
                    "intent_sha256": self.intent_pin}
        self.supervisor_owner = {**self.value["owner"], "invocation_id": "b" * 32}
        self.request = {"schema": "host-recovery-reconcile-request-v1", "attempt_id": self.value["attempt_id"],
            "intent_sha256": self.intent_pin, "owner": self.supervisor_owner.copy(), "original_arm": self.arm["arm"].copy(),
            "failure_lower_bound": 1000.0, "deadline": 1180.0, "detection_upper_bound_seconds": 50.0,
            "forward_allowed": False, "production_acceptance": False}
        self.now, self.boot = 1050.0, "boot-a"
        self.save()

    def save(self):
        self.request.pop("request_id", None)
        self.request["request_id"] = durable.digest(durable.canonical(self.request))
        self.binding = jobs.RecoveryJobBinding(self.request["request_id"], "/synthetic/recovery.service", "c" * 64, "d" * 64)
        self.write("intent.json", durable.canonical(self.value))
        self.write("arm.json", durable.canonical(self.arm))
        self.write("reconcile-request.json", durable.canonical(self.request))

    def load(self):
        return loading.load_recovery(self.fd, approval=self.approval, binding=self.binding,
            supervisor_owner=self.supervisor_owner, boot_id=self.boot, now=self.now)

    def test_exact_original_pins_and_restarted_supervisor_load_without_grant(self):
        loaded = self.load()
        self.assertEqual(loaded.intent, self.value)
        self.assertEqual(loaded.request, self.request)
        self.assertNotEqual(loaded.request["owner"]["invocation_id"], loaded.intent["owner"]["invocation_id"])
        self.assertNotIn("start_permission", loaded.request)
        changed = loaded.request
        changed["deadline"] = 99999
        self.assertEqual(loaded.request["deadline"], 1180.0)
        self.assertTrue((self.root / "intent.json").exists())

    def test_actual_supervisor_durable_request_loads_inside_retained_lock(self):
        (self.root / "reconcile-request.json").unlink()
        manager = ScriptedManager()
        loaded = []
        def receive(request):
            binding = replace(self.binding, request_id=request["request_id"])
            value = loading.load_recovery(self.fd, approval=self.approval, binding=binding,
                supervisor_owner=self.supervisor_owner, boot_id=self.boot, now=self.now)
            self.assertEqual(value.request, request)
            self.assertEqual(value.intent, self.value)
            loaded.append(value)
        manager.on_enqueue = receive
        with supervisor.recovery_owner(str(self.root), owner=self.supervisor_owner, manager=manager,
                clock=lambda: self.now, boot_id=lambda: self.boot,
                persist_alert=lambda _: None, transport_alert=lambda _: True) as process:
            result = process.reconcile(deadline=1100.0)
            self.assertEqual(result["state"], "recovery_enqueued")
            self.assertFalse(result["start_permission"])
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].request["deadline"], 1100.0)

    def test_each_independent_approval_pin_and_identity_is_required(self):
        original = self.approval
        for key in ("intent_sha256", "package_sha256", "manifest_sha256", "baseline_sha256", "policy_sha256",
                    "installation_id", "attempt_id"):
            self.approval = replace(original, **{key: "e" * 64 if key.endswith("sha256") else "foreign"})
            with self.subTest(key=key), self.assertRaises(durable.Rejected):
                self.load()

    def test_self_consistent_replacement_intent_does_not_supply_approval(self):
        self.value["baseline_sha256"] = "f" * 64
        self.request["intent_sha256"] = self.arm["intent_sha256"] = durable.digest(durable.canonical(self.value))
        self.save()
        with self.assertRaisesRegex(durable.Rejected, "intent-pin"):
            self.load()

    def test_independent_current_supervisor_must_match_request_not_old_intent(self):
        self.supervisor_owner["invocation_id"] = "c" * 32
        with self.assertRaisesRegex(durable.Rejected, "request-unbound"):
            self.load()

    def test_resigned_request_cannot_change_attempt_installation_arm_or_intent(self):
        original = copy.deepcopy(self.request)
        for change in (lambda x: x.update(intent_sha256="f" * 64),
                       lambda x: x["owner"].update(installation_id="other"),
                       lambda x: x.update(attempt_id="other"),
                       lambda x: x["original_arm"].update(monotonic=999.0)):
            self.request = copy.deepcopy(original)
            change(self.request)
            self.save()
            with self.subTest(change=change), self.assertRaises(durable.Rejected):
                self.load()

    def test_modified_arm_schema_pin_or_value_refuses(self):
        original = copy.deepcopy(self.arm)
        for change in (lambda x: x.update(schema="unknown"), lambda x: x.update(extra=True),
                       lambda x: x.update(intent_sha256="f" * 64), lambda x: x["arm"].update(monotonic=999.0)):
            self.arm = copy.deepcopy(original)
            change(self.arm)
            self.save()
            with self.subTest(change=change), self.assertRaises(durable.Rejected):
                self.load()

    def test_expired_cross_boot_or_regressed_clock_never_gets_new_budget(self):
        for now, boot in ((1180.0, "boot-a"), (999.0, "boot-a"), (1050.0, "boot-b")):
            self.now, self.boot = now, boot
            with self.subTest(now=now, boot=boot), self.assertRaises(durable.Rejected):
                self.load()

    def test_resigned_request_cannot_extend_original_reserve(self):
        self.request["deadline"] = 1181.0
        self.save()
        with self.assertRaises(durable.Rejected):
            self.load()

    def test_private_owner_mode_and_root_required(self):
        self.approval = replace(self.approval, gid=os.getegid() + 1)
        with self.assertRaises(durable.Rejected):
            self.load()
        self.approval = replace(self.approval, gid=os.getegid())
        self.root.chmod(0o755)
        with self.assertRaises(durable.Rejected):
            self.load()
        self.root.chmod(0o700)
        (self.root / "intent.json").chmod(0o644)
        with self.assertRaises(durable.Rejected):
            self.load()

    def test_missing_linked_or_partial_records_refuse(self):
        path = self.root / "arm.json"
        path.unlink()
        with self.assertRaises(OSError):
            self.load()
        path.symlink_to("intent.json")
        with self.assertRaises(OSError):
            self.load()
        path.unlink()
        self.write("arm.json", b'{"schema":')
        with self.assertRaises(durable.Rejected):
            self.load()

    def test_stage_record_refuses_even_with_complete_matching_records(self):
        for name in (".stage-reconcile-request.json", ".stage-arm.json", ".recovery-stage-uncertain"):
            path = self.write(name, b"uncertain")
            with self.subTest(name=name), self.assertRaisesRegex(durable.Rejected, "staging"):
                self.load()
            path.unlink()

    def test_terminal_file_cannot_replace_missing_original_request(self):
        self.write("outcome.json", b'{"outcome":"candidate_verified"}')
        (self.root / "reconcile-request.json").unlink()
        with self.assertRaises(OSError):
            self.load()

    def test_changed_prior_record_during_readback_refuses(self):
        actual = loading.read_file
        count = 0
        def changed(fd, name, *args, **kwargs):
            nonlocal count
            value = actual(fd, name, *args, **kwargs)
            count += 1
            if count == 3:
                self.write("intent.json", b"changed after first read")
            return value
        with patch.object(loading, "read_file", side_effect=changed):
            with self.assertRaises(durable.Rejected):
                self.load()

    def test_read_fault_produces_no_inputs(self):
        for code in (errno.EIO, errno.ENOSPC):
            with patch.object(loading, "read_file", side_effect=OSError(code, "synthetic")):
                with self.subTest(code=code), self.assertRaises(OSError):
                    self.load()

    def test_journal_factory_passes_only_loaded_original_inputs_to_identity_client(self):
        with patch.object(worker_bootstrap.SystemdWorkerBootstrap, "__init__", return_value=None) as init:
            worker_bootstrap.SystemdWorkerBootstrap.from_journal(self.fd, approval=self.approval,
                supervisor_owner=self.supervisor_owner, systemctl="/synthetic/systemctl", commands=object(),
                supervisor_binding=object(), worker_binding=self.binding, clock=lambda: self.now, boot_id=lambda: self.boot)
        self.assertEqual(init.call_args.kwargs["request"], self.request)
        self.assertEqual(init.call_args.kwargs["intent_sha256"], self.intent_pin)
        self.assertEqual(init.call_args.kwargs["installation_id"], self.value["installation_id"])
        self.assertEqual(init.call_args.kwargs["attempt_id"], self.value["attempt_id"])

    def test_bad_journal_never_constructs_worker_client(self):
        self.write("arm.json", b"broken")
        with patch.object(worker_bootstrap.SystemdWorkerBootstrap, "__init__", return_value=None) as init:
            with self.assertRaises(durable.Rejected):
                worker_bootstrap.SystemdWorkerBootstrap.from_journal(self.fd, approval=self.approval,
                    supervisor_owner=self.supervisor_owner, systemctl="/synthetic/systemctl", commands=object(),
                    supervisor_binding=object(), worker_binding=self.binding, clock=lambda: self.now, boot_id=lambda: self.boot)
        init.assert_not_called()
