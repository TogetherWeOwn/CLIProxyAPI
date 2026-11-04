"""Deterministic component tests. No daemon, unit, live path or provider access."""
import copy
import errno
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from host_recovery import budget, durable, inventory


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="host-recovery-component-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def write(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def scan(self):
        return inventory.snapshot(self.fd, uid=os.geteuid(), gid=os.getegid())

    def mixed_tree(self):
        (self.root / "auths").mkdir(mode=0o700)
        selected = {}
        for i in range(9):
            name = f"auths/selected-{i}.json"
            selected[name] = i < 7
            self.write(name, durable.canonical({"type": "meta", "disabled": i < 7, "opaque": "fixture-only"}))
        self.write("auths/unrelated.json", b'{"type":"other","opaque":"fixture-only"}\n')
        self.write("config.yaml", b"unrelated: preserved\n")
        return selected

    def test_strict_json_rejects_duplicates_and_nonfinite_numbers(self):
        for raw in (b'{"key":1,"key":2}', b'{"value":NaN}', b'{"value":Infinity}', b'{"value":1e999}', b'[]'):
            with self.subTest(raw=raw), self.assertRaises(durable.Rejected):
                durable.decode(raw)

    def test_atomic_write_acknowledges_readback(self):
        pin = durable.atomic_write(self.fd, "intent.json", b"intent\n")
        self.assertEqual(pin, durable.digest(b"intent\n"))
        raw, st = durable.read_file(self.fd, "intent.json")
        self.assertEqual(raw, b"intent\n")
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
        self.assertEqual(os.listdir(self.fd), ["intent.json"])

    def test_fault_at_every_persistence_boundary_never_acknowledges(self):
        for code in (errno.EIO, errno.ENOSPC):
            for stage in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
                with self.subTest(errno=code, stage=stage):
                    def fault(point):
                        if point == stage:
                            raise OSError(code, "injected")
                    with self.assertRaises(OSError):
                        durable.atomic_write(self.fd, "receipt", b"terminal", fault=fault)

    def test_directory_fsync_uncertainty_is_not_success(self):
        def fault(point):
            if point == "directory-fsync":
                raise OSError(errno.EIO, "injected")
        self.write("intent", b"nonterminal")
        with self.assertRaises(OSError):
            durable.atomic_write(self.fd, "terminal", b"verified", fault=fault)
        self.assertEqual((self.root / "terminal").read_bytes(), b"verified")
        self.assertEqual((self.root / "intent").read_bytes(), b"nonterminal")

    def test_real_syscall_failures_propagate(self):
        for operation in ("write", "fsync", "replace"):
            for code in (errno.EIO, errno.ENOSPC):
                with self.subTest(operation=operation, errno=code):
                    with patch.object(durable.os, operation, side_effect=OSError(code, "injected")):
                        with self.assertRaises(OSError):
                            durable.atomic_write(self.fd, "receipt", b"intent")

    def test_directory_fsync_syscall_failure_after_rename(self):
        fsync = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.ENOSPC, "injected")
            return fsync(fd)
        with patch.object(durable.os, "fsync", side_effect=fail_directory):
            with self.assertRaises(OSError):
                durable.atomic_write(self.fd, "receipt", b"intent")
        self.assertTrue((self.root / "receipt").exists())

    def test_partial_writes_are_completed(self):
        write = os.write
        with patch.object(durable.os, "write", side_effect=lambda fd, raw: write(fd, raw[:2])):
            durable.atomic_write(self.fd, "receipt", b"complete-intent")
        self.assertEqual((self.root / "receipt").read_bytes(), b"complete-intent")

    def test_zero_write_is_rejected(self):
        with patch.object(durable.os, "write", return_value=0):
            with self.assertRaises(durable.Rejected):
                durable.atomic_write(self.fd, "receipt", b"intent")

    def test_no_path_traversal_or_symlink_directory(self):
        for name in ("", ".", "..", "../elsewhere", "/absolute", "nul\0name"):
            with self.subTest(name=name), self.assertRaises(durable.Rejected):
                durable.atomic_write(self.fd, name, b"x")
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            with durable.directory(self.root / "link"):
                self.fail("followed symlink")

    def test_single_installation_lock_rejects_contender(self):
        owner = dict(installation_id="fixture", attempt_id="attempt", unit="supervisor.service",
                     invocation_id="invocation", boot_id="boot")
        with durable.installation_lock(self.root, owner) as (_, actual):
            self.assertEqual(actual, owner)
            with self.assertRaises(BlockingIOError):
                with durable.installation_lock(self.root, owner):
                    self.fail("overlapping owner")
        with durable.installation_lock(self.root, owner):
            pass

    def test_owner_requires_manager_invocation(self):
        with self.assertRaises(durable.Rejected):
            with durable.installation_lock(self.root, {"pid": "123"}):
                self.fail("PID is not a manager identity")

    def test_mixed_inventory_is_complete_and_exact_selection_is_separate(self):
        selected = self.mixed_tree()
        tree, blobs = self.scan()
        self.assertEqual(len(tree["entries"]), 13)
        self.assertIn("auths/unrelated.json", tree["entries"])
        self.assertEqual(inventory.selected_auths(tree, blobs, selected), {"selected": 9, "disabled": 7, "enabled": 2})
        inventory.validate_tree(tree, blobs)
        receipt = inventory.receipt(tree)
        self.assertNotIn("selected-", str(receipt))
        self.assertNotIn("unrelated.json", str(receipt))
        self.assertFalse(receipt["production_acceptance"])

    def test_exact_nine_and_strict_seven_two_flags(self):
        selected = self.mixed_tree()
        tree, blobs = self.scan()
        traversing = dict(selected)
        traversing["../escape"] = traversing.pop(next(iter(traversing)))
        wrong = [dict(list(selected.items())[:8]), {**selected, "extra": True},
                 {**selected, next(iter(selected)): 1}, {name: False for name in selected}, traversing]
        for mapping in wrong:
            with self.subTest(mapping=mapping), self.assertRaises(durable.Rejected):
                inventory.selected_auths(tree, blobs, mapping)

    def test_selected_auth_malformed_and_wrong_type_rejected(self):
        selected = self.mixed_tree()
        for raw in (b'{"torn":', b'{"type":"meta","type":"meta","disabled":true}',
                    b'{"type":"meta-muse","disabled":true}', b'{"type":"meta","disabled":1}'):
            with self.subTest(raw=raw):
                self.write(next(iter(selected)), raw)
                tree, blobs = self.scan()
                with self.assertRaises(durable.Rejected):
                    inventory.selected_auths(tree, blobs, selected)

    def test_links_and_special_files_rejected(self):
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                target = self.write("target", b"x")
                path = self.root / "unsafe"
                if kind == "symlink":
                    path.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, path)
                else:
                    os.mkfifo(path, 0o600)
                with self.assertRaises((OSError, durable.Rejected)):
                    self.scan()
                path.unlink()

    def test_unsupported_permissions_and_metadata_rejected(self):
        path = self.write("file", b"x")
        path.chmod(0o666)
        with self.assertRaises(durable.Rejected):
            self.scan()
        path.chmod(0o600)
        with patch.object(inventory.os, "listxattr", return_value=["user.unsupported"]):
            with self.assertRaises(durable.Rejected):
                self.scan()

    def test_concurrent_earlier_sibling_change_rejected(self):
        first = self.write("a", b"initial")
        self.write("z", b"later")
        read = inventory.read_file
        def changing(fd, name):
            if name == "z":
                first.write_bytes(b"modified")
            return read(fd, name)
        with patch.object(inventory, "read_file", side_effect=changing):
            with self.assertRaises(durable.Rejected):
                self.scan()

    def test_restricted_baseline_roundtrip_and_no_overwrite(self):
        self.mixed_tree()
        tree, blobs = self.scan()
        pin = inventory.save_baseline(self.fd, "baseline", tree, blobs)
        with durable.directory(self.root / "baseline", private=True) as fd:
            self.assertEqual(inventory.load_baseline(fd, pin), (tree, blobs))
        with self.assertRaises(FileExistsError):
            inventory.save_baseline(self.fd, "baseline", tree, blobs)

    def test_tampered_partial_and_unexpected_baseline_rejected(self):
        self.write("source", b"original")
        tree, blobs = self.scan()
        pin = inventory.save_baseline(self.fd, "baseline", tree, blobs)
        blob = self.root / "baseline" / next(iter(blobs))
        for action in ("tamper", "missing", "unexpected"):
            with self.subTest(action=action):
                blob.write_bytes(b"original")
                blob.chmod(0o600)
                extra = self.root / "baseline" / "extra"
                if extra.exists():
                    extra.unlink()
                if action == "tamper":
                    blob.write_bytes(b"tampered")
                elif action == "missing":
                    blob.unlink()
                else:
                    extra.write_bytes(b"extra")
                with durable.directory(self.root / "baseline", private=True) as fd:
                    with self.assertRaises(durable.Rejected):
                        inventory.load_baseline(fd, pin)

    def test_malformed_baseline_paths_metadata_and_digests_rejected(self):
        self.write("source", b"original")
        tree, blobs = self.scan()
        for change in (lambda t: t["entries"].update({"../escape": t["entries"]["source"]}),
                       lambda t: t["entries"]["source"].update(uid=True),
                       lambda t: t["entries"]["source"].update(sha256="0" * 64),
                       lambda t: t["entries"].update({".": {"kind": "file"}})):
            bad = copy.deepcopy(tree)
            change(bad)
            with self.assertRaises(durable.Rejected):
                inventory.validate_tree(bad, blobs)


class AlertTests(unittest.TestCase):
    def test_independent_transport_attempted_for_every_disk_fault(self):
        for code in (errno.EIO, errno.ENOSPC):
            delivered = []
            def fail(_):
                raise OSError(code, "injected")
            result = durable.notify({"attempt_id": "fixture"}, fail, lambda notice: delivered.append(notice) or True)
            self.assertEqual(len(delivered), 1)
            self.assertFalse(result["receipt_persisted"])
            self.assertTrue(result["transport_delivered"])
            self.assertFalse(result["human_acknowledged"])

    def test_transport_failure_does_not_claim_delivery(self):
        def fail(_):
            raise OSError(errno.ENOENT, "missing listener")
        result = durable.notify({}, lambda _: None, fail)
        self.assertTrue(result["receipt_persisted"])
        self.assertFalse(result["transport_delivered"])
        self.assertEqual(result["transport_error"], "alert-transport-failed")

    def test_non_receipt_transport_result_is_not_delivery(self):
        for response in (None, False, 1, "sent"):
            with self.subTest(response=response):
                self.assertFalse(durable.notify({}, lambda _: None, lambda _: response)["transport_delivered"])


class BudgetTests(unittest.TestCase):
    def setUp(self):
        # Synthetic values exercise validation, NOT measured/approved phase caps.
        self.policy = {"schema": "host-recovery-budget-v1", "work_seconds": 120,
                       "recovery_seconds": 180, "total_seconds": 300,
                       "measurement_sha256": "a" * 64,
                       "forward": {"caps": dict.fromkeys(budget.FORWARD_PHASES, 10), "safety_margin": 5},
                       "recovery": {"caps": dict.fromkeys(budget.RECOVERY_PHASES, 20), "safety_margin": 5}}
        self.time, self.boot = 1000.0, "boot-a"
        self.meter = budget.Budget(self.policy, {"boot_id": self.boot, "monotonic": self.time},
                                   lambda: self.time, lambda: self.boot)

    def test_explicit_positive_caps_measurement_and_margin_required(self):
        for change in (lambda p: p["forward"]["caps"].pop("stop"),
                       lambda p: p["forward"]["caps"].update(stop=0),
                       lambda p: p["forward"]["caps"].update(stop=True),
                       lambda p: p["forward"]["caps"].update(stop=float("nan")),
                       lambda p: p["recovery"].update(safety_margin=0),
                       lambda p: p["recovery"]["caps"].update(quiescence=180),
                       lambda p: p.update(measurement_sha256=None),
                       lambda p: p.update(total_seconds=900)):
            bad = copy.deepcopy(self.policy)
            change(bad)
            with self.assertRaises(durable.Rejected):
                budget.validate_policy(bad)

    def test_early_recovery_does_not_borrow_unused_work(self):
        self.time = 1010
        self.assertEqual(self.meter.trigger_recovery(1005), 1185)
        self.assertEqual(self.meter.events[-1]["detection_seconds"], 5)
        self.assertEqual(self.meter.phase_deadline("recovery", "detection"), 1025)

    def test_delayed_detection_counts_from_expired_work_deadline(self):
        self.time = 1150
        self.assertEqual(self.meter.trigger_recovery(1149), 1300)
        self.assertEqual(self.meter.events[-1]["detection_seconds"], 30)
        with self.assertRaises(durable.Rejected):
            self.meter.phase_deadline("recovery", "detection")

    def test_recovery_trigger_and_phase_caps_never_reset(self):
        self.time = 1010
        self.meter.trigger_recovery(1005)
        first = self.meter.phase_deadline("recovery", "quiescence")
        self.time = 1015
        self.assertEqual(self.meter.trigger_recovery(1014), 1185)
        self.assertEqual(self.meter.phase_deadline("recovery", "quiescence"), first)
        with self.assertRaises(durable.Rejected):
            self.meter.deadline("forward")

    def test_safety_margin_and_persistence_inside_target(self):
        self.time = 1119
        with self.assertRaises(durable.Rejected):
            self.meter.phase_deadline("forward", "persistence")
        self.meter.trigger_recovery(1119)
        self.time = 1293
        self.assertEqual(self.meter.phase_deadline("recovery", "alert"), 1294)
        self.time = 1294
        with self.assertRaises(durable.Rejected):
            self.meter.check(1294)

    def test_boot_change_and_clock_regression_never_reset_budget(self):
        self.boot = "boot-b"
        self.time = 1
        with self.assertRaisesRegex(durable.Rejected, "clock-discontinuity"):
            self.meter.now()
        self.boot = "boot-a"
        with self.assertRaisesRegex(durable.Rejected, "clock-regressed"):
            self.meter.now()
        self.assertEqual(self.meter.arm["monotonic"], 1000)

    def test_policy_is_not_mutable_after_validation(self):
        self.policy["forward"]["caps"]["stop"] = 119
        self.assertEqual(self.meter.phase_deadline("forward", "stop"), 1010)


if __name__ == "__main__":
    unittest.main(verbosity=2)
