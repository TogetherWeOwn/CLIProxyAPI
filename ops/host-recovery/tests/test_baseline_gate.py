"""Actual restored files/built helper; scripted manager, fence, daemon and oracle."""
from dataclasses import replace
import copy
import errno
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from host_recovery import baseline_gate, coordinator, durable, input_gate, inventory, journal, write_set
import test_input_gate
import test_write_set

IMAGE = "synthetic.example/proxy@sha256:" + "a" * 64
CONFIG = b"meta: {reasoning-replay: {enabled: true}}\n"
# Hash of the strict parser's typed representation, not a hash of YAML text.
REPLAY = durable.digest(durable.canonical({"kind": "map", "mapping": {
    "enabled": {"kind": "!!bool", "scalar": "true"}}}).rstrip(b"\n"))


class BaselineGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="baseline-input-guard-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / "baselineguard"
        result = subprocess.run(("go", "build", "-o", str(cls.binary),
                                 "./ops/host-recovery/inputguard/baselinecmd"),
                                cwd=test_input_gate.ROOT, capture_output=True, timeout=180)
        if result.returncode:
            raise RuntimeError("repository helper build failed: " + result.stderr.decode(errors="replace"))

    def setUp(self):
        self.fx = test_write_set.WriteSetTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.roles = {role: ("config", name) for role, name in (
            ("config", "config.yaml"), ("compose_source", "compose.yaml"),
            ("frozen_rendered_compose", "frozen.json"), ("environment", "environment.json"))}
        self.policy = {"rollback_source": "b4c6bf0e7a0b610983ad21d343aff6a7bef5fb24",
                       "renderer": "compose-go/v2@v2.16.2:single-file-model-v1", "project_name": "recovery-test",
                       "replay_sha256": REPLAY, "service": "proxy", "image": IMAGE}
        self.fx.put(self.fx.paths["config"] / "config.yaml", CONFIG)
        self.fx.put(self.fx.paths["config"] / "compose.yaml", b"services: {proxy: {image: '${IMAGE:?required}'}}\n")
        self.fx.put(self.fx.paths["config"] / "environment.json", durable.canonical({"IMAGE": IMAGE}))
        frozen = {"name": "recovery-test", "networks": {"default": {"name": "recovery-test_default"}},
                  "services": {"proxy": {"image": IMAGE, "networks": {"default": None}}}}
        self.fx.put(self.fx.paths["config"] / "frozen.json", durable.canonical(frozen))
        self.save_baseline()
        helper = self.fx.root / "helper"
        helper.write_bytes(self.binary.read_bytes())
        helper.chmod(0o700)
        self.helper_fd = os.open(helper, os.O_RDONLY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.helper_fd)

    def save_baseline(self):
        # Synthetic approval creation, not operational provisioning. Keep previous
        # fixture baselines intact in separately named directories.
        backup = self.fx.root / ("baseline-" + str(len(list(self.fx.root.glob("baseline-*")))))
        backup.mkdir(mode=0o700)
        manifest = copy.deepcopy(self.fx.manifest)
        with durable.directory(str(backup), private=True) as parent:
            for name, path in self.fx.paths.items():
                with durable.directory(str(path)) as fd:
                    tree, blobs = inventory.snapshot(fd, uid=os.geteuid(), gid=os.getegid())
                self.fx.trees[name] = tree, blobs
                manifest["roots"][name]["baseline_sha256"] = inventory.save_baseline(parent, name, tree, blobs)
            pin = durable.atomic_write(parent, "manifest.json", durable.canonical(manifest))
        self.fx.backup, self.fx.manifest, self.fx.pin = backup, manifest, pin
        self.fx.value["baseline_sha256"] = pin

    def setup_gate(self, recovery):
        approval = baseline_gate.BaselineApproval(durable.digest(durable.canonical(self.fx.value)),
                      durable.digest(durable.canonical(self.roles)), durable.digest(durable.canonical(self.policy)))
        self.snapshot = baseline_gate.RestoredInputSnapshot(recovery=recovery, roles=self.roles, policy=self.policy,
                        approval=approval, check=self.fx.check, clock=lambda: self.fx.time)
        raw = self.snapshot(self.fx.value, deadline=1100)
        self.gate = baseline_gate.RestoredInputGate(helper_fd=self.helper_fd,
                    approval=input_gate.InputApproval(approval.intent_sha256, durable.digest(raw),
                                durable.digest(self.binary.read_bytes()), os.geteuid(), os.getegid()),
                    snapshot=self.snapshot, check=lambda: self.fx.fenced, clock=lambda: self.fx.time)
        self.reached = []
        run = self.gate._run
        def dispatch(raw, remaining):
            self.reached.append("baseline-helper-dispatched")
            return run(raw, remaining)
        self.gate._run = dispatch
        return raw

    def restored(self):
        recovery = self.enterContext(self.fx.open())
        recovery.restore_complete(self.fx.value, deadline=1100)
        self.setup_gate(recovery)
        return recovery

    def refused(self, call):
        with self.assertRaises(durable.Rejected):
            call()

    def test_actual_restored_inputs_use_distinct_non_authorizing_helper(self):
        recovery = self.restored()
        reached, run = [], self.gate._run
        def dispatch(raw, remaining):
            run(raw, remaining)
            reached.append("real-baseline-helper-confirmed")
        self.gate._run = dispatch
        self.assertTrue(self.gate.verify(self.fx.value, deadline=1100))
        self.assertEqual(reached, ["real-baseline-helper-confirmed"])
        self.assertNotIn(b'"start_authorized":true', self.gate.receipt)
        self.assertFalse(recovery.verify_files(self.fx.value, deadline=1100)["semantic_start_oracle_proven"])
        self.fx.assert_baseline()

    def open_verifier(self):
        return write_set.open_write_set_verifier(baseline=test_write_set.approve(self.fx.backup),
                    roots={name: test_write_set.approve(path) for name, path in self.fx.paths.items()},
                    baseline_sha256=self.fx.pin, check=self.fx.check, clock=lambda: self.fx.time)

    def test_fresh_read_only_verifier_supplies_actual_semantic_helper_inputs(self):
        with self.open_verifier() as observer:
            self.setup_gate(observer)
            self.assertTrue(self.gate.verify(self.fx.value, deadline=1100))
            self.assertEqual(self.reached, ["baseline-helper-dispatched"])
            self.assertFalse(observer._reader.restored)
            self.assertFalse(hasattr(observer, "restore_complete"))
            self.assertFalse(observer.verify_files(self.fx.value, deadline=1100)["start_permission"])
        self.refused(lambda: self.gate.verify(self.fx.value, deadline=1100))

    def test_byte_exact_invalid_baseline_from_read_only_verifier_still_fails_semantics(self):
        self.fx.put(self.fx.paths["config"] / "config.yaml", CONFIG + b"plugins: {enabled: true}\n")
        self.save_baseline()
        with self.open_verifier() as observer:
            self.assertTrue(observer.verify_files(self.fx.value, deadline=1100)["filesystem_verified"])
            self.setup_gate(observer)
            self.refused(lambda: self.gate.verify(self.fx.value, deadline=1100))
            self.assertEqual(self.reached, ["baseline-helper-dispatched"])
            self.assertFalse(observer._reader.restored)

    def test_snapshot_rechecks_approval_after_external_callback(self):
        for field in ("intent", "roles", "policy", "approval"):
            with self.subTest(field=field):
                self.setUp()
                with self.open_verifier() as observer:
                    self.setup_gate(observer)
                    reached = []
                    def changed(*, deadline):
                        reached.append(field)
                        if field == "intent":
                            self.fx.value["package_sha256"] = "0" * 64
                        elif field == "roles":
                            self.snapshot.roles["config"] = ("config", "missing")
                        elif field == "policy":
                            self.snapshot.policy["image"] = "mutable:tag"
                        else:
                            self.snapshot.approval = replace(self.snapshot.approval, intent_sha256="0" * 64)
                        return True
                    self.snapshot.check = changed
                    self.refused(lambda: self.snapshot._current(self.fx.value, 1100, lambda: None))
                    self.assertEqual(reached, [field])

    def test_capture_requires_restoration_and_valid_role_files(self):
        with self.fx.open() as recovery:
            self.refused(lambda: recovery.capture_files(self.fx.value, self.roles, deadline=1100))
        for location in (("config", "missing"), ("config", "../config.yaml"), ("absent", "config.yaml"),
                         ("auth", "nested"), ["config", "config.yaml"]):
            with self.subTest(location=location), self.fx.open() as recovery:
                recovery.restore_complete(self.fx.value, deadline=1100)
                roles = {**self.roles, "config": location}
                self.refused(lambda: recovery.capture_files(self.fx.value, roles, deadline=1100))
        with self.fx.open() as recovery:
            recovery.restore_complete(self.fx.value, deadline=1100)
            roles = {**self.roles, "environment": self.roles["config"]}
            self.refused(lambda: recovery.capture_files(self.fx.value, roles, deadline=1100))

    def test_capture_returns_current_bytes_not_cached_backup_blobs(self):
        self.restored()
        self.fx.put(self.fx.paths["config"] / "config.yaml", b"corrupted-after-restoration")
        self.refused(lambda: self.snapshot(self.fx.value, deadline=1100))
        self.refused(lambda: self.gate.verify(self.fx.value, deadline=1100))

    def test_full_root_recheck_catches_unrelated_provider_and_plugin_addition(self):
        for path in (self.fx.paths["auth"] / "unrelated.json", self.fx.paths["plugin"] / "candidate.so"):
            with self.subTest(path=path):
                self.setUp()
                self.restored()
                # Resolve into the current fixture; prior paths stay private.
                target = self.fx.paths[path.parent.name] / path.name
                self.fx.put(target, b"unexpected")
                self.refused(lambda: self.gate.verify(self.fx.value, deadline=1100))

    def test_role_policy_intent_and_helper_pins_cannot_drift(self):
        self.restored()
        for field in ("roles_sha256", "policy_sha256", "intent_sha256"):
            old = self.snapshot.approval
            self.snapshot.approval = replace(old, **{field: "0" * 64})
            self.refused(lambda: self.gate.verify(self.fx.value, deadline=1100))
            self.snapshot.approval = old
        old = self.gate.approval
        self.gate.approval = replace(old, helper_sha256="0" * 64)
        self.refused(lambda: self.gate.verify(self.fx.value, deadline=1100))

    def test_external_role_policy_mutation_is_not_adopted(self):
        self.restored()
        self.roles["config"] = ("config", "missing")
        self.policy["image"] = "mutable:tag"
        self.assertTrue(self.gate.verify(self.fx.value, deadline=1100))

    def test_serialization_mutation_requires_fresh_all_root_readback(self):
        self.restored()
        reached, serialize = [], baseline_gate.canonical
        def changed(value):
            raw = serialize(value)
            if type(value) is dict and value.get("schema") == "host-recovery-baseline-input-v1":
                self.fx.put(self.fx.paths["config"] / "environment.json", b'{"IMAGE":"changed"}')
                reached.append("serialized-then-mutated")
            return raw
        with patch.object(baseline_gate, "canonical", side_effect=changed), patch.object(
                inventory, "signature", return_value="synthetic-coarse-metadata"), patch.object(
                durable, "signature", return_value="synthetic-coarse-metadata"):
            self.refused(lambda: self.gate.verify(self.fx.value, deadline=1100))
        self.assertEqual(reached, ["serialized-then-mutated"])

    def test_after_helper_mutation_and_lost_fence_refuse(self):
        for change in ("bytes", "fence"):
            self.setUp()
            self.restored()
            reached, run = [], self.gate._run
            def changed(raw, remaining):
                run(raw, remaining)
                reached.append("real-helper-passed")
                if change == "bytes":
                    self.fx.put(self.fx.paths["config"] / "compose.yaml", b"changed")
                else:
                    self.fx.fenced = False
            self.gate._run = changed
            self.refused(lambda: self.gate.verify(self.fx.value, deadline=1100))
            self.assertEqual(reached, ["real-helper-passed"])

    def test_deadline_closed_context_and_storage_read_uncertainty_refuse(self):
        recovery = self.restored()
        self.refused(lambda: self.gate.verify(self.fx.value, deadline=self.fx.time))
        for code in (errno.EIO, errno.ENOSPC):
            self.setUp()
            recovery = self.restored()
            reached = []
            def fault(*args, **kwargs):
                reached.append(code)
                raise OSError(code, "synthetic-read-fault")
            with patch.object(inventory, "read_file", side_effect=fault):
                self.refused(lambda: self.gate.verify(self.fx.value, deadline=1100))
            self.assertEqual(reached, [code])
        recovery.closed = True
        self.refused(lambda: self.gate.verify(self.fx.value, deadline=1100))

    def boundary(self, recovery, *, complete=True, fault=None):
        case = self
        class Boundary:
            def __init__(self): self.calls = []
            def recovery_preflight(self, value, *, deadline): return True
            def fence(self, value, *, deadline): return True
            def quiesce(self, value, *, deadline): return True
            def validate_recovery(self, value, *, deadline):
                return recovery.validate_recovery(value, deadline=deadline)
            def restore_complete(self, value, *, deadline):
                return recovery.restore_complete(value, deadline=deadline, fault=fault)
            def verify_baseline_stopped(self, value, *, deadline):
                self.calls.append("scripted-oracle")
                if not complete:
                    return recovery.verify_files(value, deadline=deadline)
                return {"baseline_sha256": value["baseline_sha256"], "object_id": value["old_object_id"],
                        "original_image": True, "original_replay": True, "new_plugin_absent": True,
                        "complete_write_set": True, "metadata_verified": True, "all_writers_stopped": True}
            def start_old(self, value, receipt, *, deadline):
                case.fx.assert_baseline()
                self.calls.append("scripted-start")
                return True
            def old_ready(self, value, *, deadline): return True
        return Boundary()

    def test_start_is_one_shot_original_oracle_bound_and_freshly_checked(self):
        for failure in ("none", "before-oracle", "receipt", "intent", "late-file"):
            self.setUp()
            recovery = self.restored()
            host = self.boundary(recovery)
            boundary = baseline_gate.RecoveredInputBoundary(host, self.gate)
            if failure == "before-oracle":
                self.refused(lambda: boundary.start_old(self.fx.value, {}, deadline=1100))
                self.assertEqual(host.calls, [])
                continue
            receipt = boundary.verify_baseline_stopped(self.fx.value, deadline=1100)
            value = copy.deepcopy(self.fx.value)
            if failure == "receipt": receipt["original_image"] = False
            if failure == "intent": value["package_sha256"] = "0" * 64
            if failure == "late-file": self.fx.put(self.fx.paths["config"] / "config.yaml", b"changed")
            if failure == "none":
                self.assertTrue(boundary.start_old(value, receipt, deadline=1100))
                self.assertEqual(host.calls, ["scripted-oracle", "scripted-start"])
            else:
                self.refused(lambda: boundary.start_old(value, receipt, deadline=1100))
                self.assertEqual(host.calls, ["scripted-oracle"])
            self.refused(lambda: boundary.start_old(value, receipt, deadline=1100))
            self.refused(lambda: boundary.verify_baseline_stopped(value, deadline=1100))

    def test_direct_boundary_requires_complete_strict_oracle_before_helper(self):
        recovery = self.restored()
        host = self.boundary(recovery)
        good = host.verify_baseline_stopped(self.fx.value, deadline=1100)
        for field in good:
            for bad in (None, 1, False, "wrong"):
                if type(good[field]) is type(bad) and good[field] == bad:
                    continue
                with self.subTest(field=field, bad=bad):
                    value = {**good, field: bad}
                    host.verify_baseline_stopped = lambda *args, **kwargs: value
                    boundary = baseline_gate.RecoveredInputBoundary(host, self.gate)
                    self.refused(lambda: boundary.verify_baseline_stopped(self.fx.value, deadline=1100))
                    self.refused(lambda: boundary.start_old(self.fx.value, value, deadline=1100))
        self.assertEqual(self.reached, [])
        self.assertNotIn("scripted-start", host.calls)

    def test_lost_start_reply_never_reuses_original_check(self):
        recovery = self.restored()
        host = self.boundary(recovery)
        starts = []
        def ambiguous(*args, **kwargs):
            starts.append("start-reply-lost")
            raise OSError(errno.EIO, "synthetic transport fault")
        host.start_old = ambiguous
        boundary = baseline_gate.RecoveredInputBoundary(host, self.gate)
        receipt = boundary.verify_baseline_stopped(self.fx.value, deadline=1100)
        self.refused(lambda: boundary.start_old(self.fx.value, receipt, deadline=1100))
        self.refused(lambda: boundary.start_old(self.fx.value, receipt, deadline=1100))
        self.assertEqual(starts, ["start-reply-lost"])
        self.assertEqual(self.reached, ["baseline-helper-dispatched"] * 2)

    def resume_case(self, *, invalid=False, complete=True, receipt_fault=False):
        if invalid:
            self.fx.put(self.fx.paths["config"] / "config.yaml", CONFIG + b"plugins: {enabled: true}\n")
            self.save_baseline()  # Approved bytes still must pass independent semantics.
        with self.fx.open() as recovery:
            # Construct approved snapshot/request before simulating candidate mutation.
            recovery.restore_complete(self.fx.value, deadline=1100)
            self.setup_gate(recovery)
        with self.fx.open() as recovery:
            self.snapshot.recovery = recovery
            host = self.boundary(recovery, complete=complete)
            boundary = baseline_gate.RecoveredInputBoundary(host, self.gate)
            state = self.fx.root / "resume-state"
            state.mkdir(mode=0o700)
            notices = []
            def persist(_):
                if receipt_fault: raise OSError(errno.ENOSPC, "synthetic receipt fault")
            with durable.installation_lock(state, self.fx.value["owner"]) as (fd, _):
                log = journal.Journal(fd)
                log.prepare(self.fx.value)
                log.arm({"boot_id": "boot-a", "monotonic": 1000})
                self.fx.mutate()
                engine = coordinator.AttemptCoordinator(journal.Journal(fd), boundary, lambda: self.fx.time,
                         lambda: "boot-a", persist, lambda notice: notices.append(notice) or True)
                result = engine.resume()
            self.assertEqual(engine.meter.arm["monotonic"], 1000)
            self.assertTrue(result["start_fenced"])
            self.assertFalse(result["production_acceptance"])
            self.assertEqual(len(notices), 1)
            return result, host.calls, state

    def test_original_arm_resume_checks_restored_inputs_and_existing_oracle(self):
        result, calls, state = self.resume_case()
        self.assertEqual(result["outcome"], "baseline_restored")
        self.assertEqual(calls, ["scripted-oracle", "scripted-start"])
        self.assertEqual(self.reached, ["baseline-helper-dispatched"] * 2)
        self.assertTrue((state / "recovery-outcome.json").exists())

    def test_invalid_but_byte_exact_baseline_never_reaches_old_start(self):
        result, calls, state = self.resume_case(invalid=True, receipt_fault=True)
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertEqual(calls, ["scripted-oracle"])
        self.assertFalse((state / "recovery-outcome.json").exists())
        self.assertFalse(result["alert"]["receipt_persisted"])
        self.assertTrue(result["alert"]["transport_delivered"])
        self.assertEqual(self.reached, ["baseline-helper-dispatched"])

    def test_valid_inputs_cannot_replace_incomplete_independent_oracle(self):
        result, calls, state = self.resume_case(complete=False)
        self.assertEqual(result["outcome"], "recovery_unresolved")
        self.assertEqual(calls, ["scripted-oracle"])
        self.assertFalse((state / "recovery-outcome.json").exists())
