"""Real synthetic files, scripted daemon/fence; no container namespace is opened."""
import copy
import errno
import unittest
from unittest.mock import patch

from host_recovery import daemon, deployment, durable, inventory, write_set
import test_deployment
import test_write_set
from test_installation import approve


class BindSourceTests(unittest.TestCase):
    def setUp(self):
        self.fx = test_write_set.WriteSetTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.mounts = [{"Type": "bind", "Source": str(self.fx.paths[root]), "Destination": "/" + root,
                        "Mode": "ro", "RW": False, "Propagation": "rprivate"} for root in ("auth", "config")]

    def open(self):
        return write_set.open_write_set_verifier(baseline=approve(self.fx.backup), roots=self.fx.approvals,
                    baseline_sha256=self.fx.pin, check=self.fx.check, clock=lambda: self.fx.time)

    def verify(self, observer):
        return observer.verify_bind_sources(self.fx.value, self.mounts, deadline=1100)

    def gate(self, observer, *, enabled=True):
        docker = test_deployment.Docker()
        docker.deadline, docker.value["mounts"] = 1100, copy.deepcopy(self.mounts)
        objects = daemon.DockerObjects(docker="/accepted/docker", endpoint="unix:///accepted/disposable.sock",
                    commands=docker, intent=self.fx.value, old_image_id="e" * 64,
                    start_fence=lambda: self.fx.fenced, clock=lambda: self.fx.time)
        approval = deployment.DeploymentApproval(durable.digest(durable.canonical(self.fx.value)), "e" * 64,
                                                durable.digest(durable.canonical(docker.value)))
        return deployment.OldDeploymentGate(objects=objects, approval=approval, check=self.fx.check,
                    clock=lambda: self.fx.time, bind_sources=observer if enabled else None), docker

    def test_approved_sources_verify_full_baseline_without_mutating(self):
        with patch.object(write_set, "restore_tree", side_effect=AssertionError("restore attempted")), self.open() as observer:
            receipt = self.verify(observer)
            self.assertEqual(receipt, {"schema": "host-recovery-bind-source-result-v1", "baseline_sha256": self.fx.pin,
                "mounts": 2, "bind_source_baseline_verified": True, "container_namespace_verified": False,
                "start_authorized": False})
            self.assertNotIn(str(self.fx.root), str(receipt))
            self.assertNotIn("synthetic-0", str(receipt))
            self.assertFalse(observer._reader.restored)
        self.fx.assert_baseline()

    def test_missing_empty_unknown_or_oversized_mount_inventory_refuses(self):
        for mounts in (None, {}, [], self.mounts * 9):
            with self.subTest(mounts=mounts), self.open() as observer:
                self.mounts, saved = mounts, self.mounts
                try:
                    with self.assertRaises(durable.Rejected):
                        self.verify(observer)
                finally:
                    self.mounts = saved

    def test_unsupported_mount_semantics_and_nonliteral_flags_refuse(self):
        for key, value in (("Type", "volume"), ("Source", "/unapproved"), ("Source", str(self.fx.paths["config"] / "config.yaml")),
                           ("Mode", "rw"), ("Mode", "ro,z"), ("RW", True), ("RW", 0), ("RW", None),
                           ("Propagation", "rshared"), ("Propagation", "private")):
            with self.subTest(key=key, value=value), self.open() as observer:
                mounts = copy.deepcopy(self.mounts)
                mounts[0][key] = value
                with self.assertRaises(durable.Rejected):
                    observer.verify_bind_sources(self.fx.value, mounts, deadline=1100)

    def test_mount_fields_must_be_complete_and_supported(self):
        for key in self.mounts[0]:
            with self.subTest(missing=key), self.open() as observer:
                mounts = copy.deepcopy(self.mounts)
                del mounts[0][key]
                with self.assertRaises(durable.Rejected):
                    observer.verify_bind_sources(self.fx.value, mounts, deadline=1100)
        with self.open() as observer:
            mounts = copy.deepcopy(self.mounts)
            mounts[0]["Name"] = "unsupported"
            with self.assertRaises(durable.Rejected):
                observer.verify_bind_sources(self.fx.value, mounts, deadline=1100)

    def test_duplicate_sources_and_shadowed_destinations_refuse(self):
        for field, value in (("Source", self.mounts[0]["Source"]), ("Destination", "/auth"),
                             ("Destination", "/auth/nested")):
            with self.subTest(field=field, value=value), self.open() as observer:
                mounts = copy.deepcopy(self.mounts)
                mounts[1][field] = value
                with self.assertRaises(durable.Rejected):
                    observer.verify_bind_sources(self.fx.value, mounts, deadline=1100)
        with self.open() as observer:
            mounts = copy.deepcopy(self.mounts)
            mounts[0]["Destination"] = "/config/nested"
            with self.assertRaises(durable.Rejected):
                observer.verify_bind_sources(self.fx.value, mounts, deadline=1100)

    def test_noncanonical_destinations_refuse(self):
        for path in ("/", "relative", "/auth/", "/auth//nested", "/auth/./nested", "/auth/../config", "/bad\0path", "/" + "x" * 4096):
            with self.subTest(path=path), self.open() as observer:
                mounts = copy.deepcopy(self.mounts)
                mounts[0]["Destination"] = path
                with self.assertRaises(durable.Rejected):
                    observer.verify_bind_sources(self.fx.value, mounts, deadline=1100)

    def test_changed_mounted_bytes_and_unmounted_root_refuse_without_repair(self):
        for root, name in (("auth", "unrelated.json"), ("config", "config.yaml"), ("plugin", "candidate.so")):
            with self.subTest(root=root):
                self.setUp()
                path = self.fx.paths[root] / name
                self.fx.put(path, b"changed")
                with self.open() as observer, self.assertRaises(durable.Rejected):
                    self.verify(observer)
                self.assertEqual(path.read_bytes(), b"changed")

    def test_replaced_source_directory_refuses(self):
        # The retained directory handle also rejects replacement on context exit.
        with self.assertRaisesRegex(durable.Rejected, "^installation-directory-changed$"):
            with self.open() as observer:
                self.fx.paths["config"].rename(self.fx.root / "detached-config")
                self.fx.paths["config"].mkdir(mode=0o700)
                with self.assertRaises(durable.Rejected):
                    self.verify(observer)

    def test_reached_file_read_fault_poisoning(self):
        for code in (errno.EIO, errno.ENOSPC):
            with self.subTest(code=code), self.open() as observer:
                reached = []
                def fail(*args, **kwargs):
                    reached.append(code)
                    raise OSError(code, "synthetic-read-fault")
                with patch.object(inventory, "read_file", side_effect=fail), self.assertRaises(OSError):
                    self.verify(observer)
                self.assertEqual(reached, [code])
                with self.assertRaises(durable.Rejected):
                    self.verify(observer)

    def test_trailing_fence_cannot_change_mounts_or_reader(self):
        for target in ("mounts", "reader"):
            with self.subTest(target=target), self.open() as observer:
                scanned, reached = [], []
                reader, verify = observer._reader, observer._reader._verify_all
                def scan(deadline):
                    result = verify(deadline)
                    scanned.append("scan")
                    return result
                def check(*, deadline):
                    if len(scanned) == 2:
                        reached.append(target)
                        if target == "mounts":
                            self.mounts[0]["Source"] = "/unapproved"
                        else:
                            observer._reader = copy.copy(reader)
                    return True
                reader.check = check
                with patch.object(reader, "_verify_all", side_effect=scan), self.assertRaises(durable.Rejected):
                    self.verify(observer)
                self.assertEqual(reached, [target])
                with self.assertRaises(durable.Rejected):
                    self.verify(observer)
                self.mounts[0]["Source"] = str(self.fx.paths["auth"])

    def test_closed_or_expired_observer_cannot_verify_sources(self):
        with self.open() as observer:
            pass
        with self.assertRaises(durable.Rejected):
            self.verify(observer)
        with self.open() as observer, self.assertRaises(durable.Rejected):
            observer.verify_bind_sources(self.fx.value, self.mounts, deadline=self.fx.time)

    def test_deployment_composes_fresh_sources_with_pinned_projection(self):
        with self.open() as observer:
            gate, docker = self.gate(observer)
            receipt = gate.verify(self.fx.value, deadline=1100)
            self.assertIs(receipt["bind_source_baseline_verified"], True)
            self.assertIs(receipt["start_authorized"], False)
            self.assertEqual(len(docker.calls), 8)
            self.assertTrue(all(argv[2:4] == ("container", "inspect") for argv in docker.calls))

    def test_projection_only_receipt_does_not_claim_source_verification(self):
        with self.open() as observer:
            gate, _ = self.gate(observer, enabled=False)
            self.assertIs(gate.verify(self.fx.value, deadline=1100)["bind_source_baseline_verified"], False)

    def test_source_callback_cannot_hide_running_object(self):
        with self.open() as observer:
            gate, docker = self.gate(observer)
            observed, verify = [], observer.verify_bind_sources
            def sources(*args, **kwargs):
                result = verify(*args, **kwargs)
                observed.append("sources")
                if len(observed) == 3:
                    docker.state.update(running=True, status="running")
                return result
            with patch.object(observer, "verify_bind_sources", side_effect=sources), self.assertRaises(durable.Rejected):
                gate.verify(self.fx.value, deadline=1100)
            self.assertEqual(len(observed), 3)
            self.assertEqual(len(docker.calls), 7)

    def test_final_projection_cannot_replace_source_verifier(self):
        with self.open() as observer:
            gate, docker = self.gate(observer)
            reached = []
            def change(argv):
                if len(docker.calls) == 8:
                    reached.append("final-projection")
                    gate.bind_sources = None
            docker.hook = change
            with self.assertRaises(durable.Rejected):
                gate.verify(self.fx.value, deadline=1100)
            self.assertEqual(reached, ["final-projection"])

    def test_configured_source_check_cannot_be_removed_between_verify_and_start(self):
        with self.open() as observer:
            gate, docker = self.gate(observer)
            oracle = test_deployment.Oracle()
            oracle.receipt["baseline_sha256"] = self.fx.pin
            boundary = deployment.RecoveredDeploymentBoundary(oracle, gate)
            receipt = boundary.verify_baseline_stopped(self.fx.value, deadline=1100)
            before = len(docker.calls)
            gate.bind_sources = None
            with self.assertRaises(durable.Rejected):
                boundary.start_old(self.fx.value, receipt, deadline=1100)
            self.assertEqual(len(docker.calls), before)
            self.assertEqual(oracle.starts, 0)

    def test_recovered_deployment_rechecks_source_bytes_before_start(self):
        with self.open() as observer:
            gate, _ = self.gate(observer)
            oracle = test_deployment.Oracle()
            oracle.receipt["baseline_sha256"] = self.fx.pin
            boundary = deployment.RecoveredDeploymentBoundary(oracle, gate)
            receipt = boundary.verify_baseline_stopped(self.fx.value, deadline=1100)
            path = self.fx.paths["auth"] / "unrelated.json"
            self.fx.put(path, b"changed-between-verification-and-start")
            with self.assertRaises(durable.Rejected):
                boundary.start_old(self.fx.value, receipt, deadline=1100)
            self.assertEqual(oracle.starts, 0)
            with self.assertRaises(durable.Rejected):
                boundary.start_old(self.fx.value, receipt, deadline=1100)
            self.assertEqual(path.read_bytes(), b"changed-between-verification-and-start")
