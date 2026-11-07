import copy
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import docker_runtime_fixture as fixture
from docker_runtime_fixture import docker_config, fixture_names, inspect_object, rootfs_archive, validate_info, validate_plugin_mount


class DockerRuntimeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.root, self.units, self.slice = fixture_names("123456789", "1")
        self.object_id, self.image_id = "a" * 64, "sha256:" + "b" * 64
        self.row = {"Id": self.object_id, "Image": self.image_id, "Path": "/probe", "Args": [], "RestartCount": 0,
                    "HostConfig": {"RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                        "AutoRemove": False, "Privileged": False, "Binds": None, "NetworkMode": "none",
                        "CgroupParent": self.slice, "Runtime": "cpa", "CapDrop": ["ALL"],
                        "SecurityOpt": ["no-new-privileges"]}, "Mounts": [],
                    "State": {"Running": False, "Restarting": False, "Pid": 0}}

    def inspect(self, row, running=False):
        inspect_object(row, self.object_id, self.image_id, self.slice, running=running)

    def task_http(self):
        return fixture.TaskInspection(self.root, peer=(123, 0, 0), unit=self.units[1]["dockerd"],
            invocation="a" * 32, current=Mock(), deadline=1000)

    def test_fixed_inspection_uses_only_full_object_read_and_trailing_binding(self):
        client = self.task_http()
        response = Mock(status=200)
        response.read.return_value = b'{"synthetic":true}'
        with patch.object(client, "bound") as bound, patch.object(client, "request") as request, \
                patch.object(client, "getresponse", return_value=response):
            self.assertEqual(client.inspect(self.object_id), {"synthetic": True})
        request.assert_called_once_with("GET", "/v1.48/containers/" + self.object_id + "/json")
        self.assertEqual(bound.call_count, 2)
        response.read.assert_called_once_with(1024 * 1024 + 1)
        with patch.object(client, "request") as request, self.assertRaises(AssertionError):
            client.inspect("../unapproved")
        request.assert_not_called()

    def test_fixed_inspection_refuses_error_and_overflow_without_healthy_result(self):
        for status, raw in ((500, b'{}'), (200, b"x" * (1024 * 1024 + 1))):
            client = self.task_http()
            response = Mock(status=status)
            response.read.return_value = raw
            with self.subTest(status=status), patch.object(client, "bound"), patch.object(client, "request"), \
                    patch.object(client, "getresponse", return_value=response), self.assertRaises(AssertionError):
                client.inspect(self.object_id)

    def test_fixed_inspection_rejects_each_original_manager_binding_change(self):
        good = {"MainPID": "123", "InvocationID": "a" * 32, "ActiveState": "active"}
        for name, value in (("MainPID", "124"), ("InvocationID", "b" * 32), ("ActiveState", "inactive")):
            client = self.task_http()
            fields = {**good, name: value}
            raw = "".join(key + "=" + value + "\n" for key, value in fields.items()).encode()
            with self.subTest(name=name), patch.object(fixture, "command", return_value=Mock(stdout=raw)), \
                    self.assertRaises(AssertionError):
                client.bound()
            self.assertEqual(client.current.call_count, 2)

    def test_fixed_inspection_batches_fresh_manager_reads_within_original_budget(self):
        client = self.task_http()
        raw = b"MainPID=123\nInvocationID=" + b"a" * 32 + b"\nActiveState=active\n"
        elapsed = 0
        def current():
            self.assertLess(elapsed, 3, "synthetic original budget exhausted")
        def command(*args):
            nonlocal elapsed
            elapsed += 1
            return Mock(stdout=raw)
        def show(unit, key):
            nonlocal elapsed
            elapsed += 1
            return dict(line.split("=", 1) for line in raw.decode().splitlines())[key]
        client.current = current
        with patch.object(fixture, "command", side_effect=command) as query, \
                patch.object(fixture, "show", side_effect=show):
            client.bound()
            client.bound()
        self.assertEqual(elapsed, 2)
        self.assertEqual(query.call_count, 2)
        query.assert_called_with("/usr/bin/systemctl", "show", "--property=MainPID",
                                 "--property=InvocationID", "--property=ActiveState", "--", client.unit)

    def test_fixed_inspection_rejects_ambiguous_or_incomplete_manager_fields(self):
        good = b"MainPID=123\nInvocationID=" + b"a" * 32 + b"\nActiveState=active\n"
        for raw in (b"", good.replace(b"MainPID=123\n", b""), good + b"MainPID=123\n",
                    good + b"Unknown=value\n", good + b"ActiveState\n",
                    good.replace(b"MainPID=123", b"MainPID=0123")):
            client = self.task_http()
            with self.subTest(raw=raw), patch.object(fixture, "command", return_value=Mock(stdout=raw)), \
                    self.assertRaises(AssertionError):
                client.bound()

    def test_fixed_inspection_never_reuses_previous_manager_sample(self):
        client = self.task_http()
        good = b"MainPID=123\nInvocationID=" + b"a" * 32 + b"\nActiveState=active\n"
        for bad in (good.replace(b"123", b"124"), good.replace(b"a" * 32, b"b" * 32),
                    good.replace(b"active\n", b"inactive\n")):
            with self.subTest(bad=bad), patch.object(fixture, "command",
                    side_effect=[Mock(stdout=good), Mock(stdout=bad)]) as query:
                client.bound()
                with self.assertRaises(AssertionError):
                    client.bound()
                self.assertEqual(query.call_count, 2)

    def test_fixed_inspection_checks_original_deadline_after_manager_query(self):
        client = self.task_http()
        good = b"MainPID=123\nInvocationID=" + b"a" * 32 + b"\nActiveState=active\n"
        client.current.side_effect = [None, AssertionError("synthetic deadline expired")]
        with patch.object(fixture, "command", return_value=Mock(stdout=good)) as query, \
                self.assertRaisesRegex(AssertionError, "synthetic deadline expired"):
            client.bound()
        query.assert_called_once()

    def test_fixed_inspection_rejects_socket_peer_drift(self):
        client = self.task_http()
        client.sock = Mock()
        for peer in ((124, 0, 0), (123, 1, 0), (123, 0, 1)):
            client.sock.getsockopt.return_value = fixture.struct.pack("3i", *peer)
            with self.subTest(peer=peer), self.assertRaises(AssertionError):
                client.require_peer()
        client.sock.getsockopt.return_value = fixture.struct.pack("3i", 123, 0, 0)
        client.require_peer()
        client.close()

    def test_baseline_root_is_separate_protected_and_exact_runtime_scoped(self):
        root = fixture.baseline_fixture.baseline_root(self.root)
        self.assertEqual(root.parent, Path("/"))
        self.assertNotEqual(root, fixture.baseline_fixture.baseline_root(fixture_names("123456789", "2")[0]))
        for path in (Path("/tmp/anything"), Path("/"), Path(str(self.root) + "/child")):
            with self.subTest(path=path), self.assertRaises(fixture.Rejected):
                fixture.baseline_fixture.baseline_root(path)

    def test_diagnostic_intent_binds_actual_object_and_baseline_without_start(self):
        value = fixture.baseline_fixture.intent("c" * 64, self.object_id)
        self.assertEqual(value["old_object_id"], self.object_id)
        self.assertEqual(value["baseline_sha256"], "c" * 64)
        self.assertEqual(value["budget"]["total_seconds"], 300)
        with self.assertRaises(fixture.Rejected):
            fixture.baseline_fixture.intent("c" * 64, "short-id")

    def mounted_row(self):
        mounts = [{"Type": "bind", "Source": "/synthetic-private/auth", "Destination": "/baseline/auth",
                   "Mode": "ro", "RW": False, "Propagation": "rprivate"}]
        row = copy.deepcopy(self.row)
        row["HostConfig"]["Binds"] = ["/synthetic-private/auth:/baseline/auth:ro"]
        row["Mounts"] = copy.deepcopy(mounts)
        return row, mounts

    def cold_row(self):
        row, mounts = self.mounted_row()
        row["Mounts"] = [dict(mounts[0], Source="/synthetic-private/" + name,
                              Destination="/baseline/" + name) for name in ("plugins", "config", "auth")]
        return row

    def test_cold_object_accepts_only_mount_order_changes_without_mutating_samples(self):
        first = self.cold_row()
        second = copy.deepcopy(first)
        second["Mounts"].reverse()
        original_first, original_second = copy.deepcopy(first), copy.deepcopy(second)
        fixture.require_same_cold_object(first, second)
        self.assertEqual(first, original_first)
        self.assertEqual(second, original_second)
        fixture.require_same_cold_object(self.row, copy.deepcopy(self.row))

    def test_cold_object_rejects_each_changed_mount_field_after_reordering(self):
        first = self.cold_row()
        for field, value in (("Type", "volume"), ("Source", "/other"), ("Destination", "/other"),
                             ("Mode", "rw"), ("RW", True), ("Propagation", "shared")):
            changed = copy.deepcopy(first)
            changed["Mounts"].reverse()
            changed["Mounts"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, "cold startup object changed"):
                fixture.require_same_cold_object(first, changed)

    def test_cold_object_rejects_added_removed_and_duplicate_mounts(self):
        first = self.cold_row()
        for operation in ("add", "remove", "duplicate", "replace-with-duplicate"):
            changed = copy.deepcopy(first)
            changed["Mounts"].reverse()
            if operation == "add":
                changed["Mounts"].append(dict(changed["Mounts"][0], Destination="/extra"))
            elif operation == "remove":
                changed["Mounts"].pop()
            elif operation == "duplicate":
                changed["Mounts"].append(copy.deepcopy(changed["Mounts"][0]))
            else:
                changed["Mounts"][1] = copy.deepcopy(changed["Mounts"][0])
            with self.subTest(operation=operation), self.assertRaisesRegex(AssertionError, "cold startup object changed"):
                fixture.require_same_cold_object(first, changed)

    def test_cold_object_does_not_canonicalize_other_fields_or_arrays(self):
        first = self.cold_row()
        first["Args"] = ["first", "second"]
        first["Config"] = {"Env": ["FIRST=1", "SECOND=2"]}
        first["HostConfig"]["Binds"] = ["/first:/first:ro", "/second:/second:ro"]
        for field in ("Args", "Env", "Binds", "Id", "RestartCount", "State", "extra"):
            changed = copy.deepcopy(first)
            changed["Mounts"].reverse()
            if field == "Args":
                changed[field].reverse()
            elif field == "Env":
                changed["Config"][field].reverse()
            elif field == "Binds":
                changed["HostConfig"][field].reverse()
            elif field == "Id":
                changed[field] = "c" * 64
            elif field == "RestartCount":
                changed[field] = 1
            elif field == "State":
                changed[field]["Running"] = True
            else:
                changed[field] = True
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, "cold startup object changed"):
                fixture.require_same_cold_object(first, changed)

    def test_cold_object_rejects_incomplete_or_extended_mount_schema(self):
        first = self.cold_row()
        for shape in ("missing", "extra", "not-list", "not-object"):
            changed = copy.deepcopy(first)
            if shape == "missing":
                del changed["Mounts"][0]["RW"]
            elif shape == "extra":
                changed["Mounts"][0]["Other"] = "value"
            elif shape == "not-list":
                changed["Mounts"] = None
            else:
                changed["Mounts"][0] = None
            with self.subTest(shape=shape), self.assertRaisesRegex(AssertionError, "Docker fixture mount schema changed"):
                fixture.require_same_cold_object(first, changed)

    def test_only_exact_expected_mount_projection_and_bind_argv_are_accepted(self):
        row, mounts = self.mounted_row()
        inspect_object(row, self.object_id, self.image_id, self.slice, running=False, mounts=mounts)
        for field, value in (("Source", "/"), ("Destination", "/host"), ("Mode", "rw"),
                             ("RW", True), ("Propagation", "shared")):
            changed = copy.deepcopy(row)
            changed["Mounts"][0][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                inspect_object(changed, self.object_id, self.image_id, self.slice, running=False, mounts=mounts)

    def test_bind_argv_cannot_differ_from_matching_inspect_mounts(self):
        row, mounts = self.mounted_row()
        for binds in (None, [], ["/:/baseline/auth:ro"], ["/synthetic-private/auth:/baseline/auth:rw"]):
            changed = copy.deepcopy(row)
            changed["HostConfig"]["Binds"] = binds
            with self.subTest(binds=binds), self.assertRaises(AssertionError):
                inspect_object(changed, self.object_id, self.image_id, self.slice, running=False, mounts=mounts)

    def test_unexpected_additional_bind_is_not_ignored(self):
        row, mounts = self.mounted_row()
        row["Mounts"].append({**mounts[0], "Source": "/run/docker.sock", "Destination": "/socket"})
        with self.assertRaises(AssertionError):
            inspect_object(row, self.object_id, self.image_id, self.slice, running=False, mounts=mounts)

    def test_short_private_root_and_distinct_epoch_units(self):
        root, units, _ = fixture_names("9" * 20, "8" * 20)
        self.assertLessEqual(len(str(root / "s")), 42)
        self.assertEqual(len({unit for epoch in units.values() for unit in epoch.values()}), 4)
        self.assertNotEqual(root, fixture_names("9" * 20, "7" * 20)[0])
        for value in ("", "0", "01", "-1", "1/x", "9" * 21):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                fixture_names(value, "1")

    def test_closed_config_has_no_ambient_daemon_or_network(self):
        config = docker_config(self.root, self.slice)
        self.assertEqual(config["containerd"], str(self.root / "grpc.sock"))
        self.assertEqual(config["hosts"], ["unix://" + str(self.root / "docker.sock")])
        self.assertEqual(config["exec-opts"], ["native.cgroupdriver=systemd"])
        self.assertEqual(config["cgroup-parent"], self.slice)
        self.assertEqual(config["storage-driver"], "vfs")
        self.assertEqual(config["runtimes"], {"cpa": {"path": "/usr/bin/runc"}})
        for key in ("data-root", "exec-root", "pidfile"):
            self.assertTrue(Path(config[key]).is_relative_to(self.root))
        for key in ("live-restore", "iptables", "ip6tables", "ip-forward", "ip-masq", "userland-proxy"):
            self.assertIs(config[key], False)
        for root, group in ((Path("/var/lib/docker"), self.slice), (self.root, "system.slice")):
            with self.subTest(root=root, group=group), self.assertRaises(AssertionError):
                docker_config(root, group)

    def test_dockerd_explicitly_requests_private_mount_propagation(self):
        with patch.object(fixture, "show", return_value="not-found"), patch.object(fixture, "command") as command:
            fixture.start_unit(self.root, self.units[1]["dockerd"], self.slice,
                               "/usr/bin/dockerd", self.root / "docker.json")
        args = command.call_args.args
        self.assertIn("--property=PrivateMounts=yes", args)
        self.assertIn("--property=MountFlags=private", args)
        self.assertIn("--property=TemporaryFileSystem=/run/docker:rw,nosuid,nodev,noexec,size=1M,mode=0700", args)
        self.assertIn("--property=InaccessiblePaths=-/run/containerd -/run/docker.sock -/var/lib/docker -/var/lib/containerd", args)

    def test_plugin_root_requires_one_private_noexec_tmpfs(self):
        line = "99 20 0:42 / /run/docker rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=1024k\n"
        validate_plugin_mount(line)
        for changed in ("", line + line, line.replace("tmpfs", "ext4"), line.replace(",noexec", ""),
                        line.replace(" - tmpfs", " shared:42 - tmpfs"), line.replace(" / /run/docker", " /host /run/docker")):
            with self.subTest(changed=changed), self.assertRaises(AssertionError):
                validate_plugin_mount(changed)

    def test_effective_info_requires_actual_server_fields(self):
        info = {"DockerRootDir": str(self.root / "docker"), "Driver": "vfs", "CgroupDriver": "systemd",
                "LiveRestoreEnabled": False, "Swarm": {"LocalNodeState": "inactive"}}
        validate_info(info, self.root)
        for field, value in (("DockerRootDir", ""), ("Driver", ""), ("CgroupDriver", "cgroupfs"),
                             ("LiveRestoreEnabled", True), ("Swarm", {"LocalNodeState": ""})):
            changed = copy.deepcopy(info)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                validate_info(changed, self.root)

    def test_restart_policy_is_checked_before_start_and_after_cold_restart(self):
        self.inspect(self.row)
        active = copy.deepcopy(self.row)
        active["State"].update(Running=True, Pid=123)
        self.inspect(active, True)
        for policy in ("always", "unless-stopped", "on-failure", "", None):
            changed = copy.deepcopy(self.row)
            changed["HostConfig"]["RestartPolicy"]["Name"] = policy
            with self.subTest(policy=policy), self.assertRaises(AssertionError):
                self.inspect(changed)
        changed = copy.deepcopy(self.row)
        changed["HostConfig"]["RestartPolicy"]["MaximumRetryCount"] = 1
        with self.assertRaises(AssertionError):
            self.inspect(changed)

    def test_host_bind_privilege_and_wrong_parent_refuse(self):
        for field, value in (("Binds", ["/:/host"]), ("Privileged", True), ("AutoRemove", True),
                             ("NetworkMode", "host"), ("CgroupParent", "system.slice"),
                             ("CapDrop", []), ("SecurityOpt", []), ("Runtime", "runc")):
            changed = copy.deepcopy(self.row)
            changed["HostConfig"][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self.inspect(changed)

    def test_stopped_pid_and_resurrection_mismatches_refuse(self):
        for field, value in (("Pid", 12), ("Pid", False), ("Running", True), ("Restarting", True)):
            changed = copy.deepcopy(self.row)
            changed["State"][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self.inspect(changed)
        for field, value in (("Id", "c" * 64), ("Image", "sha256:" + "d" * 64),
                             ("RestartCount", 1), ("Path", "/bin/sh"), ("Args", ["child"]),
                             ("Mounts", [{"Source": "/run/docker.sock"}])):
            changed = copy.deepcopy(self.row)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self.inspect(changed)

    def task_files(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        mount_id = "c" * 64
        record = root / "docker/image/vfs/layerdb/mounts" / self.object_id / "mount-id"
        record.parent.mkdir(parents=True)
        record.write_text(mount_id)
        private = root / "docker/vfs/dir" / mount_id
        private.mkdir(parents=True)
        (private / "probe").write_bytes(b"synthetic-task")
        process = root / "proc/123"
        process.mkdir(parents=True)
        (process / "root").symlink_to(private, target_is_directory=True)
        (process / "exe").symlink_to(private / "probe")
        return root, private, record, process

    def test_task_executable_uses_private_root_and_inode_not_link_text(self):
        root, _, _, _ = self.task_files()
        self.assertEqual(fixture.task_executable(root, self.object_id, 123, proc=root / "proc"), b"synthetic-task")

    def test_identical_executable_bytes_in_other_root_refuse(self):
        root, _, _, process = self.task_files()
        other = root / "other"
        other.mkdir()
        (other / "probe").write_bytes(b"synthetic-task")
        (process / "root").unlink()
        (process / "root").symlink_to(other, target_is_directory=True)
        (process / "exe").unlink()
        (process / "exe").symlink_to(other / "probe")
        with self.assertRaisesRegex(AssertionError, "root outside private"):
            fixture.task_executable(root, self.object_id, 123, proc=root / "proc")

    def test_identical_executable_copy_in_correct_root_refuses(self):
        root, private, _, process = self.task_files()
        (private / "copy").write_bytes(b"synthetic-task")
        (process / "exe").unlink()
        (process / "exe").symlink_to(private / "copy")
        with self.assertRaisesRegex(AssertionError, "differs from private mounted"):
            fixture.task_executable(root, self.object_id, 123, proc=root / "proc")

    def test_ambiguous_vfs_mount_id_refuses(self):
        root, _, record, _ = self.task_files()
        for value in ("", "../outside", "c" * 63, "c" * 64 + "\n", "d" * 129):
            record.write_text(value)
            with self.subTest(value=value), self.assertRaises(AssertionError):
                fixture.task_executable(root, self.object_id, 123, proc=root / "proc")

    def test_private_probe_symlink_refuses(self):
        root, private, _, _ = self.task_files()
        (private / "probe").rename(private / "real")
        (private / "probe").symlink_to(private / "real")
        with self.assertRaises(OSError):
            fixture.task_executable(root, self.object_id, 123, proc=root / "proc")

    def test_tar_contains_only_source_probe_and_empty_mountpoints(self):
        raw = b"synthetic-probe-bytes-not-an-executable"
        archive = rootfs_archive(raw)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
            members = source.getmembers()
            self.assertEqual([item.name for item in members], ["dev", "proc", "sys", "etc", "tmp", "probe"])
            self.assertTrue(all(item.isdir() for item in members[:-1]))
            self.assertTrue(members[-1].isfile())
            self.assertEqual(members[-1].mode, 0o500)
            self.assertEqual(source.extractfile(members[-1]).read(), raw)
            self.assertTrue(all(item.uid == item.gid == 0 and not item.linkname for item in members))


if __name__ == "__main__":
    unittest.main()
