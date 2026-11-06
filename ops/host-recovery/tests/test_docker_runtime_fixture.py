import copy
import io
from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
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
