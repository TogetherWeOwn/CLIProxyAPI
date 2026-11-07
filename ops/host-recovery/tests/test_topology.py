"""Synthetic topology/pin negatives, not installed runtime qualification."""
from dataclasses import replace
import unittest
from types import MappingProxyType

from host_recovery.durable import Rejected, canonical, digest
from host_recovery.loading import ContentApproval, ContentSnapshot
from host_recovery.topology import MAX_BYTES, Topology, load_topology


def manifest():
    from host_recovery.topology import PINS, PROTECTED_ROOTS, ROLES, TOOLS, WRITE_ROOTS
    value = {"schema": "host-recovery-topology-v1",
        "installation_id": "00000000-0000-4000-8000-000000000001",
        "runtime": {"ownership": "installation_only", "adoption": "fresh_empty_only",
            "cgroup_driver": "systemd", "live_restore": False, "restart_policy": "no",
            "maximum_retry_count": 0, "auto_remove": False, "swarm": False,
            "external_launchers": False, "boot_autostart": False, "socket_activation": False,
            "path_activation": False, "timer_activation": False, "force_restart": False,
            "cold_barrier": "required", "metadata": "regular_tree_v1", "slice": "fixture_runtime.slice",
            "cgroup_path": "/fixture_runtime.slice", "units": {
                name: {"unit": "fixture_" + name + ".service", "effective_sha256": "a" * 64}
                for name in ("dockerd", "containerd")}},
        "roles": {name: {"uid": 0 if name == "broker" else 2000 + index,
            "gid": 0 if name == "broker" else 2000 + index,
            "unit": "fixture_" + name + ("@" if name == "recovery" else "") + ".service",
            "effective_sha256": "b" * 64, "launch_sha256": "c" * 64}
            for index, name in enumerate(ROLES)},
        "tools": {name: {"version": "1.0.0", "source_revision": "a" * 40, "sha256": "d" * 64}
                  for name in TOOLS},
        "resources": {"data_root": "/srv/fixture/runtime/data", "exec_root": "/run/fixture/docker",
            "containerd_root": "/srv/fixture/runtime/containerd", "containerd_state": "/run/fixture/containerd",
            "dockerd_socket": "/run/fixture/docker/docker.sock",
            "containerd_socket": "/run/fixture/containerd/containerd.sock", "containerd_namespace": "fixture"},
        "protected_roots": {name: "/srv/fixture/protected/" + name for name in PROTECTED_ROOTS},
        "write_roots": {name: "/srv/fixture/managed/" + name for name in WRITE_ROOTS},
        "pins": {name: "a" * (40 if name.endswith("_revision") else 64) for name in PINS}}
    return value


class TopologyTests(unittest.TestCase):
    def reject(self, change, code=None):
        value = manifest()
        change(value)
        with self.assertRaisesRegex(Rejected, code or ".+"):
            Topology(canonical(value))

    def test_valid_input_is_immutable_and_always_non_authorizing(self):
        raw = canonical(manifest())
        topology = Topology(raw)
        self.assertEqual(topology.sha256, digest(raw))
        borrowed = topology.manifest()
        borrowed["runtime"]["live_restore"] = True
        self.assertFalse(topology.manifest()["runtime"]["live_restore"])
        with self.assertRaises(AttributeError):
            topology.raw = b"{}"
        status = topology.status()
        for key in ("provisioning_verified", "complete_fence_proven", "recovery_execution_allowed",
                    "start_allowed", "production_acceptance"):
            self.assertIs(status[key], False)

    def test_bounded_strict_json(self):
        for raw in (b"", b"[]", b"{}", b"{" * 1100, b'{"x":NaN}', b'{"x":1e999}',
                    b'{"schema":1,"schema":2}', b"\xff", b" " * (MAX_BYTES + 1), "{}"):
            with self.subTest(raw_type=type(raw).__name__), self.assertRaises(Rejected):
                Topology(raw)

    def test_unknown_and_missing_fields_at_every_schema_boundary(self):
        paths = [(), ("runtime",), ("runtime", "units"), ("runtime", "units", "dockerd"),
                 ("roles",), ("roles", "broker"), ("tools",), ("tools", "runc"),
                 ("resources",), ("protected_roots",), ("write_roots",), ("pins",)]
        for path in paths:
            for extra in (False, True):
                def change(value):
                    for key in path:
                        value = value[key]
                    value.update(extra=True) if extra else value.pop(next(iter(value)))
                with self.subTest(path=path, extra=extra):
                    self.reject(change, "schema")

    def test_all_runtime_policy_changes_fail_closed(self):
        supported = manifest()["runtime"]
        for key in supported.keys() - {"slice", "cgroup_path", "units"}:
            old = supported[key]
            wrong = True if type(old) is bool else (False if type(old) is int else "unsupported")
            with self.subTest(key=key):
                self.reject(lambda v: v["runtime"].update({key: wrong}), "unsupported-runtime-policy")
        for key, item in (("maximum_retry_count", False), ("live_restore", 0), ("auto_remove", 0),
                          ("ownership", "shared"), ("adoption", "existing"), ("restart_policy", "always"),
                          ("restart_policy", "unless-stopped"), ("restart_policy", "on-failure")):
            with self.subTest(key=key, item=item):
                self.reject(lambda v: v["runtime"].update({key: item}))

    def test_slice_and_fixed_unit_boundaries(self):
        for name in ("system.slice", "user.slice", "machine.slice", "-.slice", "nested-child.slice",
                     "x/service.slice", "foo.slice\n", "a" * 100 + ".slice", 7):
            with self.subTest(slice=name):
                self.reject(lambda v: v["runtime"].update(slice=name, cgroup_path="/" + str(name)))
        self.reject(lambda v: v["runtime"].update(cgroup_path="/system.slice/fixture_runtime.slice"))
        for unit in ("docker.service", "containerd.service", "wrong@.service", "foo.service;exec", "../x.service"):
            with self.subTest(unit=unit):
                self.reject(lambda v: v["runtime"]["units"]["dockerd"].update(unit=unit))
        self.reject(lambda v: v["runtime"]["units"]["containerd"].update(unit="fixture_dockerd.service"))
        self.reject(lambda v: v["roles"]["forward"].update(unit="fixture_dockerd.service"))
        self.reject(lambda v: v["roles"]["forward"].update(unit="fixture_forward@.service"))
        self.reject(lambda v: v["roles"]["recovery"].update(unit="fixture_recovery.service"))

    def test_numeric_distinct_roles_and_root_only_broker(self):
        for key, item in (("uid", True), ("gid", -1), ("uid", 2**31), ("gid", "2000"),
                          ("uid", 0), ("gid", 0), ("uid", 2001), ("gid", 2001)):
            with self.subTest(key=key, item=item):
                self.reject(lambda v: v["roles"]["forward"].update({key: item}))
        self.reject(lambda v: v["roles"]["broker"].update(uid=2000))
        self.reject(lambda v: v["roles"]["broker"].update(gid=2000))

    def test_paths_cannot_target_shared_runtime_or_infrastructure(self):
        for path in ("/", "relative", "/a/../b", "/a//b", "/a/./b", "/a/", "/a/\x00b", "/a/\\b",
                     "/" + "a" * 129, "/a" * 34, "/var/lib/docker", "/var/lib/docker/other",
                     "/var/run/fixture", "/run/containerd", "/run", "/var/lib", "/proc/fixture",
                     "/sys/fixture", "/dev/fixture", "/etc", "/usr", "/boot/fixture"):
            with self.subTest(path=path):
                self.reject(lambda v: v["write_roots"].update(auth=path))

    def test_runtime_sockets_must_be_inside_separate_private_roots(self):
        for key, path in (("dockerd_socket", "/run/docker.sock"), ("dockerd_socket", "/run/fixture/docker"),
                          ("dockerd_socket", "/run/fixture/docker-other/socket"),
                          ("containerd_socket", "/run/fixture/docker/socket"),
                          ("containerd_socket", "/run/fixture/containerd")):
            with self.subTest(key=key, path=path):
                self.reject(lambda v: v["resources"].update({key: path}))
        for namespace in ("default", "moby", "k8s.io", "..", "a/b", "", "a b", True):
            with self.subTest(namespace=namespace):
                self.reject(lambda v: v["resources"].update(containerd_namespace=namespace))

    def test_all_root_pairs_must_be_disjoint_in_both_directions(self):
        root = manifest()
        paths = [(field, key) for field in ("resources", "protected_roots", "write_roots")
                 for key in root[field] if "socket" not in key and "namespace" not in key]
        for index, (left_field, left_key) in enumerate(paths):
            for right_field, right_key in paths[index + 1:]:
                for suffix in ("", "/child"):
                    with self.subTest(left=left_key, right=right_key, suffix=suffix):
                        self.reject(lambda v: v[left_field].update({left_key: v[right_field][right_key] + suffix}))
                        self.reject(lambda v: v[right_field].update({right_key: v[left_field][left_key] + suffix}))

    def test_every_pin_and_tool_version_is_required(self):
        for key in manifest()["pins"]:
            with self.subTest(pin=key):
                self.reject(lambda v: v["pins"].update({key: "f" * 63}))
        for name in manifest()["tools"]:
            for key, wrong in (("sha256", "G" * 64), ("source_revision", "main"), ("version", "latest stable")):
                with self.subTest(tool=name, key=key):
                    self.reject(lambda v: v["tools"][name].update({key: wrong}))
        for invalid in ("not an id", "", True, "a" * 129, "../escape"):
            self.reject(lambda v: v.update(installation_id=invalid))

    def snapshot(self, value=None):
        raw = canonical(manifest() if value is None else value)
        # Explicit constructed snapshot fixture, NOT a protected root provisioning test.
        return ContentSnapshot(ContentApproval("b" * 64, "a" * 40, 0, 0),
                               MappingProxyType({"topology.json": raw}))

    def load(self, content=None, **kwargs):
        content = self.snapshot() if content is None else content
        args = {"sha256": digest(content.files["topology.json"]),
                "installation_id": manifest()["installation_id"]}
        args.update(kwargs)
        return load_topology(content, **args)

    def test_snapshot_binding_to_external_pin_source_and_installation(self):
        snapshot = self.snapshot()
        self.assertEqual(self.load(snapshot).raw, snapshot.files["topology.json"])
        with self.assertRaisesRegex(Rejected, "pin-mismatch"):
            self.load(snapshot, sha256="e" * 64)
        with self.assertRaisesRegex(Rejected, "identity-mismatch"):
            self.load(snapshot, installation_id="00000000-0000-4000-8000-000000000002")
        with self.assertRaisesRegex(Rejected, "identity-mismatch"):
            self.load(replace(snapshot, approval=replace(snapshot.approval, source_revision="e" * 40)))
        for uid, gid in ((1000, 0), (0, 1000), (1000, 1000)):
            with self.subTest(uid=uid, gid=gid), self.assertRaisesRegex(Rejected, "root-provisioned"):
                self.load(replace(snapshot, approval=replace(snapshot.approval, uid=uid, gid=gid)))

    def test_invalid_snapshot_missing_bytes_and_self_repin_do_not_supply_authority(self):
        for content in (None, {}, "path", ContentSnapshot(None, {})):
            with self.subTest(content=type(content).__name__), self.assertRaises(Rejected):
                load_topology(content, sha256="a" * 64, installation_id=manifest()["installation_id"])
        empty = replace(self.snapshot(), files={})
        with self.assertRaisesRegex(Rejected, "pin-mismatch"):
            load_topology(empty, sha256="a" * 64, installation_id=manifest()["installation_id"])
        value = manifest()
        value["runtime"]["ownership"] = "shared"
        snapshot = self.snapshot(value)
        with self.assertRaises(Rejected):
            self.load(snapshot)


if __name__ == "__main__":
    unittest.main()
