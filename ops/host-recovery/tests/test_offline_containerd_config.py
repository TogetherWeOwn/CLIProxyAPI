"""Pure diagnostic config regressions, no containerd execution or daemon contact."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import offline_containerd_config as fixture


class OfflineContainerdConfigTests(unittest.TestCase):
    def setUp(self):
        self.root = Path("/tmp/cpa-containerd-config.synthetic")
        self.raw = fixture.config_bytes(self.root)
        self.source = fixture.validate_source(self.raw, self.root)
        self.dump = copy.deepcopy(self.source)
        self.dump["imports"] = [fixture.DEFAULT_IMPORT]

    def encoded(self, value):
        # Only the small source projection is serialized; native plugin defaults
        # are independently exercised by the separate hosted Actions step.
        def literal(item):
            if isinstance(item, dict):
                return "{" + ", ".join(json.dumps(k) + " = " + literal(v) for k, v in item.items()) + "}"
            return json.dumps(item)

        plugins = value.pop("plugins")
        result = "".join(key + " = " + literal(item) + "\n" for key, item in value.items())
        for key, settings in plugins.items():
            result += "[plugins." + json.dumps(key) + "]\n"
            result += "".join(name + " = " + json.dumps(item) + "\n" for name, item in settings.items())
        return result.encode()

    def check(self, value):
        return fixture.validate_dump(self.encoded(copy.deepcopy(value)), self.source)

    def test_explicit_v4_private_roots_and_server_plugins(self):
        self.check(self.dump)
        self.assertEqual(self.source["imports"], [])
        self.assertEqual(self.source["version"], 4)
        self.assertIn(fixture.RESTART, self.source["disabled_plugins"])
        self.assertNotIn("grpc", self.source)
        self.assertEqual(self.source["plugins"][fixture.GRPC]["address"], str(self.root / "grpc.sock"))

    def test_rejects_root_aliases_and_arbitrary_paths(self):
        for root in ("/", "/tmp/cpa-containerd-config.x/../x", "/tmp/other", "/run/containerd", "relative"):
            with self.subTest(root=root), self.assertRaises(ValueError):
                fixture.config_bytes(root)

    def test_imported_unknown_or_whitespace_modified_source_refused_before_execution(self):
        for raw in (self.raw.replace(b"imports = []", b'imports = ["/etc/containerd/config.toml"]'),
                    self.raw + b"\n", self.raw.replace(b"version = 4", b"version = 3"),
                    self.raw + b"unknown = true\n"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                fixture.validate_source(raw, self.root)

    def test_root_state_temp_version_or_disabled_policy_drift_refuses(self):
        for key in ("root", "state", "temp", "version", "disabled_plugins"):
            value = copy.deepcopy(self.dump)
            value[key] = [] if key == "disabled_plugins" else 3 if key == "version" else "/run/containerd"
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(value)

    def test_boolean_is_not_config_version(self):
        raw = self.encoded(copy.deepcopy(self.dump)).replace(b"version = 4", b"version = true")
        with self.assertRaises(ValueError):
            fixture.validate_dump(raw, self.source)

    def test_disabled_restart_cannot_reappear(self):
        self.dump["plugins"][fixture.RESTART] = {"interval": "10s"}
        with self.assertRaises(ValueError):
            self.check(self.dump)

    def test_each_server_endpoint_must_remain_private(self):
        for key in (fixture.GRPC, fixture.TTRPC):
            value = copy.deepcopy(self.dump)
            value["plugins"][key]["address"] = "/run/containerd/containerd.sock"
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(value)

    def test_missing_server_plugin_refuses(self):
        del self.dump["plugins"][fixture.TTRPC]
        with self.assertRaises(ValueError):
            self.check(self.dump)

    def test_inherited_import_display_is_not_silently_erased_or_reusable(self):
        for imports in ([], ["/tmp/other"], [fixture.DEFAULT_IMPORT, "/etc/other.toml"]):
            value = copy.deepcopy(self.dump)
            value["imports"] = imports
            with self.subTest(imports=imports), self.assertRaises(ValueError):
                self.check(value)
        with self.assertRaises(ValueError):
            fixture.validate_source(self.encoded(copy.deepcopy(self.dump)), self.root)

    def test_proxy_plugin_and_legacy_endpoint_refuse(self):
        for key, value in (("proxy_plugins", {"external": "unexpected"}), ("grpc", {"address": "unexpected"})):
            with self.subTest(key=key), self.assertRaises((ValueError, TypeError)):
                self.check(dict(self.dump, **{key: value}))

    def test_empty_oversized_duplicate_or_malformed_dump_refuses(self):
        for raw in (b"", b" " * (fixture.LIMIT + 1), b"root='x'\nroot='y'", b"version = ["):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                fixture.validate_dump(raw, self.source)

    def test_entrypoint_refuses_shared_host_without_opening_binary(self):
        with patch.dict(fixture.os.environ, {}, clear=True), patch.object(fixture.os, "open") as opened:
            with self.assertRaises(ValueError):
                fixture.main()
            opened.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
