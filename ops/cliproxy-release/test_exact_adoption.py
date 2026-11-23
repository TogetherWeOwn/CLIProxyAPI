"""Rehearse the approved baseline image with synthetic auth, KV and upstream."""

from contextlib import ExitStack, contextmanager
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import stat
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from adoption import transact
from adoption_ingress import IngressFile
from compose_adapter import ComposeAdapter, Mount, Phase, docker, file_digest, location
from legacy_compose import LegacyCompose
from production import Gate, ReleaseError, read_json
from staging import CONFIG, unpack, verify_image
from test_production import eventually, local_port, probe

GATE = os.environ.get("CLIPROXY_FIXTURE_GATE")
BUNDLE = os.environ.get("CLIPROXY_FIXTURE_BUNDLE")
BUNDLE_SHA = os.environ.get("CLIPROXY_FIXTURE_BUNDLE_SHA256")
CADDY = os.environ.get("CLIPROXY_FIXTURE_CADDY")


def nsenter(container):
    namespace = docker("inspect", "--format", "{{.NetworkSettings.SandboxKey}}", container).decode().strip()
    if not namespace or not namespace.startswith(("/run/docker/netns/", "/var/run/docker/netns/")):
        raise ReleaseError("fixture namespace is unavailable")
    return ["sudo", "-n", "nsenter", f"--net={namespace}", "--setuid", str(os.getuid()),
            "--setgid", str(os.getgid()), "--", sys.executable, "-ESB", __file__]


@contextmanager
def http_connection(address, port=19237):
    connection = http.client.HTTPConnection(address, port, timeout=2)
    try:
        yield connection
    finally:
        connection.close()


def smoke(expected_text):
    import http.server
    import threading
    from staging_probe import CLIENT_MODEL, Upstream, check, request

    with http.server.ThreadingHTTPServer(("127.0.0.1", 19238), Upstream) as upstream:
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        check(request, CLIENT_MODEL, expected_text)
        upstream.shutdown()


def mount(source, target, writable=True):
    return Mount(source, target, writable, location(source))


class Proxy:
    def __init__(self, root, name, backend, ingress, stack):
        directory = root / name
        directory.mkdir()
        self.address = f"127.0.0.1:{local_port()}"
        self.port, self.resp_port = local_port(), local_port()
        self.callbacks = {port: local_port() for port in (1455, 8085, 11451, 51121, 54545)}
        live, original, adopted = (directory / name for name in ("live.json", "old.json", "new.json"))
        for file, upstream in ((original, backend), (adopted, f"unix/{ingress}")):
            file.write_text(json.dumps({
                "admin": {"listen": self.address},
                "apps": {"http": {"servers": {"fixture": {"listen": [f"127.0.0.1:{self.port}"], "routes": [
                    {"handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": upstream}],
                                 "headers": {"request": {"set": {
                                     "X-CLIProxy-Client-IP": ["{http.request.remote.host}"],
                                 }}}}]},
                ]}}}},
            }))
        shutil.copyfile(original, live)
        info = live.stat()
        self.binding = IngressFile(live, original, adopted, file_digest(original, 65536),
                                   file_digest(adopted, 65536), (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)))
        self.env = dict(os.environ, XDG_CONFIG_HOME=str(directory), XDG_DATA_HOME=str(directory))
        child = subprocess.Popen([CADDY, "run", "--config", str(live)], env=self.env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(stop, child)
        eventually(lambda: self.status() == 200)

    def apply(self, *, adopted):
        self.binding.apply(adopted=adopted)
        subprocess.run([CADDY, "reload", "--address", self.address, "--config", str(self.binding.live)],
                       env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=True)
        self.binding.verify(adopted=adopted)

    def status(self):
        return probe(self.port, "/healthz")[0]


def stop(child):
    if child.poll() is None:
        child.terminate()
        child.wait(timeout=5)


class ExactFixture:
    def __init__(self, root, stack, spec, libraries, *, reject_ready):
        self.root = root
        self.gate = Gate(root / "gate.sock")
        trusted = root / "trusted"
        trusted.mkdir()
        trusted.chmod(0o2750)
        self.ingress = trusted / "ingress.sock"
        self.journal = root / "adoption.json"
        self.release = root / "release.json"
        self.closed = False
        self.reject_ready = reject_ready
        self.front = None
        self.project = "adoption-proof-" + hashlib.sha256(os.fsencode(root)).hexdigest()[:14]
        self.port, self.resp_port = local_port(), local_port()
        self.callbacks = {port: local_port() for port in (1455, 8085, 11451, 51121, 54545)}
        self.network = self.project
        docker("network", "create", "--internal", self.network)
        stack.callback(docker, "network", "rm", self.network)
        ipam = json.loads(docker("network", "inspect", "--format", "{{json .IPAM.Config}}", self.network))
        subnet = ipaddress.ip_network(ipam[0]["Subnet"])
        self.legacy_ip, self.pinned_ip = str(subnet[10]), str(subnet[11])
        self.image = spec["image"]
        self.tag = self.project + ":legacy"
        docker("tag", self.image, self.tag)
        stack.callback(docker, "image", "rm", self.tag)
        stack.callback(self.cleanup)
        self.auth = root / "auth"
        self.auth.mkdir()
        self.auth_file = self.auth / "meta.json"
        self.auth_file.write_text(json.dumps({
            "type": "meta-muse", "auth_kind": "oauth", "email": "fixture@example.invalid",
            "disabled": False, "access_token": "staging-meta",
            "base_url": "http://127.0.0.1:19238/meta",
        }))
        self.kv = self.auth / "kv.db"
        logs = root / "logs"
        logs.mkdir()
        stable = [mount(self.auth, "/state/auths"), mount(logs, "/fixture-logs")]
        legacy_config, legacy_plugins, _ = self.make_plan(root, stable, self.tag, libraries, legacy=True)
        pinned = root / "baseline"
        pinned.mkdir()
        config, plugins, compose = self.make_plan(pinned, stable, self.image, libraries)
        phase = Phase(pinned, file_digest(compose, 65536), file_digest(config.source, 65536),
                      {path.name: file_digest(path, 768 * 1024 * 1024) for path in libraries.iterdir()},
                      self.image, spec["executable"], spec["meta"])
        self.engine = ComposeAdapter(
            digest=BUNDLE_SHA, phases={"baseline": phase, "candidate": phase}, project=self.project,
            project_directory=root, service="gateway", executable="/CLIProxyAPI/CLIProxyAPI",
            state_mounts=stable, config_target=config.target, plugins_target=plugins.target,
            pending=root / "pending.json", gate=self.gate, probe=("bound-fixture-probe",),
            check_quiescence=lambda *_: self.closed,
        )
        self.engine.compose(self, "up", "--detach", "--no-deps", "--no-build", "--pull", "never", "gateway")
        incumbent = self.engine.container()
        self.run_probe(incumbent["Id"])
        self.consume_usage(self.legacy_ip, 19237)
        self.check_callback(self.legacy_ip, 19237, 1455)
        self.authorized = incumbent["Id"]
        self.proxies = [Proxy(root, name, f"{self.legacy_ip}:19237", self.ingress, stack)
                        for name in ("host-caddy", "direct-caddy")] if CADDY else []
        service_hash = self.engine.compose(self, "config", "--hash", "gateway").decode().split()[1]
        self.legacy = LegacyCompose(
            self.engine, root, file_digest(root / "compose.yaml", 65536), service_hash, self.tag,
            file_digest(legacy_config.source, 65536), legacy_config, legacy_plugins, Path("linux/amd64"),
            frozenset({self.network}), incumbent["HostConfig"]["PortBindings"], self.authorized,
            incumbent["State"]["StartedAt"], self.kv, location(self.kv), root / "restore-pending.json",
        )

    @property
    def directory(self):
        return self.root

    def make_plan(self, directory, stable, image, libraries, *, legacy=False):
        config = directory / "config.yaml"
        config.write_bytes(CONFIG.replace(b'host: "127.0.0.1"', b'host: ""').replace(
            b"remote-management:\n", b"usage-statistics-enabled: true\nremote-management:\n"
            b"  allow-remote: true\n"
            b"  secret-key: '$2b$04$5Qxe5k3.BinaEnnuLiAHUeggZXMnTTLUN8PXYDNK1XsUUaqv2AmTC'\n",
        ))
        plugin_root = directory / "plugins"
        library_path = plugin_root / "linux" / "amd64" if legacy else plugin_root
        shutil.copytree(libraries, library_path)
        plugin_target = "/plugins" if legacy else "/plugins/linux/amd64"
        release_mounts = [mount(config, "/CLIProxyAPI/config.yaml", legacy), mount(plugin_root, plugin_target, legacy)]
        compose = directory / "compose.yaml"
        compose.write_text(json.dumps({
            "networks": {"fixture": {"name": self.network, "external": True}},
            "services": {"gateway": {
                "image": image, "entrypoint": ["/CLIProxyAPI/CLIProxyAPI"],
                "command": ["-local-model", "-config", "/CLIProxyAPI/config.yaml"],
                "user": f"{os.getuid()}:{os.getgid()}", "environment": {"HOME": "/state"},
                "ports": [f"127.0.0.1:{self.port}:19237", *[
                    f"127.0.0.1:{listen}:{port}" for port, listen in self.callbacks.items()
                ]] if legacy else [],
                "networks": {"fixture": {"ipv4_address": self.legacy_ip if legacy else self.pinned_ip}},
                "volumes": [{"type": "bind", "source": str(item.source), "target": item.target,
                             "read_only": not item.writable, "bind": {"create_host_path": False}}
                            for item in [*stable, *release_mounts]],
            }},
        }))
        return *release_mounts, compose

    def run_probe(self, container, *, reject=False):
        subprocess.run([*nsenter(container), "probe", "rejected" if reject else "stage-complete"], timeout=25, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def check_callback(self, address, port, callback_port):
        headers = {"Authorization": "Bearer fixture-management"}
        with http_connection(address, port) as connection:
            connection.request("GET", "/v0/management/codex-auth-url?is_webui=true", headers=headers)
            response = connection.getresponse()
            if response.status != 200:
                raise AssertionError("synthetic OAuth session could not start")
            state = json.loads(response.read(16384))["state"]
        query = urlencode({"state": state, "error": "denied"})
        try:
            with http_connection(address, callback_port) as connection:
                connection.request("GET", "/auth/callback?" + query)
                response = connection.getresponse()
                if response.status != 302 or "error=denied" not in response.getheader("Location", ""):
                    raise AssertionError("dynamic OAuth listener did not redirect")
        finally:
            with http_connection(address, port) as connection:
                connection.request("DELETE", "/v8/management/oauth/session?" + urlencode({"state": state}),
                                   headers=headers)
                response = connection.getresponse()
                if response.status != 200 or not json.loads(response.read(16384))["cancelled"]:
                    raise AssertionError("synthetic OAuth session could not be canceled")

        def finished():
            try:
                with http_connection(address, callback_port) as connection:
                    connection.request("GET", "/auth/callback")
                    return connection.getresponse().status == 502
            except ConnectionRefusedError:
                return True

        eventually(finished)

    def consume_usage(self, address, port):
        def send(*parts):
            command = f"*{len(parts)}\r\n".encode() + b"".join(
                f"${len(part)}\r\n".encode() + part + b"\r\n" for part in parts
            )
            connection.sendall(command)
            return reader.readline(128)

        with socket.create_connection((address, port), timeout=2) as connection, connection.makefile("rb") as reader:
            if send(b"AUTH", b"fixture-management") != b"+OK\r\n":
                raise AssertionError("synthetic Keeper authentication failed")

            def pop():
                header = send(b"RPOP", b"usage")
                if header == b"$-1\r\n":
                    return False
                if not header.startswith(b"$") or not 0 < int(header[1:]) < 65536:
                    raise AssertionError("unexpected usage queue response")
                record = json.loads(reader.read(int(header[1:])))
                if reader.read(2) != b"\r\n":
                    raise AssertionError("invalid usage record framing")
                return bool(record)

            eventually(pop)
            while pop():
                pass

    def cleanup(self):
        if self.front and self.front.poll() is None:
            self.front.terminate()
            self.front.wait(timeout=5)
        ids = docker("container", "ls", "--all", "--quiet", "--filter",
                     f"label=com.docker.compose.project={self.project}").decode().splitlines()
        if ids:
            docker("container", "rm", "--force", *ids)

    def adapter(self, verb, digest, phase, *, fence=None):
        if verb != "ready":
            self.engine(verb, digest, phase, fence=fence)
            return
        from compose_adapter import command
        with patch("compose_adapter.command", side_effect=lambda *argv, **opts:
                   self.run_probe(argv[1], reject=self.reject_ready) if argv[0] == "bound-fixture-probe" else command(*argv, **opts)):
            self.engine(verb, digest, phase)

    def site(self, verb, digest, binding):
        try:
            self.site_operation(verb, digest, binding)
        except AssertionError as error:
            # The production Site wrapper converts a failed adapter command
            # into ReleaseError so that the controller can run undo.
            raise ReleaseError(f"disposable site operation failed: {verb}") from error

    def site_operation(self, verb, digest, binding):
        # The disposable project and its synthetic clients are private to the
        # test. No shared host listener, client, writer or queue is in scope.
        assert digest == BUNDLE_SHA and binding == "e" * 64
        if verb == "legacy":
            self.legacy.read(original=True)
        elif verb == "isolate":
            self.legacy.read(original=True)
            self.closed = True
            docker("container", "stop", self.authorized)
            self.front = subprocess.Popen(
                [GATE, "-control", str(self.gate.socket_path), "-listen", f"127.0.0.1:{self.port}",
                 "-target", f"{self.pinned_ip}:19237", "-trusted-ingress", str(self.ingress),
                 "-resp", f"127.0.0.1:{self.resp_port}", *[
                     option for port, listen in self.callbacks.items()
                     for option in ("-callback", f"127.0.0.1:{listen}={port}")
                 ]],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            eventually(lambda: self.gate.read()["closed"])
            for proxy in self.proxies:
                proxy.apply(adopted=True)
        elif verb == "isolated":
            assert self.closed and probe(self.port, "/healthz")[0] == 503
            assert all(proxy.status() == 503 for proxy in self.proxies)
        elif verb == "serving":
            if probe(self.port, "/healthz")[0] != 200 or any(proxy.status() != 200 for proxy in self.proxies):
                raise ReleaseError("fixture ingress did not resume")
            self.consume_usage("127.0.0.1", self.resp_port)
            self.check_callback("127.0.0.1", self.port, self.callbacks[1455])
        elif verb == "undo-isolate":
            self.closed = True
        elif verb == "restore":
            if self.front and self.front.poll() is None:
                self.front.terminate()
                self.front.wait(timeout=5)
            self.legacy.restore(lambda: self.closed)
            for proxy in self.proxies:
                proxy.apply(adopted=False)
        elif verb == "resume":
            item = self.legacy.read()
            self.run_probe(item["Id"])
            self.consume_usage(self.legacy_ip, 19237)
            assert all(proxy.status() == 200 for proxy in self.proxies)
            self.closed = False

    def run(self, action="adopt"):
        transact(self.gate, self.adapter, self.site, self.journal, self.release, action,
                 BUNDLE_SHA, "e" * 64)


@unittest.skipUnless(GATE and BUNDLE and BUNDLE_SHA, "set the gate and exact local bundle inputs")
class ExactTests(unittest.TestCase):
    def test_exact_tag_adoption_and_failed_validation_undo(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="adopt-exact-", dir="/tmp")))
            archive = Path(BUNDLE)
            self.assertEqual(file_digest(archive, 768 * 1024 * 1024), BUNDLE_SHA)
            release = unpack(archive, root)
            spec = release["baseline"]
            verify_image(root / "baseline.oci.tar", spec)
            if docker("info", "--format", "{{.Driver}}").strip() == b"overlay2":
                spec = dict(spec, image=spec["docker_config"])
            self.assertEqual(docker("image", "inspect", "--format", "{{.Id}}", spec["image"]).decode().strip(), spec["image"])

            for reject_at in (None, "ready", "callback"):
                with self.subTest(reject_at=reject_at), ExitStack() as fixture_stack:
                    directory = Path(fixture_stack.enter_context(tempfile.TemporaryDirectory(prefix="adopt-phase-", dir="/tmp")))
                    host = ExactFixture(directory, fixture_stack, spec, root / "baseline", reject_ready=reject_at == "ready")
                    old_state = location(host.auth), location(host.auth_file), location(host.kv)
                    if reject_at:
                        if reject_at == "callback":
                            failed_callback = fixture_stack.enter_context(
                                patch.object(host, "check_callback", side_effect=AssertionError("synthetic callback failure"))
                            )
                        with self.assertRaisesRegex(ReleaseError, "failed and legacy ingress was restored"):
                            host.run()
                        if reject_at == "callback":
                            failed_callback.assert_called_once()
                    else:
                        host.run()
                        adopted = host.engine.incumbent(host.engine.phases["baseline"])
                        self.assertNotEqual(adopted["Id"], host.authorized)
                        self.assertEqual(probe(host.port, "/healthz")[0], 200)
                        self.assertTrue(all(proxy.status() == 200 for proxy in host.proxies))
                        self.assertEqual(read_json(host.journal)["phase"], "adopted")
                        host.run("undo-adoption")
                    self.assertEqual(read_json(host.journal)["phase"], "undone")
                    with http_connection(host.legacy_ip) as connection:
                        connection.request("GET", "/healthz")
                        self.assertEqual(connection.getresponse().status, 200)
                    self.assertEqual((location(host.auth), location(host.auth_file), location(host.kv)), old_state)
                    self.assertEqual(host.legacy.read()["Image"], spec["image"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "probe":
        smoke(sys.argv[2])
    else:
        unittest.main()
