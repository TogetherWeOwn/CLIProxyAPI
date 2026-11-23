"""Real Compose replacements with private synthetic images, services and mounts."""

from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

from compose_adapter import ComposeAdapter, Mount, Phase, docker, file_digest, location
from production import Gate, ReleaseError, UnixHTTP, restart
from staging_probe import check
from test_production import DIGEST, eventually, local_port

GATE = os.environ.get("CLIPROXY_FIXTURE_GATE")
BACKEND = os.environ.get("CLIPROXY_FIXTURE_COMPOSE_BACKEND")


@contextmanager
def request(root, path, payload=None):
    conn = UnixHTTP(root / "probe" / "backend.sock", timeout=30 if payload else 2)
    try:
        conn.request("GET" if payload is None else "POST", path,
                     body=None if payload is None else json.dumps(payload), headers={"Content-Type": "application/json"})
        with conn.getresponse() as response:
            yield response
    finally:
        conn.close()


def probe(root, phase):
    if not Gate(root / "gate.sock").read()["closed"]:
        raise ReleaseError("admission opened before readiness")
    check(lambda *args: request(root, *args), "synthetic-" + phase, "synthetic")


class Fixture:
    def __init__(self, root, stack, mode):
        self.root = root
        self.project = "compose-proof-" + hashlib.sha256(os.fsencode(root)).hexdigest()[:16]
        self.phases = {}
        self.binds = []
        self.journal = root / "journal.json"
        self.pending = root / "pending.json"
        self.gate = Gate(root / "gate.sock")
        # The landed gate fixture covers real ingress to the backend. Here its
        # control socket lets the actual controller fence the Compose transaction.
        target = f"127.0.0.1:{local_port()}"
        child = subprocess.Popen(
            [GATE, "-control", str(self.gate.socket_path), "-listen", "127.0.0.1:0", "-target", target],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        stack.addCleanup(self.stop, child)
        eventually(lambda: self.gate.read()["closed"])
        self.gate.change(self.gate.read(), False)
        for name in ("oauth", "kv", "probe"):
            state = root / name
            state.mkdir()
            self.binds.append(Mount(state, "/" + name, True, location(state)))
        for name in ("oauth", "kv"):
            (root / name / "state").write_text("original", encoding="ascii")
        executable = Path(BACKEND).read_bytes()
        for phase, version in (("baseline", "0.2.7"), ("candidate", "0.2.9")):
            self.make_phase(stack, phase, version, mode if phase == "candidate" else "normal", executable)
        baseline = self.phases["baseline"]
        keeper = root / "keeper.json"
        keeper.write_text(json.dumps({"services": {"keeper": {
            "image": baseline.image, "network_mode": "none", "command": ["/gateway", "keeper"],
        }}}), encoding="ascii")
        stack.addCleanup(self.cleanup)
        self.compose(keeper, "up", "-d", "--no-build", "--pull", "never")
        self.keeper = self.compose(keeper, "ps", "-q", "keeper").strip()
        self.adapter = self.bound_adapter(self.check_quiescence)
        self.compose(baseline.directory / "compose.yaml", "up", "-d", "--no-build", "--pull", "never")
        eventually(lambda: self.phase() == b"baseline")

    @staticmethod
    def stop(child):
        child.terminate()
        child.wait(timeout=5)

    def make_phase(self, stack, phase, version, mode, executable):
        archive = self.root / (phase + ".tar")
        with tarfile.open(archive, "w") as tar:
            for name, contents, permissions in (("gateway", executable, 0o755), ("phase", phase.encode(), 0o444)):
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode = len(contents), permissions
                tar.addfile(entry, io.BytesIO(contents))
            for name in ("sha256sum", "stat"):
                link = tarfile.TarInfo(name)
                link.type, link.linkname = tarfile.SYMTYPE, "/gateway"
                tar.addfile(link)
        tag = f"{self.project}:{phase}"
        image = docker("image", "import", "--change", "ENV PATH=/", str(archive), tag, timeout=25).strip().decode()
        stack.addCleanup(docker, "image", "rm", tag)
        directory = self.root / phase
        directory.mkdir()
        config = directory / "config.yaml"
        config.write_text(f"{phase} {version} {mode}", encoding="ascii")
        plugins = directory / "plugins"
        plugins.mkdir()
        plugin = plugins / f"meta-v{version}.so"
        plugin.write_text(phase, encoding="ascii")
        mounts = [*self.binds, Mount(config, "/config.yaml", False, location(config)),
                  Mount(plugins, "/plugins", False, location(plugins))]
        compose = directory / "compose.yaml"
        compose.write_text(json.dumps({"services": {"gateway": {
            "image": image, "command": ["/gateway"], "network_mode": "none",
            "restart": "no", "stop_grace_period": "1s",
            "volumes": [{"type": "bind", "source": str(mount.source), "target": mount.target,
                         "read_only": not mount.writable, "bind": {"create_host_path": False}} for mount in mounts],
        }}}), encoding="ascii")
        self.phases[phase] = Phase(
            directory, file_digest(compose, 65536), file_digest(config, 65536),
            {plugin.name: file_digest(plugin, 65536)}, image, hashlib.sha256(executable).hexdigest(), version,
        )

    def bound_adapter(self, check_quiescence=None):
        return ComposeAdapter(
            digest=DIGEST, phases=self.phases, project=self.project, project_directory=self.root, service="gateway",
            executable="/gateway", state_mounts=self.binds, config_target="/config.yaml", plugins_target="/plugins",
            pending=self.pending, gate=self.gate, check_quiescence=check_quiescence,
            probe=(sys.executable, "-ESB", __file__, "probe", str(self.root)),
        )

    def check_quiescence(self, digest, phase, state):
        # This assertion applies only to our namespace with no network, no
        # host writers, and no requests through the gate's synthetic listener.
        return digest == DIGEST and phase in self.phases and state["closed"] and state["active"] == 0

    def compose(self, file, *args):
        return docker("compose", "--project-name", self.project, "--project-directory", str(self.root),
                      "--env-file", "/dev/null", "-f", str(file), *args, timeout=15)

    def cleanup(self):
        ids = docker("container", "ls", "-aq", "--filter", f"label=com.docker.compose.project={self.project}").split()
        if ids:
            docker("container", "rm", "--force", *(item.decode("ascii") for item in ids), timeout=15)

    def phase(self):
        with request(self.root, "/healthz") as response:
            return response.read()

    def restart(self, action):
        restart(self.gate, self.adapter, self.journal, action, DIGEST)


@unittest.skipUnless(GATE and BACKEND, "build the fixture gate and Compose backend")
class ComposeTests(unittest.TestCase):
    def fixture(self, mode="normal"):
        directory = self.enterContext(tempfile.TemporaryDirectory(prefix="compose-proof-", dir="/tmp"))
        return Fixture(Path(directory), self, mode)

    def test_switch_and_stopped_rollback_preserve_state_and_keeper(self):
        host = self.fixture()
        baseline = host.adapter.container()["Id"]
        host.adapter("incumbent", DIGEST, "baseline")
        with self.assertRaisesRegex(ReleaseError, "not the expected phase"):
            host.adapter("incumbent", DIGEST, "candidate")
        host.restart("deploy")
        candidate = host.adapter.container()["Id"]
        self.assertNotEqual(candidate, baseline)
        self.assertEqual(host.phase(), b"candidate")
        self.assertFalse(host.gate.read()["closed"])
        with request(host.root, "/refresh", {}) as response:
            self.assertEqual(response.status, 204)
        docker("container", "stop", "--time", "1", candidate)
        host.adapter("incumbent", DIGEST, "candidate")
        host.restart("rollback")
        self.assertFalse(host.gate.read()["closed"])
        self.assertEqual(host.phase(), b"baseline")
        self.assertNotIn(host.adapter.container()["Id"], (baseline, candidate))
        self.assertEqual(host.compose(host.root / "keeper.json", "ps", "-q", "keeper").strip(), host.keeper)
        for name in ("oauth", "kv"):
            self.assertEqual((host.root / name / "state").read_text(encoding="ascii"), "newer")

    def test_preflight_refuses_library_drift_before_closing_or_replacing(self):
        host = self.fixture()
        initial = host.gate.read()
        baseline = host.adapter.container()["Id"]
        (host.phases["baseline"].directory / "plugins" / "unbound.so").touch()
        with self.assertRaisesRegex(ReleaseError, "release files"):
            host.restart("deploy")
        self.assertEqual(host.gate.read(), initial)
        self.assertEqual(host.adapter.container()["Id"], baseline)

    def test_unbound_verifier_and_uncertain_switch_fail_closed(self):
        host = self.fixture()
        baseline = host.adapter.container()["Id"]
        closed = host.gate.change(host.gate.read(), True)
        with self.assertRaisesRegex(ReleaseError, "verifier is unbound"):
            host.bound_adapter()("switch", DIGEST, "candidate")
        host.pending.write_text("{}", encoding="ascii")
        with self.assertRaisesRegex(ReleaseError, "needs reconciliation"):
            host.adapter("switch", DIGEST, "candidate")
        self.assertEqual(host.adapter.container()["Id"], baseline)
        self.assertEqual(host.gate.read(), closed)

    def test_gateway_health_has_deadline_before_reopening(self):
        host = self.fixture(mode="hang")
        start = time.monotonic()
        with self.assertRaisesRegex(ReleaseError, "candidate failed and the incumbent was restored"):
            host.restart("deploy")
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 25)
        self.assertLess(elapsed, 55)
        self.assertEqual(host.phase(), b"baseline")
        self.assertFalse(host.gate.read()["closed"])


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "probe":
        probe(Path(sys.argv[2]), sys.argv[5])
    else:
        unittest.main()
