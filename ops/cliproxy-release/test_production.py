"""Exercise restart and rollback behind real HTTP and RESP listeners."""

from concurrent.futures import ThreadPoolExecutor
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from production import Gate, ReleaseError, dispatch, restart

BINARY = os.environ.get("CLIPROXY_FIXTURE_GATE")
CADDY = os.environ.get("CLIPROXY_FIXTURE_CADDY")
DIGEST = "a" * 64


def eventually(check):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except OSError:
            pass
        time.sleep(0.02)
    raise AssertionError("fixture readback timed out")


def local_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def probe(port, path="/"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def handle_one_request(self):
        if self.rfile.peek(1)[:1] == b"*":
            if self.rfile.read(14) == b"*1\r\n$4\r\nPING\r\n":
                self.wfile.write(b"+PONG\r\n")
            self.close_connection = False
            return
        super().handle_one_request()

    def do_GET(self):
        root, phase = self.server.root, self.server.phase
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", "26")
            self.end_headers()
            self.wfile.write(b"data: start\n\n")
            self.wfile.flush()
            eventually(lambda: (root / "finish").exists())
            self.wfile.write(b"data: [DONE]\n")
            self.wfile.flush()
            return
        if self.path == "/refresh":
            (root / "state" / "oauth").write_bytes(b"refreshed")
            (root / "state" / "kv").write_bytes(b"current")
        body = phase.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def backend():
    with http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[4])), Backend) as server:
        server.root = Path(sys.argv[2])
        server.phase = sys.argv[3]
        server.serve_forever()


class BindingFixture:
    def __init__(self, root):
        self.root = root
        self.children = []
        self.server = None
        self.backend_port = local_port()
        self.data_port = local_port()
        self.resp_port = local_port()
        self.switches = []
        self.writer_clear = True
        self.fail_candidate = False
        self.journal = root / "transaction.json"
        (root / "state").mkdir()
        (root / "state" / "oauth").write_bytes(b"original")
        (root / "state" / "kv").write_bytes(b"original")
        for phase in ("baseline", "candidate"):
            slot = root / phase
            slot.mkdir()
            (slot / "config").write_text(phase, encoding="ascii")
            (slot / "meta.so").write_text(phase, encoding="ascii")

    def spawn(self, *args, env=None):
        child = subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append(child)
        return child

    @staticmethod
    def stop(child):
        if child is not None:
            child.terminate()
            child.wait(timeout=5)

    def cleanup(self):
        for child in reversed(self.children):
            self.stop(child)

    def start_backend(self, phase):
        self.stop(self.server)
        self.server = self.spawn(sys.executable, "-ESB", __file__, "backend", str(self.root), phase, str(self.backend_port))
        eventually(lambda: probe(self.backend_port) == (200, phase.encode("ascii")))

    def proxy(self, name, port, target, resp=None):
        directory = self.root / name
        directory.mkdir(mode=0o700)
        if CADDY and name != "gate":
            config = directory / "caddy.json"
            config.write_text(json.dumps({
                "admin": {"disabled": True},
                "apps": {"http": {"servers": {
                    "fixture": {"listen": [f"127.0.0.1:{port}"], "routes": [{
                        "handle": [{"handler": "reverse_proxy", "flush_interval": -1,
                                    "upstreams": [{"dial": f"127.0.0.1:{target}"}]}],
                    }]},
                }}},
            }))
            self.spawn(CADDY, "run", "--config", str(config),
                       env=dict(os.environ, XDG_CONFIG_HOME=str(directory), XDG_DATA_HOME=str(directory)))
            eventually(lambda: probe(port)[0] == 200)
            return None
        sock = directory / "control"
        args = [BINARY, "-control", str(sock), "-listen", f"127.0.0.1:{port}", "-target", f"127.0.0.1:{target}"]
        if resp is not None:
            args += ["-resp", f"127.0.0.1:{resp}"]
        self.spawn(*args)
        gate = Gate(sock)
        eventually(lambda: gate.read()["closed"])
        gate.change(gate.read(), False)
        return gate

    def start(self):
        self.start_backend("baseline")
        self.gate = self.proxy("gate", self.data_port, self.backend_port, self.resp_port)
        self.paths = [local_port(), local_port(), self.data_port]
        self.proxy("public", self.paths[0], self.data_port)
        self.proxy("direct", self.paths[1], self.data_port)

    def __call__(self, verb, digest, phase):
        assert digest == DIGEST
        if verb == "quiescent" and not self.writer_clear:
            raise ReleaseError("fixture writer still active")
        if verb == "prepared":
            for name in ("config", "meta.so"):
                if (self.root / phase / name).read_text(encoding="ascii") != phase:
                    raise ReleaseError("fixture artifact drifted")
        if verb == "switch":
            self.switches.append(phase)
            self.start_backend(phase)
        if verb in ("incumbent", "ready"):
            if probe(self.backend_port) != (200, phase.encode("ascii")):
                raise ReleaseError("unexpected fixture incumbent")
            if verb == "ready" and phase == "candidate" and self.fail_candidate:
                raise ReleaseError("fixture candidate smoke failed")

    def run(self, action="deploy", seconds=3):
        restart(self.gate, self, self.journal, action, DIGEST, seconds)


@unittest.skipUnless(BINARY, "build the gate and set CLIPROXY_FIXTURE_GATE")
class LifecycleTests(unittest.TestCase):
    def setUp(self):
        # Keep the Unix socket path short enough for Linux sockaddr_un.
        root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="cpa-")))
        self.fixture = BindingFixture(root)
        self.addCleanup(self.fixture.cleanup)
        self.fixture.start()

    def streams(self):
        def stream(port):
            conn = self.enterContext(close_connection(port))
            conn.request("GET", "/stream")
            response = conn.getresponse()
            self.assertEqual(response.read(13), b"data: start\n\n")
            return response

        return [stream(port) for port in self.fixture.paths]

    def test_drain_restart_and_undo_keep_live_state(self):
        fixture = self.fixture
        streams = self.streams()
        with socket.create_connection(("127.0.0.1", fixture.resp_port), timeout=5) as keeper:
            keeper.sendall(b"*1\r\n$4\r\nPING\r\n")
            with keeper.makefile("rb") as response:
                self.assertEqual(response.readline(), b"+PONG\r\n")
            eventually(lambda: fixture.gate.read()["active"] == 4)
            with ThreadPoolExecutor(max_workers=1) as executor:
                release = executor.submit(fixture.run)
                eventually(lambda: fixture.gate.read()["closed"])
                self.assertEqual([probe(port)[0] for port in fixture.paths], [503, 503, 503])
                self.assertEqual(fixture.switches, [])
                (fixture.root / "finish").touch()
                for response in streams:
                    self.assertEqual(response.read(), b"data: [DONE]\n")
                eventually(lambda: fixture.gate.read()["active"] == 1)
                self.assertEqual(fixture.switches, [])
                keeper.shutdown(socket.SHUT_RDWR)
                release.result(timeout=5)
        self.assertEqual([probe(port) for port in fixture.paths], [(200, b"candidate")] * 3)
        self.assertEqual(probe(fixture.paths[0], "/refresh"), (200, b"candidate"))
        with self.assertRaises(ReleaseError):
            fixture.run()
        fixture.run("rollback")
        self.assertEqual([probe(port) for port in fixture.paths], [(200, b"baseline")] * 3)
        self.assertEqual(fixture.switches, ["candidate", "baseline"])
        self.assertEqual((fixture.root / "state" / "oauth").read_bytes(), b"refreshed")
        self.assertEqual((fixture.root / "state" / "kv").read_bytes(), b"current")

    def test_existing_keepalive_cannot_admit_again_while_closed(self):
        fixture = self.fixture
        with close_connection(fixture.data_port) as conn:
            conn.request("GET", "/")
            self.assertEqual(conn.getresponse().read(), b"baseline")
            first_socket = conn.sock
            self.assertIsNotNone(first_socket)
            state = fixture.gate.read()
            self.assertEqual(state["active"], 0)
            closed = fixture.gate.change(state, True)
            with self.assertRaises(ReleaseError):
                fixture.gate.change(state, True)
            conn.request("GET", "/")
            self.assertIs(conn.sock, first_socket)
            response = conn.getresponse()
            self.assertEqual(response.status, 503)
            response.read()
            self.assertEqual(fixture.gate.read()["active"], 0)
            fixture.gate.change(closed, False)

    def test_refuse_undrained_stream_or_writer(self):
        fixture = self.fixture
        streams = self.streams()
        with self.assertRaisesRegex(ReleaseError, "requests did not drain"):
            fixture.run(seconds=0.15)
        self.assertFalse(fixture.gate.read()["closed"])
        self.assertEqual(fixture.switches, [])
        self.assertFalse(fixture.journal.exists())
        (fixture.root / "finish").touch()
        for response in streams:
            self.assertEqual(response.read(), b"data: [DONE]\n")
        fixture.writer_clear = False
        with self.assertRaisesRegex(ReleaseError, "writer still active"):
            fixture.run()
        self.assertFalse(fixture.gate.read()["closed"])
        self.assertEqual(fixture.switches, [])

    def test_refuse_missing_rollback_before_admission_changes(self):
        fixture = self.fixture
        (fixture.root / "baseline" / "meta.so").unlink()
        with self.assertRaises(FileNotFoundError):
            fixture.run()
        self.assertFalse(fixture.gate.read()["closed"])
        self.assertEqual(fixture.switches, [])

    def test_candidate_failure_restores_original_and_reports_failure(self):
        fixture = self.fixture
        fixture.fail_candidate = True
        with self.assertRaisesRegex(ReleaseError, "incumbent was restored"):
            fixture.run()
        self.assertEqual(fixture.switches, ["candidate", "baseline"])
        self.assertEqual([probe(port) for port in fixture.paths], [(200, b"baseline")] * 3)

    def test_interruption_before_first_switch_can_reopen_exact_incumbent(self):
        fixture = self.fixture
        fixture.gate.change(fixture.gate.read(), True)
        fixture.run("rollback")
        self.assertFalse(fixture.gate.read()["closed"])
        self.assertEqual(fixture.switches, [])

    def test_interrupted_switch_resumes_undo_on_same_binding(self):
        fixture = self.fixture
        fixture.gate.change(fixture.gate.read(), True)
        fixture.journal.write_text(json.dumps({"digest": DIGEST, "phase": "changing"}))
        fixture.start_backend("candidate")
        fixture.run("rollback")
        self.assertEqual(fixture.switches, ["baseline"])
        self.assertEqual([probe(port) for port in fixture.paths], [(200, b"baseline")] * 3)


class close_connection:
    def __init__(self, port):
        self.conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)

    def __enter__(self):
        return self.conn

    def __exit__(self, *_):
        self.conn.close()


class DispatchTests(unittest.TestCase):
    def setUp(self):
        repo = "TogetherWeOwn/CLIProxyAPI"
        self.env = {
            "RELEASE_ACTION": "deploy", "BUNDLE_SHA256": DIGEST,
            "GITHUB_REPOSITORY": repo, "GITHUB_SHA": "f" * 40, "GITHUB_WORKFLOW_SHA": "f" * 40,
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": f"{repo}/.github/workflows/deploy-cliproxy-production.yml@refs/heads/main",
            "LIFECYCLE_HOST": "target.example.invalid", "LIFECYCLE_HOST_KEY": "ssh-ed25519 " + "A" * 68,
            "LIFECYCLE_SSH_KEY": "synthetic-identity",
        }

    def test_reject_unprotected_scope_or_malformed_inputs_before_ssh(self):
        for key, invalid in (
            ("GITHUB_REF", "refs/heads/other"),
            ("GITHUB_WORKFLOW_SHA", "b" * 40),
            ("RELEASE_ACTION", "deploy\nother"),
            ("LIFECYCLE_HOST", "-F/alternate"),
            ("LIFECYCLE_HOST_KEY", "ssh-ed25519 invalid\nkey"),
            ("BUNDLE_SHA256", "b" * 65),
        ):
            with self.subTest(key=key), patch.dict(os.environ, self.env | {key: invalid}, clear=True):
                with patch("production.subprocess.run") as ssh, self.assertRaises(ReleaseError):
                    dispatch()
                ssh.assert_not_called()

    def test_dispatch_uses_pinned_target_and_fixed_command(self):
        def ssh(argv, **options):
            identity = Path(argv[argv.index("-i") + 1])
            self.assertEqual(identity.stat().st_mode & 0o777, 0o600)
            self.assertEqual(identity.read_text(), "synthetic-identity\n")
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertEqual(argv[-4:], ["cliproxy-release", "deploy", "f" * 40, DIGEST])
            self.assertNotIn("LIFECYCLE_SSH_KEY", options["env"])
            return subprocess.CompletedProcess(argv, 0)

        with patch.dict(os.environ, self.env, clear=True), patch("production.subprocess.run", side_effect=ssh):
            dispatch()


if __name__ == "__main__":
    if sys.argv[1:2] == ["backend"]:
        backend()
    else:
        if CADDY and not shutil.which(CADDY):
            sys.exit("fixture Caddy executable is unavailable")
        unittest.main()
