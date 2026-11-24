"""Test the terminal adapter with local processes and a synthetic model endpoint."""

from contextlib import closing, contextmanager, ExitStack
import fcntl
import http.client
import http.server
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import launch_hold
from production import dispatch

SCRIPT = Path(__file__).resolve()
PYTHON = [sys.executable, "-ESB"]
LOOPBACK = "127.0.0.1"
WAIT = 8


class Model(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        assert self.path == "/message" and self.rfile.read(int(self.headers["Content-Length"])) == b"prompt"
        label = self.headers["X-Fixture"]
        self.server.requests.append(label)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"data: started\n")
        self.wfile.flush()
        if label == "pre-admitted":
            assert self.server.finish.wait(WAIT)
        self.wfile.write(b"data: [DONE]\n")


def synthetic_cli(port, label, kind):
    def prompt():
        with closing(http.client.HTTPConnection(LOOPBACK, int(port), timeout=WAIT)) as connection:
            connection.request("POST", "/message", b"prompt", {"X-Fixture": label})
            response = connection.getresponse()
            assert response.status == 200 and response.readline() == b"data: started\n"
            if kind == "once":
                print("started", flush=True)
            assert response.read() == b"data: [DONE]\n"
        print("terminal", flush=True)

    if kind == "once":
        prompt()
    elif kind == "killed":
        os.kill(os.getpid(), signal.SIGKILL)
    else:
        assert kind == "interactive"
        print("idle", flush=True)
        for line in sys.stdin:
            if line == "exit\n":
                return
            assert line == "prompt\n"
            prompt()


class Terminal:
    def __init__(self, stack, command):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, bufsize=0, start_new_session=True)
        self.finished = False
        stack.callback(self.close)

    def expect(self, line):
        stream = self.process.stdout
        assert select.select([stream], [], [], WAIT)[0], (self.process.args, line)
        assert stream.readline().decode().strip() == line, (self.process.args, line)

    def send(self, line):
        self.process.stdin.write((line + "\n").encode())

    def exited(self, code=0):
        stdout, stderr = self.process.communicate(timeout=WAIT)
        self.finished = True
        assert (self.process.returncode, stdout) == (code, b""), (self.process.returncode, stdout, stderr)

    def close(self):
        if not self.finished:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait(timeout=WAIT)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()

    def waits_on(self, lock):
        info = lock.stat()
        identity = f"{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino}"
        blocked = ["->", "FLOCK", "ADVISORY", "WRITE", str(self.process.pid), identity]
        deadline = time.monotonic() + WAIT
        while time.monotonic() < deadline:
            if any(line.split()[1:7] == blocked for line in Path("/proc/locks").read_text().splitlines()):
                return
            assert self.process.poll() is None, self.process.args
            threading.Event().wait(0.01)
        raise AssertionError("launcher did not queue on the hold lock")


def pause_hold(state):
    lock = launch_hold.locked

    @contextmanager
    def paused(directory):
        with lock(directory):
            print("hold owns lock", flush=True)
            assert sys.stdin.readline() == "commit\n"
            yield

    with patch("launch_hold.locked", paused):
        return launch_hold.main([state, "hold"])


class LaunchHoldTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.state = self.root / "state"
        self.lock = self.state / "lock"
        self.adapter = PYTHON + [str(SCRIPT.with_name("launch_hold.py")), str(self.state)]
        self.model = self.stack.enter_context(http.server.ThreadingHTTPServer((LOOPBACK, 0), Model))
        self.model.requests = []
        self.model.finish = threading.Event()
        threading.Thread(target=self.model.serve_forever, daemon=True).start()
        self.stack.callback(self.model.shutdown)
        self.stack.callback(self.model.finish.set)

    def control(self, action):
        return subprocess.run(self.adapter + [action], check=True, capture_output=True,
                              text=True, timeout=WAIT).stdout.strip()

    def status(self, phase, count):
        self.assertEqual(self.control("status"), f"{phase} {count} (unmanaged callers unverified)")

    def terminal(self, label, kind="once", *, unmanaged=False):
        child = PYTHON + [str(SCRIPT), "cli", str(self.model.server_port), label, kind]
        return Terminal(self.stack, child if unmanaged else self.adapter + ["run"] + child)

    def test_hold_wins_launch_race_and_leaves_recovery_available(self):
        self.status("open", 0)
        holder = Terminal(self.stack, PYTHON + [str(SCRIPT), "pause-hold", str(self.state)])
        holder.expect("hold owns lock")
        launcher = self.terminal("blocked")
        launcher.waits_on(self.lock)
        holder.send("commit")
        holder.exited()
        launcher.exited(os.EX_TEMPFAIL)
        self.status("held", 0)
        self.assertEqual(self.model.requests, [])

        repo, workflow = "TogetherWeOwn/CLIProxyAPI", "deploy-cliproxy-production.yml"
        sha, digest = "a" * 40, "b" * 64
        for action in ("adopt", "deploy", "rollback", "undo-adoption"):
            environment = {
                "RELEASE_ACTION": action, "BUNDLE_SHA256": digest, "GITHUB_SHA": sha,
                "GITHUB_WORKFLOW_SHA": sha, "GITHUB_REPOSITORY": repo,
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                "GITHUB_WORKFLOW_REF": f"{repo}/.github/workflows/{workflow}@refs/heads/main",
                "LIFECYCLE_HOST": "target.example.invalid", "LIFECYCLE_SSH_KEY": "synthetic",
                "LIFECYCLE_HOST_KEY": "ssh-ed25519 " + "A" * 68,
            }
            with patch.dict(os.environ, environment, clear=True), patch("production.subprocess.run") as ssh:
                ssh.return_value = subprocess.CompletedProcess([], 0)
                dispatch()
                ssh.assert_called_once()
                argv = ssh.call_args.args[0]
                self.assertIn("StrictHostKeyChecking=yes", argv)
                self.assertEqual(argv[-4:], ["cliproxy-release", action, sha, digest])
        self.status("held", 0)

    def test_simultaneous_starts_normal_exit_interactive_and_undo(self):
        self.status("open", 0)
        with self.lock.open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            one_shot = self.terminal("pre-admitted")
            session = self.terminal("interactive with spaces", "interactive")
            one_shot.waits_on(self.lock)
            session.waits_on(self.lock)
        one_shot.expect("started")
        session.expect("idle")
        self.status("open", 2)
        self.control("hold")
        self.status("held", 2)
        self.terminal("blocked").exited(os.EX_TEMPFAIL)
        self.model.finish.set()
        one_shot.expect("terminal")
        one_shot.exited()
        self.status("held", 1)
        session.send("prompt")
        session.expect("terminal")
        self.status("held", 1)
        session.send("exit")
        session.exited()
        self.status("held", 0)
        self.control("undo")
        fresh = self.terminal("after undo")
        fresh.expect("started")
        fresh.expect("terminal")
        fresh.exited()
        self.status("open", 0)
        self.assertEqual(self.model.requests, ["pre-admitted", "interactive with spaces", "after undo"])

    def test_unmanaged_process_and_retired_traffic_refuse_fixture_clearance(self):
        old = self.terminal("unmanaged", "interactive", unmanaged=True)
        old.expect("idle")
        self.control("hold")

        def verdict():
            self.status("held", 0)
            if self.model.requests:
                return "unexpected traffic"
            if old.process.poll() is None:
                return "unmanaged process"
            return "fixture idle"

        self.assertEqual(verdict(), "unmanaged process")
        old.send("prompt")
        old.expect("terminal")
        old.send("exit")
        old.exited()
        self.assertEqual(self.model.requests, ["unmanaged"])
        self.assertEqual(verdict(), "unexpected traffic")

    def test_signal_exit_leaves_unresolved_record_across_undo(self):
        self.terminal("abnormal", "killed").exited(128 + signal.SIGKILL)
        self.control("hold")
        self.status("held", 1)
        self.control("undo")
        self.status("open", 1)

    def test_ordinary_exit_code_is_preserved(self):
        Terminal(self.stack, self.adapter + ["run"] + PYTHON + ["-c", "raise SystemExit(7)"]).exited(7)
        self.status("open", 0)

    def test_rejects_symlink_state_without_writing_to_target(self):
        target = self.root / "other"
        target.mkdir(mode=0o700)
        self.state.symlink_to(target, target_is_directory=True)
        Terminal(self.stack, self.adapter + ["hold"]).exited(1)
        self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    if sys.argv[1:2] == ["cli"]:
        synthetic_cli(*sys.argv[2:])
    elif sys.argv[1:2] == ["pause-hold"]:
        sys.exit(pause_hold(sys.argv[2]))
    else:
        unittest.main()
