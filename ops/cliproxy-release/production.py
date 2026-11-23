"""Protected dispatch and host-side restart transaction for one approved pair."""

import fcntl
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

SHA = r"[0-9a-f]{40}"
DIGEST = r"[0-9a-f]{64}"
ACTIONS = ("deploy", "rollback")
HOST_ROOT = Path("/etc/cliproxy-release")
STATE_ROOT = Path("/var/lib/cliproxy-release")
GATE_SOCKET = Path("/run/cliproxy-release/gate.sock")
DRAIN_SECONDS = 60
UNIT = "cliproxy-release"
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


class ReleaseError(Exception):
    pass


def matches(pattern, value):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def request(action, sha, digest):
    if action not in ACTIONS or not matches(SHA, sha) or not matches(DIGEST, digest):
        raise ReleaseError("invalid release request")
    return action, sha, digest


def read_json(path):
    with path.open("rb") as file:
        data = file.read(4097)
    if len(data) > 4096:
        raise ReleaseError("release record exceeds size limit")
    return json.loads(data)


def save_json(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as file:
        pending = Path(file.name)
        try:
            file.write(json.dumps(data).encode("ascii"))
            file.flush()
            os.fsync(file.fileno())
            os.replace(pending, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            pending.unlink(missing_ok=True)


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class Gate:
    def __init__(self, socket_path):
        self.socket_path = socket_path

    def read(self, method="GET", path="/status"):
        conn = UnixHTTP(self.socket_path, timeout=2)
        try:
            conn.request(method, path)
            response = conn.getresponse()
            data = response.read(1025)
            if response.status != 200 or len(data) > 1024:
                raise ReleaseError("gate state could not be verified")
            state = json.loads(data)
        finally:
            conn.close()
        if (type(state) is not dict or set(state) != {"generation", "epoch", "closed", "active"}
                or not matches(r"[0-9a-f]{32}", state["generation"])
                or type(state["epoch"]) is not int or not 0 <= state["epoch"] < 2**64
                or type(state["active"]) is not int or state["active"] < 0
                or type(state["closed"]) is not bool):
            raise ReleaseError("invalid gate state")
        return state

    @staticmethod
    def same(state, expected):
        return all(state[key] == expected[key] for key in ("generation", "epoch", "closed"))

    def change(self, state, closed):
        verb = "close" if closed else "open"
        result = self.read("POST", f"/{verb}/{state['generation']}/{state['epoch']}")
        if not self.same(result, dict(state, closed=closed, epoch=state["epoch"] + 1)):
            raise ReleaseError("gate transition could not be verified")
        return result

    def require(self, closed, *, empty):
        state = self.read()
        if not self.same(state, closed) or (empty and state["active"] != 0):
            raise ReleaseError("gate no longer confirms quiescence")
        return state

    def wait(self, closed, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if not self.require(closed, empty=False)["active"] and time.monotonic() < deadline:
                return
            time.sleep(0.05)
        raise ReleaseError("active requests did not drain")


class Adapter:
    """Only an installer-owned executable can resolve the local binding."""

    def __init__(self, executable):
        self.executable = executable

    def __call__(self, verb, digest, phase):
        if verb not in ("prepared", "incumbent", "quiescent", "switch", "ready") or phase not in ("baseline", "candidate"):
            raise ReleaseError("invalid lifecycle operation")
        result = subprocess.run(
            [str(self.executable), verb, digest, phase],
            check=False, env=SAFE_ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=75 if verb in ("switch", "ready") else 30,
        )
        if result.returncode:
            raise ReleaseError(f"binding refused {verb}")


def restart(gate, adapter, journal, action, digest, drain_seconds=DRAIN_SECONDS):
    """Change the approved pair under an exclusive host lock held by the caller."""
    prior = read_json(journal) if journal.exists() else None
    initial = gate.read()
    if action == "deploy":
        if prior is not None or initial["closed"]:
            raise ReleaseError("forward release requires an unused pair and open admission")
        source, target = "baseline", "candidate"
    else:
        source, target = "candidate", "baseline"
        if prior not in ({"digest": digest, "phase": "changing"}, {"digest": digest, "phase": "deployed"}):
            if not initial["closed"] or prior not in (None, {"digest": digest, "phase": "rolled_back"}):
                raise ReleaseError("rollback requires an attempted forward release")
            # A crash can leave the gate closed before the transaction reaches
            # its journal. Without a record, only verify and reopen baseline.
            adapter("incumbent", digest, target)
            adapter("ready", digest, target)
            gate.change(gate.require(initial, empty=False), False)
            return

    adapter("prepared", digest, target)
    if action == "deploy":
        adapter("prepared", digest, source)
    if not initial["closed"]:
        try:
            adapter("incumbent", digest, source)
        except ReleaseError:
            if action != "rollback" or prior["phase"] != "changing":
                raise
            # If an earlier recovery reopened baseline but did not finalize
            # the record, confirm that exact baseline and finish the record.
            adapter("incumbent", digest, target)
            adapter("ready", digest, target)
            save_json(journal, {"digest": digest, "phase": "rolled_back"})
            return

    closed = initial if initial["closed"] else gate.change(initial, True)
    try:
        gate.wait(closed, drain_seconds)
        adapter("quiescent", digest, target)
        if not initial["closed"]:
            adapter("incumbent", digest, source)
        if action == "deploy":
            save_json(journal, {"digest": digest, "phase": "changing"})
        gate.require(closed, empty=True)
    except (ReleaseError, OSError, ValueError, http.client.HTTPException, subprocess.SubprocessError):
        # No switch has started. Reopen only the gate this invocation closed,
        # after another incumbent check. If that cannot be verified, stay closed.
        if not initial["closed"]:
            adapter("incumbent", digest, source)
            gate.change(gate.require(closed, empty=False), False)
        raise

    try:
        adapter("switch", digest, target)
        adapter("ready", digest, target)
    except (ReleaseError, OSError, ValueError, http.client.HTTPException, subprocess.SubprocessError):
        if action == "deploy":
            # Quiescent includes checking that a failed/timed-out restart has
            # stopped changing the target before a second switch can start.
            adapter("quiescent", digest, source)
            gate.require(closed, empty=True)
            adapter("switch", digest, source)
            adapter("ready", digest, source)
            gate.change(gate.require(closed, empty=True), False)
            save_json(journal, {"digest": digest, "phase": "rolled_back"})
            raise ReleaseError("candidate failed and the incumbent was restored")
        raise

    gate.change(gate.require(closed, empty=True), False)
    save_json(journal, {"digest": digest, "phase": "deployed" if action == "deploy" else "rolled_back"})


def approved(sha, digest):
    return read_json(HOST_ROOT / "approved.json") == {"workflow_sha": sha, "bundle_sha256": digest}


def host(action, sha, digest):
    with (STATE_ROOT / "lock").open("ab") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not approved(sha, digest):
            raise ReleaseError("release pair is not approved on the target")
        restart(Gate(GATE_SOCKET), Adapter(HOST_ROOT / "adapter"), STATE_ROOT / (digest + ".json"), action, digest)


def submit():
    # The SSH account can invoke only this entrypoint. The forced command
    # never interprets client text as shell, a path, or systemd options.
    original = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    pattern = rf"cliproxy-release (deploy|rollback) ({SHA}) ({DIGEST})"
    match = re.fullmatch(pattern, original)
    if match is None:
        raise ReleaseError("invalid lifecycle command")
    action, sha, digest = request(*match.groups())
    # The installer grants access to precisely this root-owned helper, which
    # revalidates its input before starting a system-owned transaction.
    result = subprocess.run(
        ["/usr/bin/sudo", "-n", str(HOST_ROOT / "queue"), action, sha, digest],
        check=False, env=SAFE_ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=780,
    )
    if result.returncode:
        raise ReleaseError("target did not confirm the transaction")


def queue(action, sha, digest):
    if not approved(sha, digest):
        raise ReleaseError("release pair is not approved on the target")
    # No --pipe: the systemd unit remains owned by the host if SSH is lost.
    result = subprocess.run(
        ["/usr/bin/systemd-run", "--wait", "--quiet", "--collect", f"--unit={UNIT}",
         "--property=RuntimeMaxSec=720", "--property=Type=exec",
         "/usr/bin/python3", "-IB", str(HOST_ROOT / "production.py"), "host", action, sha, digest],
        check=False, env=SAFE_ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=750,
    )
    if result.returncode:
        raise ReleaseError("host transaction failed")


def dispatch():
    action, sha, digest = request(
        os.environ.get("RELEASE_ACTION"), os.environ.get("GITHUB_SHA"), os.environ.get("BUNDLE_SHA256"),
    )
    repo = "TogetherWeOwn/CLIProxyAPI"
    if any(os.environ.get(key) != value for key, value in {
        "GITHUB_REPOSITORY": repo,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": f"{repo}/.github/workflows/deploy-cliproxy-production.yml@refs/heads/main",
        "GITHUB_WORKFLOW_SHA": sha,
    }.items()):
        raise ReleaseError("production dispatch requires protected main")
    address = os.environ.get("LIFECYCLE_HOST", "")
    key = os.environ.get("LIFECYCLE_SSH_KEY", "")
    host_key = os.environ.get("LIFECYCLE_HOST_KEY", "")
    if (not matches(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", address)
            or not matches(r"ssh-ed25519 [A-Za-z0-9+/]{68}", host_key)
            or not 0 < len(key) <= 8192):
        raise ReleaseError("production lifecycle binding is missing or invalid")
    with tempfile.TemporaryDirectory(prefix="cliproxy-dispatch-") as directory:
        root = Path(directory)
        identity = root / "identity"
        identity.touch(mode=0o600)
        identity.write_text(key.rstrip("\n") + "\n", encoding="ascii")
        known = root / "known_hosts"
        known.write_text(f"cliproxy-lifecycle {host_key}\n", encoding="ascii")
        result = subprocess.run(
            ["/usr/bin/ssh", "-T", "-F", "/dev/null", "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=cliproxy-lifecycle",
             "-o", f"UserKnownHostsFile={known}", "-o", "GlobalKnownHostsFile=/dev/null",
             "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=10",
             "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
             "-i", str(identity), f"cliproxy-release@{address}",
             "cliproxy-release", action, sha, digest],
            check=False, env=SAFE_ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=800,
        )
        if result.returncode:
            raise ReleaseError("protected transaction not confirmed")


def main():
    match sys.argv[1:]:
        case ["dispatch"]:
            dispatch()
        case ["submit"]:
            submit()
        case ["queue", action, sha, digest]:
            queue(*request(action, sha, digest))
        case ["host", action, sha, digest]:
            host(*request(action, sha, digest))
        case _:
            raise ReleaseError("invalid lifecycle entry")


if __name__ == "__main__":
    try:
        main()
    except ReleaseError as error:
        sys.exit(str(error))
    except (OSError, ValueError, TypeError, http.client.HTTPException, subprocess.SubprocessError):
        sys.exit("release operation failed")
