"""Actions-only config expansion witness. Never starts or queries a daemon."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
import tomllib


# Observed in exact-head Actions 42116989500, not a production artifact approval.
CONTAINERD = "/usr/bin/containerd"
CONTAINERD_SHA256 = "fc185d75979d92a4f8de99b76293dca7fe81142e9c5fd01d7da59f786f0fc8d1"
CONTAINERD_SOURCE = "b7a25261e029d68978bbf290df0a62fc819b3c51"
DEFAULT_IMPORT = "/etc/containerd/conf.d/*.toml"
RESTART = "io.containerd.monitor.container.v1.restart"
DISABLED = [RESTART, "io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime",
            "io.containerd.grpc.v1.cri", "io.containerd.server.v1.grpc-tcp",
            "io.containerd.server.v1.debug", "io.containerd.server.v1.metrics"]
GRPC = "io.containerd.server.v1.grpc"
TTRPC = "io.containerd.server.v1.ttrpc"
LIMIT = 1024 * 1024


def config_bytes(root):
    root = str(root)
    if not re.fullmatch(r"/tmp/cpa-containerd-config\.[A-Za-z0-9_-]+", root):
        raise ValueError("not an exclusively allocated diagnostic root")
    return ("version = 4\n"
            f"root = {json.dumps(root + '/data')}\n"
            f"state = {json.dumps(root + '/state')}\n"
            f"temp = {json.dumps(root + '/temp')}\n"
            "imports = []\n"
            f"disabled_plugins = {json.dumps(DISABLED)}\n"
            f"[plugins.{json.dumps(GRPC)}]\n"
            f"address = {json.dumps(root + '/grpc.sock')}\n"
            f"[plugins.{json.dumps(TTRPC)}]\n"
            f"address = {json.dumps(root + '/ttrpc.sock')}\n").encode("ascii")


def validate_source(raw, root):
    # No caller-supplied imports/proxies/unknown keys can reach the native parser.
    if raw != config_bytes(root):
        raise ValueError("source configuration differs from the closed diagnostic template")
    return tomllib.loads(raw.decode("ascii"))


def validate_dump(raw, source):
    if not raw or len(raw) > LIMIT:
        raise ValueError("empty or oversized effective configuration")
    result = tomllib.loads(raw.decode("utf-8"))
    for key in ("version", "root", "state", "temp", "disabled_plugins"):
        if type(result.get(key)) is not type(source[key]) or result[key] != source[key]:
            raise ValueError("effective isolation field changed: " + key)
    # Pinned config.go merges slice defaults into the DISPLAY. LoadConfig only
    # traverses each input file's own imports. Never reuse this dump as a config:
    # doing so would turn the inherited display entry into an actual host import.
    if result.get("imports") != [DEFAULT_IMPORT] or source["imports"] != []:
        raise ValueError("unexpected import expansion/display")
    if result.get("proxy_plugins", {}) != {}:
        raise ValueError("unexpected external plugin endpoint")
    plugins = result.get("plugins")
    if not isinstance(plugins, dict) or RESTART in plugins:
        raise ValueError("disabled restart plugin present in effective display")
    for key in (GRPC, TTRPC):
        if not isinstance(plugins.get(key), dict):
            raise ValueError("missing explicit server plugin")
        if plugins[key].get("address") != source["plugins"][key]["address"]:
            raise ValueError("server endpoint drift")
    for key in ("grpc", "ttrpc", "metrics"):
        if result.get(key, {}) != {}:
            raise ValueError("legacy server settings appeared")
    return result


def binary_digest(fd):
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or
            before.st_mode & 0o022 or before.st_nlink != 1):
        raise ValueError("unprotected diagnostic executable")
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, LIMIT):
        digest.update(chunk)
    after = os.fstat(fd)
    stable = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                           info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if stable(before) != stable(after) or digest.hexdigest() != CONTAINERD_SHA256:
        raise ValueError("containerd executable does not match the retained CI observation")
    return digest.hexdigest()


def output_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.geteuid() == 0 or
            len(sys.argv) != 2 or not re.fullmatch(r"[0-9a-f]{40}", sys.argv[1])):
        raise ValueError("requires non-root disposable hosted Actions and exact source SHA")
    print("schema=host-recovery-offline-containerd-config-v1", flush=True)
    print("source_revision=" + sys.argv[1], flush=True)
    print("containerd_source_reference=" + CONTAINERD_SOURCE, flush=True)
    fd = os.open(CONTAINERD, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        print("containerd_sha256=" + binary_digest(fd), flush=True)
        with tempfile.TemporaryDirectory(prefix="cpa-containerd-config.") as directory:
            root = Path(directory)
            if root.stat().st_uid != os.geteuid() or stat.S_IMODE(root.stat().st_mode) != 0o700:
                raise ValueError("unprotected diagnostic directory")
            raw = config_bytes(root)
            source = validate_source(raw, root)
            path = root / "input.toml"
            path.write_bytes(raw)
            # Fixed config subcommand only. No shell, address flag, daemon RPC,
            # inherited runtime env or installation. Child output is file-capped.
            with (root / "dump.toml").open("w+b") as out, (root / "stderr").open("w+b") as err:
                result = subprocess.run([f"/proc/self/fd/{fd}", "--config", str(path), "config", "dump"],
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                    stdin=subprocess.DEVNULL, stdout=out, stderr=err, pass_fds=(fd,),
                    timeout=10, check=False, preexec_fn=output_limit)
                out.seek(0)
                dumped = out.read(LIMIT + 1)
                err.seek(0)
                diagnostic = err.read(LIMIT + 1)
            print("input_toml_begin\n" + raw.decode() + "input_toml_end", flush=True)
            print("dump_toml_begin\n" + dumped.decode("utf-8", errors="replace") + "dump_toml_end", flush=True)
            print("stderr_begin\n" + diagnostic.decode("utf-8", errors="replace") + "stderr_end", flush=True)
            if result.returncode != 0 or diagnostic:
                raise ValueError("offline config dump failed or emitted warnings")
            validate_dump(dumped, source)
            if path.read_bytes() != raw or binary_digest(fd) != CONTAINERD_SHA256:
                raise ValueError("diagnostic inputs changed")
            expected = {"input.toml", "dump.toml", "stderr"}
            if {item.name for item in root.iterdir()} != expected:
                raise ValueError("config expansion created runtime state")
            for name in ("data", "state", "temp", "grpc.sock", "ttrpc.sock"):
                if (root / name).exists():
                    raise ValueError("offline command created runtime resource")
            print("offline_config_expansion=pass", flush=True)
        if root.exists():
            raise ValueError("diagnostic directory cleanup failed")
        print("offline_config_cleanup=removed", flush=True)
    finally:
        os.close(fd)
    print("daemon_started=false\ndaemon_contact=false\nshim_task_options_qualified=false\n"
          "complete_fence_proven=false\nstart_allowed=false\nproduction_acceptance=false", flush=True)


if __name__ == "__main__":
    main()
