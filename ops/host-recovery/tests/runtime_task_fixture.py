"""Hosted Actions only: dedicated containerd, real shim/task and kernel witnesses.

No Docker discovery, image pull, host-root bind mount or production authority.
The pinned runner tools are diagnostic bytes, not authenticated release artifacts.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from offline_containerd_config import CONTAINERD_SHA256, config_bytes
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host_recovery.broker_runtime import RuntimeDomain
from host_recovery.runtime_processes import RuntimeProcessWitness

# Same bytes and embedded clean VCS recorded in Actions 42121171382. Never repin
# from the current runner; drift refuses before any service/runtime operation.
PINS = {
    "/usr/bin/containerd": CONTAINERD_SHA256,
    "/usr/bin/ctr": "f0c5d12710e6980d7de93096fc24d858b610d6892f2f886f467df305fc6b21f4",
    "/usr/bin/containerd-shim-runc-v2": "ca4c4b5919655332666dda634338b826d73a12cdd3b6633627e95d1ab4bc138a",
    "/usr/bin/runc": "1248fee8f9a0dc5382f888990d669e2bd225045869b9246f848a1681161abc96",
}
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def emit(**fields):
    print(json.dumps(fields, sort_keys=True), flush=True)


def identity():
    require(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("CPA_RECOVERY_RUNTIME_TASK_TEST") == "1",
            "requires explicit disposable hosted Actions root fixture")
    run, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    require(all(re.fullmatch(r"[1-9][0-9]{0,19}", x) for x in (run, attempt)), "bounded run identity required")
    key = "r" + run + "a" + attempt
    return (Path("/tmp/cpa-containerd-config." + key), "cpa-runtime-fixture-" + key + ".service",
            "system-cparuntime" + key + ".slice")


def command(*args, check=True):
    result = subprocess.run(args, env=ENV, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12)
    require(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 1024 * 1024, "fixture output overflow")
    emit(argv=args, returncode=result.returncode, stdout=result.stdout.decode(errors="replace"),
         stderr=result.stderr.decode(errors="replace"))
    if check:
        require(result.returncode == 0, "fixture command failed")
    return result


def protected_bytes(path, *, limit=128 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and not before.st_mode & 0o022, "unprotected fixture input")
        blocks, count = [], 0
        while block := os.read(fd, min(1024 * 1024, limit + 1 - count)):
            count += len(block)
            require(count <= limit, "fixture input overflow")
            blocks.append(block)
        after = os.fstat(fd)
        def stable(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(stable(before) == stable(after) == stable(path.stat()), "fixture input changed")
        return b"".join(blocks), before
    finally:
        os.close(fd)


def tool_pins():
    for path, expected in PINS.items():
        raw, info = protected_bytes(Path(path))
        require(info.st_uid == info.st_gid == 0 and hashlib.sha256(raw).hexdigest() == expected,
                "runtime diagnostic pin drift: " + path)
        emit(runtime_tool=path, sha256=expected)


def show(unit, key):
    return command("/usr/bin/systemctl", "show", "--property=" + key, "--value", "--", unit).stdout.decode().strip()


def owned(root, unit, slice_name):
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "owned runtime directory unconfirmed")
    marker, _ = protected_bytes(root / "owner.json", limit=4096)
    require(json.loads(marker) == {"schema": "host-recovery-runtime-task-fixture-v1",
            "unit": unit, "slice": slice_name}, "fixture marker mismatch")


def open_domain(slice_name):
    cgroup = "/system.slice/" + slice_name
    require(show(slice_name, "ControlGroup") == cgroup, "fixture slice path mismatch")
    fd = os.open("/sys/fs/cgroup" + cgroup, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        return fd, RuntimeDomain(fd=fd, mount_root="/sys/fs/cgroup", cgroup=cgroup,
                                 device=info.st_dev, inode=info.st_ino)
    except BaseException:
        os.close(fd)
        raise


def cleanup():
    root, unit, slice_name = identity()
    if not os.path.lexists(root):
        require(show(unit, "LoadState") == "not-found"
                and not Path("/sys/fs/cgroup/system.slice", slice_name).exists(), "fixture root absent but resource remains")
        emit(runtime_cleanup="already-absent")
        return
    owned(root, unit, slice_name)
    loaded = show(unit, "LoadState") != "not-found"
    if loaded:
        require(show(unit, "Description") == "cpa-owned-runtime=" + root.name, "refuse unowned runtime unit")
    # The explicitly started slice remains available for descriptor-bound kill,
    # even when containerd exited. Do not infer task death from daemon death.
    cgroup = Path("/sys/fs/cgroup/system.slice", slice_name)
    if cgroup.exists():
        fd, domain = open_domain(slice_name)
        try:
            domain.kill(check=lambda: owned(root, unit, slice_name))
            until = time.monotonic() + 10
            while domain.populated():
                require(time.monotonic() < until, "owned runtime domain did not empty")
                select.select([], [], [], 0.02)
        finally:
            os.close(fd)
    if loaded:
        command("/usr/bin/systemctl", "stop", "--", unit)
        command("/usr/bin/systemctl", "reset-failed", "--", unit, check=False)
    command("/usr/bin/systemctl", "stop", "--", slice_name)
    require(not cgroup.exists(), "owned runtime cgroup retained")
    # Refuse recursive file cleanup while any runtime mount remains. No lazy
    # unmount, shared state deletion, prefix sweep or default-daemon cleanup.
    mounts = Path("/proc/self/mountinfo").read_text()
    require(str(root) not in mounts, "owned runtime mount remains; preserve evidence")
    owned(root, unit, slice_name)
    shutil.rmtree(root)
    require(not os.path.lexists(root), "owned runtime directory retained")
    emit(runtime_cleanup="removed", cgroup_removed=True, unit=unit)


def main(probe):
    root, unit, slice_name = identity()
    tool_pins()
    require(Path("/proc/1/comm").read_text().strip() == "systemd", "real system manager required")
    require(show(unit, "LoadState") == "not-found", "refuse an existing runtime unit")
    require(not Path("/sys/fs/cgroup/system.slice", slice_name).exists(), "refuse an existing runtime domain")
    require(len(str(root / "s")) <= 42, "private shim socket directory exceeds the pinned runtime limit")
    raw_probe, _ = protected_bytes(Path(probe), limit=16 * 1024 * 1024)
    # CGO_ENABLED=0 must produce ELF64 without an interpreter. Record the actual
    # built bytes and source SHA in Actions; no downloaded executable is used.
    require(raw_probe[:6] == b"\x7fELF\x02\x01", "static ELF64 probe required")
    import struct
    phoff = struct.unpack_from("<Q", raw_probe, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", raw_probe, 54)
    require(phsize >= 56 and phoff + phnum * phsize <= len(raw_probe), "probe ELF program headers invalid")
    require(all(struct.unpack_from("<I", raw_probe, phoff + i * phsize)[0] != 3
                for i in range(phnum)), "probe unexpectedly uses a dynamic interpreter")
    root.mkdir(mode=0o700)
    (root / "owner.json").write_text(json.dumps({"schema": "host-recovery-runtime-task-fixture-v1",
                                               "unit": unit, "slice": slice_name}))
    os.chmod(root / "owner.json", 0o600)
    emit(schema="host-recovery-runtime-task-fixture-v1", probe_sha256=hashlib.sha256(raw_probe).hexdigest())
    pidfds, domain_fd, witness = [], None, None
    try:
        rootfs = root / "rootfs"
        rootfs.mkdir(mode=0o700)
        (rootfs / "proc").mkdir()
        (rootfs / "dev").mkdir()
        (rootfs / "probe").write_bytes(raw_probe)
        os.chmod(rootfs / "probe", 0o500)
        # config_bytes is the source template, never the dump with its default
        # import display. Shim sockets MUST NOT fall back to /run/containerd/s.
        config = config_bytes(root) + ("[plugins.\"io.containerd.shim.v1.manager\"]\n"
                                      "socket_dir = " + json.dumps(str(root / "s")) + "\n").encode()
        (root / "input.toml").write_bytes(config)
        command("/usr/bin/systemctl", "start", "--", slice_name)
        domain_fd, domain = open_domain(slice_name)
        command("/usr/bin/systemd-run", "--unit=" + unit, "--slice=" + slice_name,
                "--description=cpa-owned-runtime=" + root.name, "--service-type=exec",
                "--property=Restart=no", "--property=KillMode=control-group",
                "--property=TimeoutStopSec=5s", "--property=RuntimeMaxSec=90s",
                "--property=LimitCORE=0", "--property=ProtectHome=yes",
                "--property=PrivateNetwork=yes", "--property=PrivateMounts=yes",
                "--property=InaccessiblePaths=-/run/containerd -/run/docker.sock -/var/lib/docker -/var/lib/containerd",
                "--", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LANG=C",
                "/usr/bin/containerd", "--config", str(root / "input.toml"))
        deadline = time.monotonic() + 45
        def current():
            owned(root, unit, slice_name)
            require(time.monotonic() < deadline, "fixture observation deadline exceeded")
        def ctr(*args, check=True):
            current()
            return command("/usr/bin/ctr", "--address", str(root / "grpc.sock"),
                           "--namespace", "cpa-fixture", *args, check=check)
        while not (root / "grpc.sock").exists():
            current()
            require(show(unit, "ActiveState") == "active", "dedicated containerd failed startup")
            select.select([], [], [], 0.02)
        ctr("version")
        plugins = ctr("plugins", "list").stdout.decode().splitlines()
        require(not any(line.split()[:2] == ["io.containerd.monitor.container.v1", "restart"]
                        for line in plugins), "independent restart monitor loaded")
        ctr("namespaces", "create", "cpa-fixture")
        require(ctr("containers", "list", "--quiet").stdout == b"", "fresh runtime contains an object")
        cgroup = domain.cgroup + "/task"
        spec = {"ociVersion": "1.0.2", "root": {"path": str(rootfs), "readonly": False},
                "process": {"terminal": False, "user": {"uid": 0, "gid": 0}, "args": ["/probe"],
                            "env": [], "cwd": "/", "noNewPrivileges": True,
                            "capabilities": {key: [] for key in ("bounding", "effective", "inheritable", "permitted", "ambient")}},
                "mounts": [{"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]},
                           {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "noexec", "mode=755"]}],
                "linux": {"cgroupsPath": cgroup,
                          "devices": [{"path": "/dev/null", "type": "c", "major": 1, "minor": 3,
                                       "fileMode": 0o666, "uid": 0, "gid": 0}],
                          "namespaces": [{"type": kind} for kind in ("pid", "mount", "ipc", "uts", "network")]}}
        (root / "spec.json").write_text(json.dumps(spec))
        ctr("containers", "create", "--config", str(root / "spec.json"),
            "--runtime", "io.containerd.runc.v2", "--runc-binary", "/usr/bin/runc",
            "--runc-root", str(root / "runc"), "probe")
        metadata = ctr("containers", "info", "probe").stdout
        emit(created_metadata_sha256=hashlib.sha256(metadata).hexdigest(), metadata_observed_before_task_start=True,
             durable_host_registration_implemented=False)
        ctr("tasks", "start", "--detach", "--null-io", "--pid-file", str(root / "task.pid"), "probe")
        while not (rootfs / "ready").exists():
            current()
            select.select([], [], [], 0.02)
        require((rootfs / "ready").read_bytes() == b"parent-and-child-ready\n", "task readiness mismatch")
        task_pid = int((root / "task.pid").read_text())
        task_members = [int(x) for x in Path("/sys/fs/cgroup" + cgroup, "cgroup.procs").read_text().splitlines()]
        require(task_pid in task_members and len(task_members) == 2, "actual task and child not both contained")
        daemon_pid = int(show(unit, "MainPID"))
        daemon_group = show(unit, "ControlGroup")
        require(daemon_group == domain.cgroup + "/" + unit and cgroup != daemon_group,
                "task must demonstrate separate daemon/task cgroups")
        # With these closed ctr options shim_cgroup is unset. Observe inheritance
        # rather than claiming the daemon's process ancestry contains every task.
        daemon_members = [int(x) for x in Path("/sys/fs/cgroup" + daemon_group, "cgroup.procs").read_text().splitlines()]
        shims = [pid for pid in daemon_members if Path("/proc/%d/exe" % pid).resolve() == Path("/usr/bin/containerd-shim-runc-v2")]
        require(len(shims) == 1 and daemon_pid in daemon_members and len(daemon_members) == 2,
                "one daemon and one actual pinned shim required")
        require((root / "s").is_dir() and any((root / "s").iterdir()), "private shim sockets missing")
        for pid in [daemon_pid, *shims, *task_members]:
            fd = os.pidfd_open(pid, 0)
            pidfds.append(fd)
            poller = select.poll()
            poller.register(fd, select.POLLIN)
            require(not poller.poll(0), "witness process already exited")
            membership = Path("/proc/%d/cgroup" % pid).read_text()
            require(membership in ("0::" + daemon_group + "\n", "0::" + cgroup + "\n"), "process escaped runtime domain")
            expected = (PINS["/usr/bin/containerd"] if pid == daemon_pid else
                        PINS["/usr/bin/containerd-shim-runc-v2"] if pid in shims else hashlib.sha256(raw_probe).hexdigest())
            # This is the kernel /proc executable link, bracketed by a live pidfd,
            # not an untrusted filesystem symlink or a reusable numeric PID.
            actual, size = hashlib.sha256(), 0
            with Path("/proc/%d/exe" % pid).open("rb") as source:
                while block := source.read(1024 * 1024):
                    size += len(block)
                    require(size <= 128 * 1024 * 1024, "observed executable overflow")
                    actual.update(block)
            require(actual.hexdigest() == expected and not poller.poll(0), "observed process executable drift or death")
            emit(pid=pid, executable=str(Path("/proc/%d/exe" % pid).resolve()),
                 executable_sha256=expected, membership=membership.strip())
        witness = RuntimeProcessWitness.capture(domain=domain, check=current)
        require(witness.count == 4, "runtime process inventory differs from the four witnessed roles")
        ctr("tasks", "list")
        ctr("namespaces", "list")
        # The source kernel primitive kills the dedicated domain, including the
        # real daemon, shim, task and TERM-ignoring child. No PID-number fallback.
        domain.kill(check=current)
        until = time.monotonic() + 10
        for fd in pidfds:
            poller = select.poll()
            poller.register(fd, select.POLLIN)
            require(bool(poller.poll(max(1, int((until - time.monotonic()) * 1000)))), "observed runtime process survived kill")
        witness.require_dead(check=current)
        require(not domain.populated(), "runtime domain not empty after witnessed deaths")
        tool_pins()
        require((root / "input.toml").read_bytes() == config, "runtime source config changed")
        emit(actual_daemon_shim_task_child_deaths=True, source_recursive_domain_kill=True,
             task_separate_from_daemon_cgroup=True, private_shim_sockets=True,
             complete_fence_proven=False, pending_drained=False, start_allowed=False,
             production_acceptance=False)
    except BaseException:
        try:
            command("/usr/bin/journalctl", "--no-pager", "--boot", "--lines=200", "--unit=" + unit, check=False)
        except Exception as err:
            emit(diagnostic_failure=type(err).__name__)
        raise
    finally:
        if witness is not None:
            witness.close()
        for fd in pidfds:
            os.close(fd)
        if domain_fd is not None:
            os.close(domain_fd)
        cleanup()


if __name__ == "__main__":
    if sys.argv[1:] == ["--cleanup"]:
        cleanup()
    else:
        require(len(sys.argv) == 2, "one explicit built probe required")
        main(sys.argv[1])
