"""Hosted Actions only: fresh private Docker/runtime containment and cold restart.

Diagnostic byte pins are not release provenance. No default daemon, image pull,
production metadata, host bind mount or operational recovery authority is used.
"""
from contextlib import ExitStack
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import stat
import struct
import sys
import tarfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from offline_containerd_config import config_bytes
from runtime_task_fixture import PINS as RUNTIME_PINS
from runtime_task_fixture import command, emit, open_domain, protected_bytes, require, show, tool_pins
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host_recovery.durable import Rejected
from host_recovery.process_mounts import open_peer_mount_view
from host_recovery.runtime_processes import RuntimeProcessWitness

# Independently observed in the complete Actions 42129659342 inventory. Refuse
# drift; never repin from a runner, install tools or discover an ambient socket.
DOCKER_PINS = {
    "/usr/bin/dockerd": "b8644399e73e2c9b32ea3983daf3a9856a483a79196bea10c01977d2b021fe71",
    "/usr/bin/docker": "6435ff9214bf8e0931078fb0980809728cac0a54a526d4f28a26d3e48132b58d",
}
SCHEMA = "host-recovery-docker-runtime-fixture-v1"


def fixture_names(run, attempt):
    require(all(re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run, attempt)), "bounded run identity required")
    key = "r" + run + "a" + attempt
    short = hashlib.sha256(("docker:" + run + ":" + attempt).encode("ascii")).hexdigest()[:12]
    root = Path("/tmp/cpa-containerd-config.d" + short)
    units = {epoch: {role: "cpa-docker-" + role + "-" + key + "e" + str(epoch) + ".service"
                     for role in ("dockerd", "containerd")} for epoch in (1, 2)}
    return root, units, "system-cpadocker" + key + ".slice"


def identity():
    require(os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("CPA_RECOVERY_DOCKER_RUNTIME_TEST") == "1",
            "requires explicit disposable hosted Actions root fixture")
    return fixture_names(os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"])


def marker(units, slice_name):
    return {"schema": SCHEMA, "units": {str(k): v for k, v in units.items()}, "slice": slice_name}


def owned(root, units, slice_name):
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, "private Docker fixture root required")
    require(json.loads(protected_bytes(root / "owner.json", limit=4096)[0]) == marker(units, slice_name),
            "Docker fixture ownership mismatch")


def docker_config(root, slice_name):
    # Moby 6430e49: explicit external containerd bypasses daemon discovery;
    # ExecRoot also scopes runc and libnetwork. vfs avoids host overlay mounts.
    require(re.fullmatch(r"/tmp/cpa-containerd-config\.d[0-9a-f]{12}", str(root)), "fixed private Docker root required")
    require(re.fullmatch(r"system-cpadockerr[1-9][0-9]{0,19}a[1-9][0-9]{0,19}\.slice", slice_name),
            "fixed private Docker slice required")
    return {"data-root": str(root / "docker"), "exec-root": str(root / "exec"),
            "pidfile": str(root / "dockerd.pid"), "hosts": ["unix://" + str(root / "docker.sock")], "group": "0",
            "containerd": str(root / "grpc.sock"), "containerd-namespace": "cpa-docker",
            "containerd-plugins-namespace": "cpa-plugins", "storage-driver": "vfs",
            "exec-opts": ["native.cgroupdriver=systemd"], "cgroup-parent": slice_name,
            "runtimes": {"cpa": {"path": "/usr/bin/runc"}}, "default-runtime": "cpa",
            "live-restore": False, "bridge": "none", "iptables": False, "ip6tables": False,
            "ip-forward": False, "ip-masq": False, "userland-proxy": False, "log-driver": "none"}


def validate_info(info, root):
    require(info["DockerRootDir"] == str(root / "docker") and info["Driver"] == "vfs"
            and info["CgroupDriver"] == "systemd" and info["LiveRestoreEnabled"] is False
            and info["Swarm"]["LocalNodeState"] == "inactive", "effective Docker isolation mismatch")


def private_info(root, pid, current, deadline, *, unit, invocation):
    # The pinned CLI's formatted info returns success even when ServerErrors is
    # nonempty and also executes discovered client-plugin metadata helpers. Use
    # the exact fixture socket, not CLI formatting or any ambient/TCP endpoint.
    class PrivateDockerHTTP(http.client.HTTPConnection):
        def connect(self):
            current()
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(min(3, max(0.001, deadline - time.monotonic())))
            self.sock.connect(str(root / "docker.sock"))
            peer = struct.unpack("3i", self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(peer == (pid, 0, 0), "private Docker socket peer mismatch")
            def bound(*, deadline):
                current()
                return (show(unit, "MainPID") == str(pid) and show(unit, "InvocationID") == invocation
                        and show(unit, "ActiveState") == "active")
            with open_peer_mount_view(sock=self.sock, expected_peer=(pid, 0, 0),
                                      check=bound, clock=time.monotonic) as view:
                view._current(deadline)
                # Exercise the actual source kernel reader, not an injected
                # namespace result. Our private daemon must not authorize a
                # caller-namespace bind-source shortcut, even with a valid peer.
                with ExitStack() as sample:
                    try:
                        view._capture(sample)
                    except Rejected as err:
                        require(str(err) == "process-mount-view-mismatch", "unexpected daemon view refusal")
                    else:
                        raise AssertionError("private daemon accepted caller mount view")
                view._current(deadline)
                emit(socket_derived_daemon_pidfd_verified=True, caller_mount_view_rejected=True,
                     container_process_authenticated=False, start_allowed=False)
            current()
    connection = PrivateDockerHTTP("private-fixture")
    try:
        connection.request("GET", "/v1.48/info", headers={"Connection": "close"})
        response = connection.getresponse()
        raw = response.read(1024 * 1024 + 1)
        require(response.status == 200 and len(raw) <= 1024 * 1024, "private Docker info response invalid")
        current()
        result = json.loads(raw)
        validate_info(result, root)
        emit(private_docker_info=result, peer_pid=pid)
        return result
    except (FileNotFoundError, ConnectionRefusedError):
        # Only a not-yet-listening socket is a startup retry; malformed/effective
        # policy, peer drift, timeout or an actual server error fails the fixture.
        current()
        return None
    finally:
        connection.close()


def inspect_object(row, object_id, image_id, slice_name, *, running):
    require(row["Id"] == object_id and row["Image"] == image_id and row["Path"] == "/probe"
            and row["Args"] == [] and row["RestartCount"] == 0, "Docker object identity changed")
    host = row["HostConfig"]
    require(host["RestartPolicy"] == {"Name": "no", "MaximumRetryCount": 0}
            and host["AutoRemove"] is False and host["Privileged"] is False
            and not host["Binds"] and not row["Mounts"] and host["NetworkMode"] == "none"
            and host["CgroupParent"] == slice_name and host["Runtime"] == "cpa"
            and host["CapDrop"] == ["ALL"] and host["SecurityOpt"] == ["no-new-privileges"],
            "Docker object isolation/policy mismatch")
    require(row["State"]["Running"] is running and row["State"]["Restarting"] is False
            and (type(row["State"]["Pid"]) is int)
            and (row["State"]["Pid"] > 1 if running else row["State"]["Pid"] == 0),
            "Docker object running state mismatch")


def task_executable(root, object_id, pid, *, proc=Path("/proc")):
    # procfs executable link text is relative to the task's mount namespace, not
    # a host-side storage path. Bind the actual descriptors to Moby v28's VFS
    # mount-id mapping instead; matching bytes alone cannot prove that placement.
    require(re.fullmatch(r"[0-9a-f]{64}", object_id), "full Docker object identity required")
    mount_record = root / "docker/image/vfs/layerdb/mounts" / object_id / "mount-id"
    mount_id = protected_bytes(mount_record, limit=128)[0].decode("ascii")
    require(re.fullmatch(r"[0-9a-f]{64}", mount_id), "bounded VFS mount identity required")
    private_root = root / "docker/vfs/dir" / mount_id
    process = proc / str(pid)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    private_fd = os.open(private_root, flags)
    try:
        # Following these two procfs magic links is intentional. The caller holds
        # live pidfds and subsequently requires death of this exact process set.
        process_fd = os.open(process / "root", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            def same(first, second):
                return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)
            require(same(os.fstat(private_fd), os.fstat(process_fd)), "task root outside private Docker layer")
            raw, expected = protected_bytes(private_root / "probe")
            with (process / "exe").open("rb") as executable:
                actual = os.fstat(executable.fileno())
                mounted = os.stat("probe", dir_fd=process_fd, follow_symlinks=False)
                require(stat.S_ISREG(mounted.st_mode) and same(actual, mounted) and same(actual, expected),
                        "task executable differs from private mounted probe")
                require(executable.read(len(raw) + 1) == raw, "task executable bytes changed")
                require(same(os.fstat(executable.fileno()), os.stat("probe", dir_fd=private_fd,
                                                                 follow_symlinks=False)),
                        "private task executable replaced")
            require(same(private_root.stat(), os.fstat(private_fd))
                    and same((process / "root").stat(), os.fstat(process_fd))
                    and protected_bytes(mount_record, limit=128)[0] == mount_id.encode("ascii"),
                    "task root mapping changed")
            return raw
        finally:
            os.close(process_fd)
    finally:
        os.close(private_fd)


def rootfs_archive(raw_probe):
    # Only source-built static task bytes; no external image, tar extraction in
    # this process, registry credential, inherited build context or host binding.
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in ("dev", "proc", "sys", "etc", "tmp"):
            entry = tarfile.TarInfo(name)
            entry.type, entry.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(entry)
        entry = tarfile.TarInfo("probe")
        entry.mode, entry.size = 0o500, len(raw_probe)
        archive.addfile(entry, io.BytesIO(raw_probe))
    return data.getvalue()


def pins():
    tool_pins()
    for path, expected in DOCKER_PINS.items():
        raw, info = protected_bytes(Path(path))
        require(info.st_uid == info.st_gid == 0 and hashlib.sha256(raw).hexdigest() == expected,
                "Docker diagnostic pin drift: " + path)
        emit(runtime_tool=path, sha256=expected)


def validate_plugin_mount(raw):
    mounts = []
    for line in raw.splitlines():
        left, separator, right = line.partition(" - ")
        fields, filesystem = left.split(), right.split()
        if len(fields) >= 6 and fields[4] == "/run/docker":
            mounts.append((fields, separator, filesystem))
    require(len(mounts) == 1, "one private Docker plugin mount required")
    fields, separator, filesystem = mounts[0]
    require(separator and fields[3] == "/" and filesystem and filesystem[0] == "tmpfs"
            and {"rw", "nosuid", "nodev", "noexec"} <= set(fields[5].split(","))
            and not any(value.startswith("shared:") for value in fields[6:]),
            "Docker plugin root is not an isolated private tmpfs")


def start_unit(root, unit, slice_name, executable, config):
    require(show(unit, "LoadState") == "not-found", "refuse existing Docker fixture unit")
    inaccessible = "-/run/containerd -/run/docker.sock -/var/lib/docker -/var/lib/containerd"
    extra = []
    if executable == "/usr/bin/dockerd":
        # Moby's Linux plugin root ignores ExecRoot. Mask the shared path with
        # a fresh service-private tmpfs, never grant access to the host directory.
        # systemd v255 defaults to MS_SHARED inside a private namespace. Request
        # private propagation explicitly; PrivateMounts alone is not that policy.
        extra = ["--property=MountFlags=private",
                 "--property=TemporaryFileSystem=/run/docker:rw,nosuid,nodev,noexec,size=1M,mode=0700"]
    else:
        inaccessible += " -/run/docker"
    command("/usr/bin/systemd-run", "--unit=" + unit, "--slice=" + slice_name,
            "--description=cpa-owned-docker=" + root.name, "--service-type=exec",
            "--property=Restart=no", "--property=KillMode=control-group", "--property=Delegate=yes",
            "--property=TimeoutStopSec=5s", "--property=RuntimeMaxSec=120s", "--property=LimitCORE=0",
            "--property=ProtectHome=yes", "--property=PrivateNetwork=yes", "--property=PrivateMounts=yes",
            "--property=InaccessiblePaths=" + inaccessible, *extra,
            "--", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LANG=C", executable, "--config" if executable.endswith("containerd")
            else "--config-file", str(config))


def cleanup():
    root, units, slice_name = identity()
    all_units = [unit for epoch in units.values() for unit in epoch.values()]
    group = Path("/sys/fs/cgroup/system.slice", slice_name)
    if not os.path.lexists(root):
        require(not group.exists() and all(show(unit, "LoadState") == "not-found" for unit in all_units),
                "Docker root absent but fixture resources remain")
        emit(docker_cleanup="already-absent")
        return
    owned(root, units, slice_name)
    loaded = [unit for unit in all_units if show(unit, "LoadState") != "not-found"]
    for unit in loaded:
        require(show(unit, "Description") == "cpa-owned-docker=" + root.name, "refuse unowned Docker unit")
    if group.exists():
        fd, domain = open_domain(slice_name)
        try:
            domain.kill(check=lambda: owned(root, units, slice_name))
            deadline = time.monotonic() + 10
            while domain.populated():
                require(time.monotonic() < deadline, "Docker cleanup domain remains populated")
                select.select([], [], [], 0.02)
        finally:
            os.close(fd)
    for unit in loaded:
        command("/usr/bin/systemctl", "stop", "--", unit)
        command("/usr/bin/systemctl", "reset-failed", "--", unit, check=False)
    command("/usr/bin/systemctl", "stop", "--", slice_name)
    require(not group.exists(), "Docker fixture domain remains")
    require(str(root) not in Path("/proc/self/mountinfo").read_text(), "Docker fixture mount remains; preserve evidence")
    owned(root, units, slice_name)
    shutil.rmtree(root)
    require(not os.path.lexists(root), "Docker fixture root remains")
    emit(docker_cleanup="removed", cgroup_removed=True)


def main(probe):
    root, units, slice_name = identity()
    pins()
    require(Path("/proc/1/comm").read_text().strip() == "systemd", "real system manager required")
    require(not os.path.lexists(root) and not Path("/sys/fs/cgroup/system.slice", slice_name).exists()
            and all(show(unit, "LoadState") == "not-found" for epoch in units.values() for unit in epoch.values()),
            "fresh Docker resources required")
    raw_probe, _ = protected_bytes(Path(probe), limit=16 * 1024 * 1024)
    require(len(raw_probe) >= 64 and raw_probe[:6] == b"\x7fELF\x02\x01", "source-built ELF64 task required")
    phoff = struct.unpack_from("<Q", raw_probe, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", raw_probe, 54)
    require(phsize >= 56 and phnum > 0 and phoff + phnum * phsize <= len(raw_probe)
            and all(struct.unpack_from("<I", raw_probe, phoff + i * phsize)[0] != 3 for i in range(phnum)),
            "source-built task has an invalid header or dynamic interpreter")
    require(len(str(root / "s")) <= 42, "private shim socket path exceeds runtime bound")
    root.mkdir(mode=0o700)
    (root / "owner.json").write_text(json.dumps(marker(units, slice_name)))
    (root / "owner.json").chmod(0o600)
    fds, domain_fd, witness = [], None, None
    try:
        (root / "client").mkdir(mode=0o700)
        containerd = config_bytes(root) + ('[plugins."io.containerd.shim.v1.manager"]\nsocket_dir = '
                                         + json.dumps(str(root / "s")) + '\n').encode()
        (root / "input.toml").write_bytes(containerd)
        docker = docker_config(root, slice_name)
        (root / "docker.json").write_text(json.dumps(docker))
        archive = rootfs_archive(raw_probe)
        (root / "rootfs.tar").write_bytes(archive)
        emit(schema=SCHEMA, probe_sha256=hashlib.sha256(raw_probe).hexdigest(),
             rootfs_sha256=hashlib.sha256(archive).hexdigest(), docker_config=docker)
        command("/usr/bin/systemctl", "start", "--", slice_name)
        domain_fd, domain = open_domain(slice_name)
        deadline = time.monotonic() + 90
        def current():
            owned(root, units, slice_name)
            require(time.monotonic() < deadline, "Docker fixture deadline exceeded")
            domain.current()
        def docker_cmd(*args, check=True):
            current()
            return command("/usr/bin/docker", "--config", str(root / "client"),
                           "--host=unix://" + str(root / "docker.sock"), *args, check=check)
        def ctr(*args, check=True):
            current()
            return command("/usr/bin/ctr", "--address=" + str(root / "grpc.sock"), *args, check=check)
        def observe(object_id, image_id, running):
            row = json.loads(docker_cmd("container", "inspect", object_id).stdout)
            require(type(row) is list and len(row) == 1, "one exact Docker object required")
            inspect_object(row[0], object_id, image_id, slice_name, running=running)
            require(docker_cmd("container", "ls", "--all", "--no-trunc", "--format={{.ID}}").stdout
                    == (object_id + "\n").encode(), "whole Docker inventory changed")
            current()
            return row[0]
        def launch(epoch):
            start_unit(root, units[epoch]["containerd"], slice_name, "/usr/bin/containerd", root / "input.toml")
            while True:
                current()
                require(show(units[epoch]["containerd"], "ActiveState") == "active", "containerd startup failed")
                if (root / "grpc.sock").exists() and ctr("version", check=False).returncode == 0:
                    break
                select.select([], [], [], 0.02)
            plugins = ctr("plugins", "list").stdout.decode().splitlines()
            require(not any(line.split()[:2] == ["io.containerd.monitor.container.v1", "restart"] for line in plugins),
                    "containerd restart monitor loaded")
            start_unit(root, units[epoch]["dockerd"], slice_name, "/usr/bin/dockerd", root / "docker.json")
            # A stale socket is not readiness. Probe only the private explicit
            # endpoint, bound by the fixture's original absolute deadline.
            while True:
                current()
                require(show(units[epoch]["dockerd"], "ActiveState") == "active", "dockerd startup failed")
                pid = int(show(units[epoch]["dockerd"], "MainPID"))
                require(pid > 1, "private dockerd MainPID required")
                invocation = show(units[epoch]["dockerd"], "InvocationID")
                require(re.fullmatch(r"[0-9a-f]{32}", invocation), "private dockerd invocation required")
                if private_info(root, pid, current, deadline, unit=units[epoch]["dockerd"], invocation=invocation) is not None:
                    mountinfo = Path("/proc/%d/mountinfo" % pid).read_text()
                    emit(plugin_mountinfo=[line for line in mountinfo.splitlines()
                                           if len(line.split()) >= 6 and line.split()[4] == "/run/docker"])
                    require(os.readlink("/proc/%d/ns/mnt" % pid) != os.readlink("/proc/self/ns/mnt"),
                            "dockerd shares the fixture's host mount namespace")
                    validate_plugin_mount(mountinfo)
                    require(show(units[epoch]["dockerd"], "MainPID") == str(pid), "dockerd changed during readiness")
                    emit(private_docker_plugin_tmpfs_observed=True)
                    break
                select.select([], [], [], 0.02)
            # The root is 0700 even if the local daemon uses a broader socket
            # mode. No shared Docker group or inherited client config is used.
            require(stat.S_ISSOCK((root / "docker.sock").lstat().st_mode), "private Docker socket required")
        launch(1)
        require(docker_cmd("container", "ls", "--all", "--quiet").stdout == b"", "fresh Docker daemon contains objects")
        image_id = docker_cmd("image", "import", "--change=ENTRYPOINT [\"/probe\"]", str(root / "rootfs.tar")).stdout.decode().strip()
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "imported source image identity required")
        object_id = docker_cmd("container", "create", "--name=cpa-inert", "--restart=no", "--network=none",
                               "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64",
                               "--cgroup-parent=" + slice_name, "--runtime=cpa", "--log-driver=none", image_id).stdout.decode().strip()
        require(re.fullmatch(r"[0-9a-f]{64}", object_id), "full created object identity required")
        observe(object_id, image_id, False)
        emit(full_object_id=object_id, image_id=image_id, policy_observed_before_start=True,
             durable_host_registration_implemented=False)
        docker_cmd("container", "start", object_id)
        row = observe(object_id, image_id, True)
        pid = row["State"]["Pid"]
        task_group = domain.cgroup + "/docker-" + object_id + ".scope"
        task_path = Path("/sys/fs/cgroup" + task_group, "cgroup.procs")
        while True:
            current()
            members = [int(value) for value in task_path.read_text().splitlines()]
            if len(members) == 2 and Path("/proc/%d/root/ready" % pid).exists():
                break
            select.select([], [], [], 0.02)
        require(pid in members and Path("/proc/%d/root/ready" % pid).read_bytes() == b"parent-and-child-ready\n",
                "actual Docker task/child readiness missing")
        for epoch_unit in units[1].values():
            daemon_group = show(epoch_unit, "ControlGroup")
            require(daemon_group == domain.cgroup + "/" + epoch_unit and daemon_group != task_group,
                    "Docker task is not a sibling of both daemon services")
        witness = RuntimeProcessWitness.capture(domain=domain, check=current)
        require(witness.count == 5, "dockerd/containerd/shim/task/child inventory required")
        # Independently pin all original runtime process executables/membership.
        # The source witness retains pidfds; these numeric reads cannot survive a
        # death unnoticed because require_dead must subsequently cover that set.
        allowed = {"/usr/bin/dockerd": DOCKER_PINS["/usr/bin/dockerd"],
                   "/usr/bin/containerd": RUNTIME_PINS["/usr/bin/containerd"],
                   "/usr/bin/containerd-shim-runc-v2": RUNTIME_PINS["/usr/bin/containerd-shim-runc-v2"]}
        observed = []
        for procs in sorted(Path("/sys/fs/cgroup" + domain.cgroup).rglob("cgroup.procs")):
            for value in procs.read_text().splitlines():
                member = int(value)
                fd = os.pidfd_open(member, 0)
                fds.append(fd)
                poller = select.poll()
                poller.register(fd, select.POLLIN)
                require(not poller.poll(0), "Docker process died before executable observation")
                path = str(Path("/proc/%d/exe" % member).resolve())
                if member in members:
                    require(task_executable(root, object_id, member) == raw_probe,
                            "task executable differs from source-built probe")
                    role, expected = "/probe", hashlib.sha256(raw_probe).hexdigest()
                else:
                    require(path in allowed, "unexpected Docker runtime process")
                    role, expected = path, allowed[path]
                with Path("/proc/%d/exe" % member).open("rb") as source:
                    raw = source.read(128 * 1024 * 1024 + 1)
                membership = Path("/proc/%d/cgroup" % member).read_text()
                require(len(raw) <= 128 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == expected
                        and membership == "0::" + str(procs.parent).removeprefix("/sys/fs/cgroup") + "\n"
                        and not poller.poll(0), "Docker process executable/membership drift or death")
                observed.append(role)
                emit(pid=member, executable=path, executable_sha256=expected, cgroup=membership.strip())
        require(sorted(observed) == sorted(["/usr/bin/dockerd", "/usr/bin/containerd",
                                           "/usr/bin/containerd-shim-runc-v2", "/probe", "/probe"]),
                "unexpected complete Docker runtime inventory")
        domain.kill(check=current)
        until = min(deadline, time.monotonic() + 10)
        for fd in fds:
            poller = select.poll()
            poller.register(fd, select.POLLIN)
            require(bool(poller.poll(max(1, int((until - time.monotonic()) * 1000)))), "Docker process survived recursive kill")
        witness.require_dead(check=current)
        require(domain.populated() is False, "Docker cold domain remains populated")
        for unit in units[1].values():
            command("/usr/bin/systemctl", "stop", "--", unit)
        # Observe exactly our persisted object before any daemon is relaunched.
        # This is fixture correspondence, not the independently approved offline
        # metadata/ownership validator required for operational quarantine.
        metadata = root / "docker/containers" / object_id
        host = json.loads(protected_bytes(metadata / "hostconfig.json", limit=1024 * 1024)[0])
        require(host["RestartPolicy"] == {"Name": "no", "MaximumRetryCount": 0}, "persisted restart policy changed")
        require(sorted(path.name for path in metadata.parent.iterdir()) == [object_id], "unexpected persisted Docker object")
        launch(2)
        first = observe(object_id, image_id, False)
        require(ctr("--namespace=cpa-docker", "tasks", "list", "--quiet").stdout == b"", "task resurrected during cold startup")
        # Two reads are explicitly only point observations, not a drain or
        # continuous no-launch proof. The old source pidfds must remain dead.
        require(observe(object_id, image_id, False) == first, "cold startup object changed")
        witness.require_dead(check=current)
        require(not Path("/sys/fs/cgroup" + task_group).exists(), "old Docker task scope reappeared")
        pins()
        require((root / "input.toml").read_bytes() == containerd and json.loads((root / "docker.json").read_bytes()) == docker,
                "Docker fixture configuration changed")
        emit(docker_task_sibling_placement=True, actual_five_process_deaths=True,
             restart_disabled_cold_start_observed=True, private_runtime_only=True,
             complete_fence_proven=False, pending_drained=False, start_allowed=False, production_acceptance=False)
    except BaseException:
        for epoch in units.values():
            for unit in epoch.values():
                command("/usr/bin/journalctl", "--no-pager", "--boot", "--lines=100", "--unit=" + unit, check=False)
        raise
    finally:
        if witness is not None:
            witness.close()
        for fd in fds:
            os.close(fd)
        if domain_fd is not None:
            os.close(domain_fd)
        cleanup()


if __name__ == "__main__":
    if sys.argv[1:] == ["--cleanup"]:
        cleanup()
    else:
        require(len(sys.argv) == 2, "one explicit source-built probe required")
        main(sys.argv[1])
