"""Offline Compose operations for a single installer-bound release pair."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from production import DIGEST, ReleaseError, SAFE_ENV, matches, save_json

IMAGE = "sha256:" + DIGEST
NAME = r"[a-z0-9][a-z0-9_-]*"
LIBRARY = r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,119}\.so"


def file_digest(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ReleaseError("invalid release file")
        return hashlib.file_digest(file, "sha256").hexdigest()


def location(path):
    info = path.stat()
    if not path.is_absolute() or path.resolve() != path:
        raise ReleaseError("mount source must be a canonical host path")
    return info.st_dev, info.st_ino


@dataclass(frozen=True)
class Mount:
    source: Path
    target: str
    writable: bool
    identity: tuple[int, int]

    def mode(self):
        return str(self.source), self.target, self.writable

    def verify(self):
        if location(self.source) != self.identity:
            raise ReleaseError("bind mount source changed")


@dataclass(frozen=True)
class Phase:
    directory: Path
    compose_sha256: str
    config_sha256: str
    libraries: dict[str, str]
    image: str
    executable: str
    meta: str

    def verify_libraries(self, plugins, *, allow_shadow=False):
        entries = {path.name for path in plugins.iterdir()}
        shadow = plugins / ".shadow"
        if allow_shadow and shadow.is_dir() and not shadow.is_symlink():
            entries.remove(".shadow")
        if (plugins.resolve() != plugins or not plugins.is_dir()
                or not 1 <= len(self.libraries) <= 32
                or any(not matches(LIBRARY, name) for name in self.libraries)
                or entries != self.libraries.keys()
                or f"meta-v{self.meta}.so" not in self.libraries
                or any(file_digest(plugins / name, 768 * 1024 * 1024) != digest
                       for name, digest in self.libraries.items())):
            raise ReleaseError("release libraries do not match the bound phase")

    def verify(self):
        compose, config = self.directory / "compose.yaml", self.directory / "config.yaml"
        if (file_digest(compose, 64 * 1024) != self.compose_sha256
                or file_digest(config, 1024 * 1024) != self.config_sha256):
            raise ReleaseError("release files do not match the bound phase")
        self.verify_libraries(self.directory / "plugins")


def command(*args, timeout=5, logs=False):
    # Ignore ambient Docker/Compose configuration. Never emit command output
    # or exceptions containing it to the controller's service log.
    result = subprocess.run(
        args, env=SAFE_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if logs else subprocess.DEVNULL, timeout=timeout, check=False,
    )
    if result.returncode:
        raise ReleaseError("local Compose operation failed")
    return result.stdout


def docker(*args, **kwargs):
    return command("/usr/bin/docker", "--host", "unix:///var/run/docker.sock", *args, **kwargs)


class ComposeAdapter:
    """Call under the production controller's lock via a root-owned wrapper."""

    def __init__(self, *, digest, phases, project, project_directory, service, executable,
                 state_mounts, config_target, plugins_target, pending, gate,
                 check_quiescence=None, probe=None, read_registration=None, writable_release_files=False):
        if (not matches(DIGEST, digest) or set(phases) != {"baseline", "candidate"}
                or not matches(NAME, project) or not matches(NAME, service)
                or not state_mounts or not project_directory.is_absolute()):
            raise ReleaseError("invalid Compose binding")
        self.digest, self.phases = digest, phases
        self.project, self.directory, self.service = project, project_directory, service
        self.executable = executable
        self.state_mounts = tuple(state_mounts)
        self.config_target, self.plugins_target = config_target, plugins_target
        self.pending, self.gate = pending, gate
        self.check_quiescence, self.probe = check_quiescence, probe
        self.read_registration = read_registration or self.docker_registration
        self.writable_release_files = writable_release_files

    def compose(self, phase, *args, **kwargs):
        return docker("compose", "--project-name", self.project, "--project-directory", str(self.directory),
                      "--env-file", "/dev/null", "-f", str(phase.directory / "compose.yaml"), *args, **kwargs)

    def mounts(self, phase):
        mounts = list(self.state_mounts)
        for name, target in (("config.yaml", self.config_target), ("plugins", self.plugins_target)):
            source = phase.directory / name
            mounts.append(Mount(source, target, self.writable_release_files, location(source)))
        if len({mount.target for mount in mounts}) != len(mounts):
            raise ReleaseError("duplicate bind mount target")
        for mount in mounts:
            mount.verify()
        return mounts

    def plan(self, phase):
        phase.verify()
        mounts = self.mounts(phase)
        model = json.loads(self.compose(phase, "config", "--format", "json"))
        services = model["services"]
        if (model["name"] != self.project or set(services) != {self.service}
                or any(model.get(key) for key in ("volumes", "configs", "secrets"))):
            raise ReleaseError("Compose plan must contain only the bound gateway")
        service = services[self.service]
        if (not matches(IMAGE, phase.image) or service.get("image") != phase.image
                or any(key in service for key in ("build", "develop", "provider", "post_start", "pre_stop",
                                                  "volumes_from", "configs", "secrets", "depends_on"))):
            raise ReleaseError("Compose plan could change an unbound resource")
        # Use an existing network, or an isolated gateway namespace. The site
        # verifies private reachability and the peer used by the gate.
        networks = model.get("networks", {})
        if service.get("network_mode") == "none":
            if networks:
                raise ReleaseError("isolated Compose plan declares networks")
        elif ("network_mode" in service or not networks
              or any(not net.get("external") for net in networks.values())):
            raise ReleaseError("Compose networks must already be provisioned")
        volumes = service.get("volumes", [])
        if any(volume["type"] != "bind" or volume.get("bind", {}).get("create_host_path")
               or volume.get("bind", {}).get("propagation", "rprivate") != "rprivate" for volume in volumes):
            raise ReleaseError("Compose plan must use existing private bind mounts")
        observed = sorted((volume["source"], volume["target"], not volume.get("read_only", False))
                          for volume in volumes)
        if observed != sorted(mount.mode() for mount in mounts):
            raise ReleaseError("Compose bind plan does not match the installed binding")
        for net in networks.values():
            docker("network", "inspect", "--format", "{{.Id}}", net["name"])
        return mounts, set(net["name"] for net in networks.values()) or {"none"}

    def prepared(self, phase):
        if not self.probe:
            raise ReleaseError("private gateway probe is unbound")
        self.plan(phase)
        identity = docker("image", "inspect", "--format", "{{.Id}} {{.Os}}/{{.Architecture}}", phase.image)
        if identity.strip() != f"{phase.image} linux/amd64".encode("ascii"):
            raise ReleaseError("local image does not match the bound phase")
        executable = docker(
            "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=16", "--memory=64m", "--user=65534:65534",
            "--entrypoint", "sha256sum", phase.image, "--", self.executable, timeout=12,
        ).split()
        if not executable or executable[0].decode("ascii") != phase.executable:
            raise ReleaseError("local image executable does not match the bound phase")

    def container(self):
        labels = {
            "com.docker.compose.project": self.project,
            "com.docker.compose.service": self.service,
            "com.docker.compose.oneoff": "False",
        }
        filters = [arg for key, value in labels.items() for arg in ("--filter", f"label={key}={value}")]
        ids = docker("container", "ls", "--all", "--quiet", "--no-trunc", *filters).decode("ascii").splitlines()
        if len(ids) != 1 or not matches(DIGEST, ids[0]):
            raise ReleaseError("expected one installed gateway container")
        item, = json.loads(docker("container", "inspect", ids[0]))
        if (item["Id"] != ids[0]
                or any(item["Config"]["Labels"].get(key) != value for key, value in labels.items())):
            raise ReleaseError("gateway container does not match the installed binding")
        return item

    @staticmethod
    def check_mounts(item, mounts, *, exact):
        observed = {(mount["Source"], mount["Destination"], mount["RW"])
                    for mount in item["Mounts"]
                    if mount["Type"] == "bind" and mount["Propagation"] == "rprivate"}
        if (not {mount.mode() for mount in mounts} <= observed
                or (exact and len(item["Mounts"]) != len(mounts))):
            raise ReleaseError("installed gateway bind mounts do not match")
        for mount in mounts:
            mount.verify()
        if item["State"]["Running"]:
            inodes = docker("exec", item["Id"], "stat", "-c", "%d:%i", "--",
                            *(mount.target for mount in mounts)).splitlines()
            if inodes != [f"{dev}:{ino}".encode("ascii") for dev, ino in (m.identity for m in mounts)]:
                raise ReleaseError("running gateway has stale bind mounts")

    def incumbent(self, phase):
        mounts, networks = self.plan(phase)
        identity = self.compose(phase, "config", "--hash", self.service).decode("ascii").split()
        if len(identity) != 2 or identity[0] != self.service or not matches(DIGEST, identity[1]):
            raise ReleaseError("invalid Compose service hash")
        return self.installed(phase, mounts, networks, identity[1])

    def installed(self, phase, mounts, networks, service_hash):
        item = self.container()
        labels = item["Config"]["Labels"]
        if (item["Image"] != phase.image or labels.get("com.docker.compose.config-hash") != service_hash
                or labels.get("com.docker.compose.project.working_dir") != str(self.directory)):
            raise ReleaseError("installed gateway is not the expected phase")
        if item["State"]["Running"] and set(item["NetworkSettings"]["Networks"]) != networks:
            raise ReleaseError("running gateway networks do not match the phase")
        self.check_mounts(item, mounts, exact=True)
        if item["State"]["Running"]:
            executable = docker("exec", item["Id"], "sha256sum", "/proc/1/exe").split()
            if not executable or executable[0].decode("ascii") != phase.executable:
                raise ReleaseError("running gateway executable does not match the phase")
        return item

    def quiescent(self, phase, fence):
        if self.pending.exists():
            raise ReleaseError("previous Compose operation needs reconciliation")
        if self.check_quiescence is None:
            raise ReleaseError("host quiescence verifier is unbound")
        if not fence or fence.get("closed") is not True:
            raise ReleaseError("controller gate fence is required")
        state = self.gate.require(fence, empty=True)
        if self.check_quiescence(self.digest, phase, state.copy()) is not True:
            raise ReleaseError("host quiescence could not be verified")
        return self.gate.require(fence, empty=True)

    def switch(self, phase_name, phase, fence):
        self.plan(phase)
        incumbent = self.container()
        self.check_mounts(incumbent, self.state_mounts, exact=False)
        closed = self.quiescent(phase_name, fence)
        # A timeout or failed Compose client can leave daemon work in flight.
        # Keep the marker until a synchronous success, even across a crash.
        save_json(self.pending, {"digest": self.digest, "phase": phase_name})
        self.gate.require(closed, empty=True)
        self.compose(phase, "up", "--detach", "--no-deps", "--no-build", "--pull", "never",
                     "--force-recreate", "--scale", f"{self.service}=1", self.service, timeout=50)
        if self.container()["Id"] == incumbent["Id"]:
            raise ReleaseError("Compose did not replace the gateway")
        self.pending.unlink()

    @staticmethod
    def docker_registration(container, started_at):
        return docker("container", "logs", "--since", started_at, "--tail", "2000", container, logs=True)

    def ready(self, phase_name, phase):
        item = self.incumbent(phase)
        state = item["State"]
        if not state["Running"] or self.probe is None or self.pending.exists():
            raise ReleaseError("gateway readiness is unavailable")
        command(*self.probe, item["Id"], self.digest, phase_name, timeout=25)
        logs = self.read_registration(item["Id"], state["StartedAt"])
        phase.verify()
        for mount in self.state_mounts:
            mount.verify()
        meta = re.findall(rb"pluginhost: plugin registered plugin_id=meta [^\r\n]*? version=([^\s]+)", logs)
        current = self.container()
        if (meta != [phase.meta.encode("ascii")] or current["Id"] != item["Id"]
                or current["State"]["Status"] != "running" or current["State"]["StartedAt"] != state["StartedAt"]):
            raise ReleaseError("running gateway readiness does not match the phase")

    def __call__(self, verb, digest, phase_name, *, fence=None):
        if digest != self.digest or phase_name not in self.phases:
            raise ReleaseError("release is not bound to this Compose adapter")
        phase = self.phases[phase_name]
        match verb:
            case "prepared":
                self.prepared(phase)
            case "incumbent":
                self.incumbent(phase)
            case "quiescent":
                self.quiescent(phase_name, fence)
            case "switch":
                self.switch(phase_name, phase, fence)
            case "ready":
                self.ready(phase_name, phase)
            case _:
                raise ReleaseError("unknown Compose operation")
