"""Read and restore the pre-adoption gateway without changing release or state files."""

from dataclasses import dataclass
import json
from pathlib import Path

from compose_adapter import ComposeAdapter, Mount, docker, file_digest, location
from production import DIGEST, ReleaseError, matches, save_json

TAG = r"[a-z0-9][a-z0-9._/-]{0,126}:[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}"


@dataclass(frozen=True)
class LegacyCompose:
    adapter: ComposeAdapter
    directory: Path
    compose_sha256: str
    service_hash: str
    image_tag: str
    config_sha256: str
    config_mount: Mount
    plugins_mount: Mount
    library_path: Path
    networks: frozenset[str]
    ports: dict
    incumbent_id: str
    started_at: str
    kv_file: Path
    kv_identity: tuple[int, int]
    pending: Path

    @property
    def baseline(self):
        return self.adapter.phases["baseline"]

    def plan(self):
        compose = self.directory / "compose.yaml"
        if (self.directory != self.adapter.directory or compose.resolve() != compose
                or file_digest(compose, 64 * 1024) != self.compose_sha256
                or file_digest(self.config_mount.source, 1024 * 1024) != self.config_sha256
                or location(self.kv_file) != self.kv_identity
                or self.library_path.is_absolute() or ".." in self.library_path.parts
                or not matches(DIGEST, self.incumbent_id)
                or not matches(DIGEST, self.service_hash)
                or not matches(TAG, self.image_tag)):
            raise ReleaseError("legacy gateway files or identities changed")
        self.baseline.verify_libraries(self.plugins_mount.source / self.library_path, allow_shadow=True)

        mounts = (*self.adapter.state_mounts, self.config_mount, self.plugins_mount)
        for mount in mounts:
            mount.verify()

        model = json.loads(self.adapter.compose(self, "config", "--format", "json"))
        if (model["name"] != self.adapter.project or set(model["services"]) != {self.adapter.service}
                or any(model.get(key) for key in ("volumes", "configs", "secrets"))):
            raise ReleaseError("legacy Compose plan changed")
        service = model["services"][self.adapter.service]
        networks = model.get("networks", {})
        if (service.get("image") != self.image_tag
                or any(key in service for key in ("build", "develop", "provider", "post_start", "pre_stop",
                                                  "volumes_from", "configs", "secrets", "depends_on", "network_mode"))
                or {net["name"] for net in networks.values() if net.get("external")} != self.networks
                or len(networks) != len(self.networks) or not self.networks):
            raise ReleaseError("legacy Compose image or network plan changed")

        volumes = service.get("volumes", [])
        if any(volume["type"] != "bind" or volume.get("bind", {}).get("propagation", "rprivate") != "rprivate"
               for volume in volumes):
            raise ReleaseError("legacy Compose plan requires bind mounts")
        observed = sorted((vol["source"], vol["target"], not vol.get("read_only", False)) for vol in volumes)
        if observed != sorted(mount.mode() for mount in mounts):
            raise ReleaseError("legacy Compose bind plan changed")

        expected_ports = {}
        for port in service.get("ports", []):
            if port.get("protocol", "tcp") != "tcp" or port.get("host_ip") != "127.0.0.1":
                raise ReleaseError("legacy publishes must be loopback TCP")
            key = f"{port['target']}/tcp"
            expected_ports.setdefault(key, []).append({"HostIp": port["host_ip"], "HostPort": port["published"]})
        if expected_ports != self.ports:
            raise ReleaseError("legacy Compose published ports changed")

        observed_hash = self.adapter.compose(self, "config", "--hash", self.adapter.service).split()
        if observed_hash != [self.adapter.service.encode("ascii"), self.service_hash.encode("ascii")]:
            raise ReleaseError("legacy Compose service hash changed")
        return mounts

    def verify_tag(self):
        identity = docker("image", "inspect", "--format", "{{.Id}}", self.image_tag)
        if identity.strip() != self.baseline.image.encode("ascii"):
            raise ReleaseError("legacy image tag no longer points to the approved artifact")

    def read(self, *, original=False, running=True):
        mounts = self.plan()
        if original:
            self.verify_tag()
        item = self.adapter.installed(self.baseline, mounts, self.networks, self.service_hash)
        state = item["State"]
        if (item["Config"]["Image"] != self.image_tag or item["HostConfig"]["PortBindings"] != self.ports
                or (running and (not state["Running"] or state["Restarting"]))
                or (original and (item["Id"] != self.incumbent_id or state["StartedAt"] != self.started_at))):
            raise ReleaseError("legacy container does not match the binding")
        return item

    def restore(self, check_isolated):
        """Recover under the host fence, leaving that fence closed for readiness."""
        self.plan()
        if self.pending.exists() or self.adapter.pending.exists():
            raise ReleaseError("previous Compose operation needs reconciliation")
        self.verify_tag()
        if check_isolated() is not True:
            raise ReleaseError("legacy restoration requires isolated ingress and writers")
        save_json(self.pending, {"phase": "restore-legacy", "image": self.baseline.image})
        self.adapter.compose(self, "up", "--detach", "--no-deps", "--no-build", "--pull", "never",
                             "--scale", f"{self.adapter.service}=1", self.adapter.service, timeout=50)
        item = self.read()
        self.pending.unlink()
        return item
