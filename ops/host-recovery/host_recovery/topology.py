"""Closed dedicated-runtime topology input; never an operational authority grant.

All values describe independently provisioned expectations, not observed facts.
Even a root-owned, digest-matched topology cannot prove exclusive ownership,
activation exclusion, cold quiescence, original lock ownership or safe starts.
Existing deny-only runners deliberately do not consume this as a fence.
"""
from dataclasses import dataclass
import re

from .durable import Rejected, decode, digest
from .journal import identity
from .loading import ContentApproval, ContentSnapshot, REVISION, owner, pin

MAX_BYTES = 32768
TOPOLOGY_FILE = "topology.json"
ROLES = ("broker", "observer", "supervisor", "forward", "recovery")
RUNTIME_ROLES = ("dockerd", "containerd")
TOOLS = ("dockerd", "containerd", "runc", "systemd", "kernel", "broker", "observer", "interpreter")
RESOURCE_ROOTS = ("data_root", "exec_root", "containerd_root", "containerd_state")
PROTECTED_ROOTS = ("package", "approval", "baseline", "broker_state", "supervisor_state", "worker_evidence")
WRITE_ROOTS = ("auth", "config", "compose", "plugin")
PINS = ("package_revision", "candidate_revision", "rollback_revision", "producer_revision",
        "package_closure_sha256", "candidate_image_sha256", "rollback_image_sha256",
        "plugin_archive_sha256", "plugin_library_sha256", "producer_schema_sha256",
        "policy_sha256", "baseline_sha256")
PATH_PART = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
UNIT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,95}(?:@)?\.service\Z")
SLICE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_]{0,63}\.slice\Z")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,95}\Z")
SHARED_PATHS = ("/var/lib/docker", "/run/docker", "/run/docker.sock", "/var/run",
                "/var/lib/containerd", "/run/containerd")
INFRASTRUCTURE = ("/proc", "/sys", "/dev", "/boot", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64")


def shape(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise Rejected("topology-schema")


def absolute(value):
    if (type(value) is not str or not value.startswith("/") or len(value) > 1024
            or len(value.split("/")) > 33
            or any(PATH_PART.fullmatch(part) is None or part in (".", "..")
                   for part in value.split("/")[1:])):
        raise Rejected("topology-explicit-canonical-path-required")
    return value


def within(path, root):
    return path == root or path.startswith(root + "/")


def disjoint(paths):
    for index, path in enumerate(paths):
        if any(within(path, other) or within(other, path) for other in paths[index + 1:]):
            raise Rejected("topology-resource-overlap")


def revision(value):
    if type(value) is not str or REVISION.fullmatch(value) is None:
        raise Rejected("topology-source-revision-required")


def service(value):
    if type(value) is not str or UNIT.fullmatch(value) is None:
        raise Rejected("topology-fixed-service-required")


def constant(value, expected):
    # bool and int compare equal in Python, but are not interchangeable policy.
    if type(value) is not type(expected) or value != expected:
        raise Rejected("topology-unsupported-runtime-policy")


def validate(value):
    shape(value, ("schema", "installation_id", "runtime", "roles", "tools", "resources",
                  "protected_roots", "write_roots", "pins"))
    constant(value["schema"], "host-recovery-topology-v1")
    if not identity(value["installation_id"]):
        raise Rejected("topology-installation-identity-required")
    runtime = value["runtime"]
    expected = {"ownership": "installation_only", "adoption": "fresh_empty_only",
                "cgroup_driver": "systemd", "live_restore": False, "restart_policy": "no",
                "maximum_retry_count": 0, "auto_remove": False, "swarm": False,
                "external_launchers": False, "boot_autostart": False,
                "socket_activation": False, "path_activation": False, "timer_activation": False,
                "force_restart": False, "cold_barrier": "required", "metadata": "regular_tree_v1"}
    shape(runtime, (*expected, "slice", "cgroup_path", "units"))
    for key, item in expected.items():
        constant(runtime[key], item)
    slice_name = runtime["slice"]
    if (type(slice_name) is not str or SLICE.fullmatch(slice_name) is None
            or slice_name in ("system.slice", "user.slice", "machine.slice")):
        raise Rejected("topology-dedicated-slice-required")
    # Initial support excludes nested slices and user-manager runtime domains.
    constant(runtime["cgroup_path"], "/" + slice_name)
    shape(runtime["units"], RUNTIME_ROLES)
    all_units = []
    for name in RUNTIME_ROLES:
        entry = runtime["units"][name]
        shape(entry, ("unit", "effective_sha256"))
        service(entry["unit"])
        if "@" in entry["unit"] or entry["unit"] in ("docker.service", "dockerd.service", "containerd.service"):
            raise Rejected("topology-fixed-runtime-unit-required")
        pin(entry["effective_sha256"])
        all_units.append(entry["unit"])
    shape(value["roles"], ROLES)
    uids, gids = [], []
    for name in ROLES:
        entry = value["roles"][name]
        shape(entry, ("uid", "gid", "unit", "effective_sha256", "launch_sha256"))
        owner(entry["uid"], entry["gid"])
        service(entry["unit"])
        if name == "broker":
            constant(entry["uid"], 0)
            constant(entry["gid"], 0)
        elif entry["uid"] == 0 or entry["gid"] == 0:
            raise Rejected("topology-unprivileged-role-required")
        if ("@" in entry["unit"]) != (name == "recovery"):
            raise Rejected("topology-role-unit-kind")
        pin(entry["effective_sha256"])
        pin(entry["launch_sha256"])
        all_units.append(entry["unit"])
        uids.append(entry["uid"])
        gids.append(entry["gid"])
    if len(set(all_units)) != len(all_units) or len(set(uids)) != len(uids) or len(set(gids)) != len(gids):
        raise Rejected("topology-distinct-roles-required")
    shape(value["tools"], TOOLS)
    for entry in value["tools"].values():
        shape(entry, ("version", "source_revision", "sha256"))
        if type(entry["version"]) is not str or VERSION.fullmatch(entry["version"]) is None:
            raise Rejected("topology-pinned-tool-version-required")
        revision(entry["source_revision"])
        pin(entry["sha256"])
    resources = value["resources"]
    shape(resources, (*RESOURCE_ROOTS, "dockerd_socket", "containerd_socket", "containerd_namespace"))
    directories = [absolute(resources[key]) for key in RESOURCE_ROOTS]
    for key in ("dockerd_socket", "containerd_socket"):
        absolute(resources[key])
    if (not within(resources["dockerd_socket"], resources["exec_root"])
            or resources["dockerd_socket"] == resources["exec_root"]
            or not within(resources["containerd_socket"], resources["containerd_state"])
            or resources["containerd_socket"] == resources["containerd_state"]):
        raise Rejected("topology-private-runtime-endpoint-required")
    namespace = resources["containerd_namespace"]
    if (type(namespace) is not str or PATH_PART.fullmatch(namespace) is None
            or namespace in (".", "..", "default", "moby", "k8s.io")):
        raise Rejected("topology-dedicated-namespace-required")
    for field, keys in (("protected_roots", PROTECTED_ROOTS), ("write_roots", WRITE_ROOTS)):
        shape(value[field], keys)
        directories.extend(absolute(value[field][key]) for key in keys)
    # Reject conventional shared endpoints/roots, including aliases through var/run.
    # Nonstandard shared resources still require actual provisioning qualification.
    for path in directories + [resources["dockerd_socket"], resources["containerd_socket"]]:
        if any(within(path, shared) or within(shared, path) for shared in SHARED_PATHS + INFRASTRUCTURE):
            raise Rejected("topology-shared-runtime-path-unsupported")
    disjoint(directories)
    shape(value["pins"], PINS)
    for key, item in value["pins"].items():
        revision(item) if key.endswith("_revision") else pin(item)


@dataclass(frozen=True)
class Topology:
    """Immutable captured input, explicitly not a fence/authorization receipt."""
    raw: bytes

    def __post_init__(self):
        if type(self.raw) is not bytes or not 0 < len(self.raw) <= MAX_BYTES:
            raise Rejected("topology-size-or-type")
        validate(decode(self.raw))

    @property
    def sha256(self):
        return digest(self.raw)

    def manifest(self):
        # Never lend a mutable approval object to a caller or callback.
        return decode(self.raw)

    def status(self):
        return {"schema": "host-recovery-topology-status-v1", "topology_sha256": self.sha256,
                "state": "input_validated_only", "provisioning_verified": False,
                "complete_fence_proven": False, "recovery_execution_allowed": False,
                "start_allowed": False, "production_acceptance": False}


def load_topology(content, *, sha256, installation_id):
    """Consume an already protected snapshot plus independent installation pins.

    ContentSnapshot is produced by load_content under the retained installation
    lock and independently approved index. The caller must obtain root-owned
    package/approval handles through provisioning and revalidate them at later
    barriers. Constructing a Python ContentSnapshot is not authentication.
    """
    pin(sha256)
    if not identity(installation_id):
        raise Rejected("topology-installation-identity-required")
    if (not isinstance(content, ContentSnapshot) or not isinstance(content.approval, ContentApproval)
            or (content.approval.uid, content.approval.gid) != (0, 0)):
        raise Rejected("topology-root-provisioned-content-required")
    raw = content.files.get(TOPOLOGY_FILE)
    if type(raw) is not bytes or digest(raw) != sha256:
        raise Rejected("topology-pin-mismatch")
    topology = Topology(raw)
    value = topology.manifest()
    if (value["installation_id"] != installation_id
            or value["pins"]["package_revision"] != content.approval.source_revision):
        raise Rejected("topology-content-identity-mismatch")
    return topology
