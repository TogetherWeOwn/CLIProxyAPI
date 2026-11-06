"""Read-only whole-runtime inventory correspondence, never a quarantine grant.

Fixed Docker/ctr observations are bound to the original live supervisor, lock,
protected journal and dedicated topology. No relaunch, registration/adoption,
kill, restore, start, epoch retirement or drain is implemented. Stable repeated
inventories cannot prove creator exclusion, dead old handlers or shim containment.
"""
import re
import stat
import threading

from .broker_authority import SupervisorPeerAuthority
from .daemon import DockerObjects, INSPECT_FORMAT
from .durable import Rejected, canonical, decode, digest, read_file, signature
from .installation import open_approved_directory
from .journal import OBJECT_ID, validate_intent, validate_registration
from .loading import metadata, names, pin
from .topology import Topology, absolute

MAX_OBJECTS = 2  # One original old object and at most one registered candidate.
MAX_OUTPUT = 65536
REGISTRATION = re.compile(r"object-([a-f0-9]{64})\.json\Z")


def lines(raw, *, pattern, limit):
    # CLI framing is strict: empty is allowed, but partial lines, blanks, short
    # IDs, duplicates, whitespace and terminal/control bytes are not evidence.
    if type(raw) is not bytes or len(raw) > MAX_OUTPUT:
        raise Rejected("quarantine-inventory-output-limit")
    if raw and not raw.endswith(b"\n"):
        raise Rejected("quarantine-inventory-partial-output")
    try:
        values = raw.decode("ascii").split("\n")[:-1] if raw else []
    except UnicodeError:
        raise Rejected("quarantine-inventory-output-encoding") from None
    if (len(values) > limit or len(set(values)) != len(values)
            or any(pattern.fullmatch(value) is None for value in values)):
        raise Rejected("quarantine-inventory-output-schema")
    return sorted(values)


def original_registry(*, authority, topology, deadline, check):
    """Read the original protected intent/registrations without runtime contact."""
    check()
    approval = authority.approval
    with open_approved_directory(authority.lock.journal) as root:
        before = metadata(root.fd, uid=approval.uid, gid=approval.gid, directory=True, private=True)
        first = names(root.fd)
        raw, st = read_file(root.fd, "intent.json", limit=16384)
        intent = decode(raw)
        validate_intent(intent)
        if (digest(canonical(intent)) != approval.intent_sha256
                or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (approval.uid, approval.gid, 0o600)
                or st.st_dev != before.st_dev):
            raise Rejected("quarantine-inventory-original-intent-required")
        pins = topology.manifest()["pins"]
        if any(intent[field] != pins[expected] for field, expected in (
                ("candidate_image_id", "candidate_image_sha256"),
                ("baseline_sha256", "baseline_sha256"), ("policy_sha256", "policy_sha256"))):
            raise Rejected("quarantine-inventory-original-pins-required")
        objects = {}
        records = {"intent.json": (raw, signature(st))}
        for name in first:
            if name.startswith((".stage-", ".recovery-stage-")):
                raise Rejected("quarantine-inventory-ambiguous-staging")
            if not name.startswith("object-"):
                continue
            match = REGISTRATION.fullmatch(name)
            if match is None or objects:
                raise Rejected("quarantine-inventory-registration-ambiguous")
            raw, st = read_file(root.fd, name, limit=16384)
            record = decode(raw)
            validate_registration(record, intent)
            if (record["object_id"] != match[1] or st.st_dev != before.st_dev
                    or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (approval.uid, approval.gid, 0o600)):
                raise Rejected("quarantine-inventory-registration-unconfirmed")
            objects[match[1]] = record
            records[name] = (raw, signature(st))
        for name, (raw, stamp) in records.items():
            again, st = read_file(root.fd, name, limit=16384)
            if again != raw or signature(st) != stamp:
                raise Rejected("quarantine-inventory-registry-changed")
        if (names(root.fd) != first
                or signature(metadata(root.fd, uid=approval.uid, gid=approval.gid,
                                      directory=True, private=True)) != signature(before)):
            raise Rejected("quarantine-inventory-registry-changed")
        root.validate()
    check()
    return intent, objects, canonical({name: {"sha256": digest(raw), "signature": stamp}
                                      for name, (raw, stamp) in records.items()})


class QuarantineInventory:
    """Non-authorizing observation for a *future qualified* quarantine runtime.

    The broker independently provisions the helper paths/pins and owns commands.
    Neither IPC arguments nor Docker labels choose them. Existing runtime/broker
    runners do not expose this component. Helpers use the existing bounded local
    transport; all API operations here are read-only and any uncertainty revokes
    this instance. No installation lock is taken or transferred.
    """
    def __init__(self, *, authority, topology, docker, ctr, docker_sha256, ctr_sha256,
                 commands, read_helper_hash):
        if not isinstance(authority, SupervisorPeerAuthority) or not isinstance(topology, Topology):
            raise Rejected("quarantine-inventory-explicit-boundaries-required")
        absolute(docker)
        absolute(ctr)
        pin(docker_sha256)
        pin(ctr_sha256)
        if docker == ctr or not callable(read_helper_hash):
            raise Rejected("quarantine-inventory-distinct-pinned-helpers-required")
        binding = decode(authority._binding)
        if (topology.sha256 != binding["topology_sha256"]
                or topology.manifest()["installation_id"] != binding["installation_id"]):
            raise Rejected("quarantine-inventory-original-topology-required")
        self.authority, self.topology = authority, topology
        self.docker, self.ctr = docker, ctr
        self.docker_sha256, self.ctr_sha256 = docker_sha256, ctr_sha256
        self.commands, self.read_helper_hash = commands, read_helper_hash
        self._mutex, self.failed = threading.Lock(), False
        self._configuration = self.configuration()

    def configuration(self):
        return canonical({"binding_sha256": digest(self.authority._binding),
            "topology_sha256": self.topology.sha256, "docker": self.docker, "ctr": self.ctr,
            "docker_sha256": self.docker_sha256, "ctr_sha256": self.ctr_sha256})

    def _current(self, deadline):
        if self.failed or self.configuration() != self._configuration:
            raise Rejected("quarantine-inventory-revoked")
        self.authority.observe(deadline=deadline)
        for path, expected in ((self.docker, self.docker_sha256), (self.ctr, self.ctr_sha256)):
            if self.read_helper_hash(path) != expected:
                raise Rejected("quarantine-inventory-helper-changed")
        # Helper reads may themselves outlive the peer/lock or original budget.
        self.authority.observe(deadline=deadline)
        if self.configuration() != self._configuration:
            raise Rejected("quarantine-inventory-configuration-changed")

    def _registry(self, deadline):
        return original_registry(authority=self.authority, topology=self.topology, deadline=deadline,
                                 check=lambda: self._current(deadline))

    def _run(self, argv, deadline):
        self._current(deadline)
        raw = self.commands.run(argv, deadline=deadline)
        self._current(deadline)
        return raw

    def _snapshot(self, intent, registered, deadline):
        resources = self.topology.manifest()["resources"]
        endpoint = "unix://" + resources["dockerd_socket"]
        docker = (self.docker, "--host=" + endpoint)
        ctr = (self.ctr, "--address=" + resources["containerd_socket"])
        namespace = resources["containerd_namespace"]
        expected = sorted([intent["old_object_id"], *registered])
        observer = self
        class InspectCommands:
            def run(self, argv, *, deadline):
                if argv not in tuple(docker + ("container", "inspect", "--format=" + INSPECT_FORMAT, object_id)
                                     for object_id in expected):
                    raise Rejected("quarantine-inventory-fixed-inspection-required")
                return observer._run(argv, deadline)
        objects = DockerObjects(docker=self.docker, endpoint=endpoint, commands=InspectCommands(),
            intent=intent, old_image_id=self.topology.manifest()["pins"]["rollback_image_sha256"],
            start_fence=lambda: False, clock=self.authority.lock.clock)
        list_argv = docker + ("container", "ls", "--all", "--no-trunc", "--format={{.ID}}")
        def docker_ids():
            return lines(self._run(list_argv, deadline), pattern=OBJECT_ID, limit=MAX_OBJECTS)
        def namespaces():
            value = lines(self._run(ctr + ("namespaces", "list", "--quiet"), deadline),
                          pattern=re.compile(re.escape(namespace) + r"\Z"), limit=1)
            return value
        if docker_ids() != expected:
            # No label-filtered discovery, adoption, registration write or guessed
            # missing object. A lost/ambiguous create is a separate prerequisite.
            raise Rejected("quarantine-inventory-whole-daemon-mismatch")
        rows = [objects.inspect(object_id, deadline=deadline) for object_id in expected]
        if any(row["running"] is not False for row in rows):
            raise Rejected("quarantine-inventory-object-not-stopped")
        spaces = namespaces()
        # Namespace metadata absence is not task-service absence. Always query
        # the fixed namespace too, including when the namespace list is empty.
        prefix = ctr + ("--namespace=" + namespace,)
        containers = lines(self._run(prefix + ("containers", "list", "--quiet"), deadline),
                           pattern=OBJECT_ID, limit=MAX_OBJECTS)
        tasks = lines(self._run(prefix + ("tasks", "list", "--quiet"), deadline),
                      pattern=OBJECT_ID, limit=MAX_OBJECTS)
        if tasks or not set(containers) <= set(expected) or not spaces and containers:
            raise Rejected("quarantine-inventory-unknown-container-or-live-task")
        if docker_ids() != expected or namespaces() != spaces:
            raise Rejected("quarantine-inventory-changed")
        return canonical({"objects": rows, "containerd_namespaces": spaces,
                          "containerd_containers": containers, "containerd_tasks": tasks})

    def observe(self, *, deadline):
        with self._mutex:
            try:
                intent, registered, registry = self._registry(deadline)
                first = self._snapshot(intent, registered, deadline)
                if self._registry(deadline) != (intent, registered, registry):
                    raise Rejected("quarantine-inventory-registry-changed")
                second = self._snapshot(intent, registered, deadline)
                if first != second or self._registry(deadline) != (intent, registered, registry):
                    raise Rejected("quarantine-inventory-changed")
                self._current(deadline)
                return {"schema": "host-recovery-quarantine-inventory-observation-v1",
                    "binding_sha256": digest(self.authority._binding),
                    "registry_sha256": digest(registry), "inventory_sha256": digest(first),
                    "object_count": 1 + len(registered), "registered_candidate_count": len(registered),
                    "whole_daemon_inventory_observed": True, "containerd_no_tasks_observed": True,
                    "old_epoch_retired": False, "activation_exclusion_proven": False,
                    "shim_containment_proven": False, "quarantine_reconciled": False,
                    "pending_drained": False, "complete_fence_proven": False,
                    "recovery_execution_allowed": False, "start_allowed": False,
                    "settlement_allowed": False, "production_acceptance": False}
            except Exception:
                self.failed = True
                raise Rejected("quarantine-inventory-unconfirmed") from None
