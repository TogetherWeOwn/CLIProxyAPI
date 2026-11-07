"""Read-only old-container deployment correspondence, never start authority.

Full Config/HostConfig and effective Mounts are restricted transient input. Only
hashes leave this reader; do not persist/log its raw daemon response. An external
approved projection digest is required, not a pin learned from the current daemon.
This does not authenticate approval, inspect mounted bytes or implement a fence.
"""
import copy
from dataclasses import dataclass
import math

from .commands import Deadline, MAX_OUTPUT
from .coordinator import validate_baseline_receipt
from .daemon import DockerObjects
from .durable import Rejected, canonical, decode, digest
from .journal import validate_intent
from .loading import pin
from .process_mounts import ProcessMountView
from .write_set import WriteSetVerifier

FORMAT = ('{"object_id":{{json .Id}},"image_id":{{json .Image}},'
          '"path":{{json .Path}},"args":{{json .Args}},'
          '"config":{{json .Config}},"host_config":{{json .HostConfig}},'
          '"mounts":{{json .Mounts}}}')
FIELDS = frozenset(("object_id", "image_id", "path", "args", "config", "host_config", "mounts"))


@dataclass(frozen=True)
class DeploymentApproval:
    intent_sha256: str
    old_image_id: str
    projection_sha256: str

    def __post_init__(self):
        for value in (self.intent_sha256, self.old_image_id, self.projection_sha256):
            pin(value)


class OldDeploymentGate:
    """Reobserve a stopped immutable object around complete-fence callbacks.

    Caller holds the installation lock and supplies the actual complete writer,
    daemon-internal-restart and pending-operation fence. Matching stopped snapshots
    without that enforcement cannot close an inter-query/start race. DockerObjects
    supplies only fixed inspection argv here, never create/start/exec/copy/mutation.
    """
    def __init__(self, *, objects, approval, check, clock, bind_sources=None, daemon_view=None):
        if (not isinstance(objects, DockerObjects) or not isinstance(approval, DeploymentApproval)
                or not callable(check) or not callable(clock)
                or bind_sources is not None and not isinstance(bind_sources, WriteSetVerifier)
                or daemon_view is not None and (not isinstance(daemon_view, ProcessMountView) or bind_sources is None)):
            raise Rejected("deployment-explicit-boundaries-required")
        self.objects, self.approval, self.check, self.clock = objects, approval, check, clock
        self.bind_sources = self._bind_sources = bind_sources
        self.daemon_view = self._daemon_view = daemon_view
        self.failed = self._active = False
        self._binding, self._last_clock = None, None

    def _bound_observers(self):
        objects = self.objects
        values = (self.approval, objects.prefix, objects.installation_id, objects.attempt_id,
                  objects.old_object_id, objects.old_image_id, objects.candidate_image_id)
        readers = (objects, self.check, self.clock, self.bind_sources, self.daemon_view,
                   objects.commands, objects.clock, objects.start_fence)
        # Configuration may be composed before first use, never rebound after an
        # observation. Retain the actual transport and callbacks, not just facade.
        if self._binding is None:
            self._binding = values, readers
        expected, retained = self._binding
        if (self.failed or values != expected
                or any(actual is not original for actual, original in zip(readers, retained))
                or self.bind_sources is not self._bind_sources or self.daemon_view is not self._daemon_view):
            raise Rejected("deployment-observer-configuration-changed")

    def _now(self):
        self._bound_observers()
        now = self.clock()
        self._bound_observers()
        if (type(now) not in (int, float) or not math.isfinite(now)
                or self._last_clock is not None and now < self._last_clock):
            raise Rejected("deployment-clock-discontinuity")
        self._last_clock = now
        return now

    def _projection(self, objects, object_id, approval, deadline):
        raw = objects._run(("container", "inspect", "--format=" + FORMAT, object_id), deadline)
        if type(raw) is not bytes or len(raw) > MAX_OUTPUT:
            raise Rejected("deployment-response-bounds")
        value = decode(raw)
        if (set(value) != FIELDS or value["object_id"] != object_id
                or value["image_id"] != "sha256:" + approval.old_image_id
                or type(value["path"]) is not str or not value["path"] or "\0" in value["path"]
                or type(value["args"]) is not list
                or any(type(arg) is not str or "\0" in arg for arg in value["args"])
                or type(value["config"]) is not dict or not value["config"]
                or type(value["host_config"]) is not dict or not value["host_config"]
                or type(value["mounts"]) is not list
                or any(type(mount) is not dict or not mount for mount in value["mounts"])):
            raise Rejected("deployment-projection-schema")
        if digest(canonical(value)) != approval.projection_sha256:
            raise Rejected("deployment-projection-mismatch")
        return value

    def verify(self, intent, *, deadline):
        try:
            if self.failed or self._active:
                raise Rejected("deployment-gate-unavailable")
            self._active = True
            self._bound_observers()
            value, approval, objects = copy.deepcopy(intent), self.approval, self.objects
            verifier, daemon_view, check = self._bind_sources, self._daemon_view, self.check
            validate_intent(value)
            remaining = Deadline(self._now, deadline).remaining

            def bound():
                self._bound_observers()
                if (self.failed or self.bind_sources is not verifier or self.daemon_view is not daemon_view
                        or self.approval != approval or self.objects is not objects
                        or digest(canonical(intent)) != approval.intent_sha256
                        or digest(canonical(value)) != approval.intent_sha256
                        or objects.old_object_id != value["old_object_id"]
                        or objects.old_image_id != approval.old_image_id):
                    raise Rejected("deployment-approval-or-fence-changed")

            def current():
                remaining()
                bound()
                if check(deadline=deadline) is not True:
                    raise Rejected("deployment-approval-or-fence-changed")
                bound()
                remaining()
                bound()

            def observe():
                bound()
                state = objects.inspect(value["old_object_id"], deadline=deadline)
                bound()
                if state["running"] is not False or state["image_id"] != approval.old_image_id:
                    raise Rejected("deployment-old-object-not-stopped")
                projection = self._projection(objects, value["old_object_id"], approval, deadline)
                bound()
                return projection

            def namespace():
                if daemon_view is not None:
                    receipt = daemon_view.observe(deadline=deadline)
                    if (type(receipt) is not dict or set(receipt) != {"schema", "view_sha256",
                            "source_namespace_matches", "container_namespace_verified", "start_authorized"}
                            or receipt["schema"] != "host-recovery-process-mount-view-v1"
                            or receipt["source_namespace_matches"] is not True
                            or receipt["container_namespace_verified"] is not False
                            or receipt["start_authorized"] is not False):
                        raise Rejected("deployment-daemon-namespace-unconfirmed")
                    pin(receipt["view_sha256"])
                    remaining()
                    bound()

            def sources(projection):
                if verifier is not None:
                    namespace()
                    observed = copy.deepcopy(value)
                    receipt = verifier.verify_bind_sources(observed, projection["mounts"], deadline=deadline)
                    if (canonical(observed) != canonical(value) or type(receipt) is not dict
                            or receipt != {"schema": "host-recovery-bind-source-result-v1",
                                "baseline_sha256": value["baseline_sha256"], "mounts": len(projection["mounts"]),
                                "bind_source_baseline_verified": True, "container_namespace_verified": False,
                                "start_authorized": False}
                            or receipt["bind_source_baseline_verified"] is not True
                            or receipt["container_namespace_verified"] is not False
                            or receipt["start_authorized"] is not False):
                        raise Rejected("deployment-bind-source-observation-unconfirmed")
                    bound()
                    namespace()

            current()
            for _ in range(2):
                sources(observe())
                current()
            # Source verification invokes its own fence callbacks; reobserve the
            # daemon after those reads, never infer container namespace identity.
            projection = observe()
            if verifier is not None:
                sources(projection)
                observe()
            remaining()
            bound()
            return {"schema": "host-recovery-deployment-result-v1", "object_id": value["old_object_id"],
                    "projection_sha256": approval.projection_sha256,
                    "bind_source_baseline_verified": verifier is not None,
                    "daemon_source_namespace_verified": daemon_view is not None,
                    "deployment_matches": True, "start_authorized": False}
        except BaseException:
            self.failed = True
            raise Rejected("deployment-observation-unconfirmed") from None
        finally:
            self._active = False


class RecoveredDeploymentBoundary:
    """Supplement, never manufacture, the independent baseline/start oracle."""
    def __init__(self, boundary, gate):
        if not isinstance(gate, OldDeploymentGate):
            raise Rejected("deployment-gate-required")
        self.boundary, self.gate = boundary, gate
        self.attempted, self.pending, self.failed = False, None, False

    def verify_baseline_stopped(self, intent, *, deadline):
        try:
            if self.attempted or self.failed:
                raise Rejected("deployment-oracle-once-only")
            self.attempted = True
            value, boundary, gate = copy.deepcopy(intent), self.boundary, self.gate
            original = canonical(value)
            observed = copy.deepcopy(value)
            receipt = copy.deepcopy(boundary.verify_baseline_stopped(observed, deadline=deadline))
            validate_baseline_receipt(value, receipt)
            if (canonical(intent) != original or canonical(observed) != original
                    or self.failed or self.boundary is not boundary or self.gate is not gate):
                raise Rejected("deployment-original-oracle-changed")
            observed = copy.deepcopy(value)
            gate.verify(observed, deadline=deadline)
            if (canonical(intent) != original or canonical(observed) != original
                    or self.failed or self.boundary is not boundary or self.gate is not gate):
                raise Rejected("deployment-original-oracle-changed")
            self.pending = (digest(original), canonical(receipt), boundary, gate)
            return copy.deepcopy(receipt)
        except Exception:
            self.failed = True
            raise Rejected("deployment-baseline-oracle-unconfirmed") from None

    def start_old(self, intent, receipt, *, deadline):
        try:
            value, saved = copy.deepcopy(intent), copy.deepcopy(receipt)
            if (self.failed or self.pending is None
                    or self.pending[:2] != (digest(canonical(value)), canonical(saved))
                    or self.pending[2] is not self.boundary or self.pending[3] is not self.gate):
                raise Rejected("deployment-original-oracle-required")
            self.pending = None
            boundary, gate = self.boundary, self.gate
            observed = copy.deepcopy(value)
            gate.verify(observed, deadline=deadline)
            if (canonical(intent) != canonical(value) or canonical(observed) != canonical(value)
                    or canonical(receipt) != canonical(saved)
                    or self.failed or self.boundary is not boundary or self.gate is not gate):
                raise Rejected("deployment-original-oracle-changed")
            return boundary.start_old(value, saved, deadline=deadline)
        except Exception:
            self.failed = True
            raise Rejected("deployment-old-start-unconfirmed") from None

    def __getattr__(self, name):
        return getattr(self.boundary, name)
