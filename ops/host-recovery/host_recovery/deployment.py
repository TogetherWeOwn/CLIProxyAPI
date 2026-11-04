"""Read-only old-container deployment correspondence, never start authority.

Full Config/HostConfig and effective Mounts are restricted transient input. Only
hashes leave this reader; do not persist/log its raw daemon response. An external
approved projection digest is required, not a pin learned from the current daemon.
This does not authenticate approval, inspect mounted bytes or implement a fence.
"""
import copy
from dataclasses import dataclass

from .commands import Deadline, MAX_OUTPUT
from .coordinator import validate_baseline_receipt
from .daemon import DockerObjects
from .durable import Rejected, canonical, decode, digest
from .journal import validate_intent
from .loading import pin

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
    def __init__(self, *, objects, approval, check, clock):
        if (not isinstance(objects, DockerObjects) or not isinstance(approval, DeploymentApproval)
                or not callable(check) or not callable(clock)):
            raise Rejected("deployment-explicit-boundaries-required")
        self.objects, self.approval, self.check, self.clock = objects, approval, check, clock
        self.failed = False

    def _projection(self, object_id, approval, deadline):
        raw = self.objects._run(("container", "inspect", "--format=" + FORMAT, object_id), deadline)
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

    def verify(self, intent, *, deadline):
        try:
            if self.failed:
                raise Rejected("deployment-gate-unavailable")
            value, approval = copy.deepcopy(intent), self.approval
            validate_intent(value)
            remaining = Deadline(self.clock, deadline).remaining

            def current():
                remaining()
                if (self.approval != approval or digest(canonical(intent)) != approval.intent_sha256
                        or digest(canonical(value)) != approval.intent_sha256
                        or self.objects.old_object_id != value["old_object_id"]
                        or self.objects.old_image_id != approval.old_image_id
                        or self.check(deadline=deadline) is not True):
                    raise Rejected("deployment-approval-or-fence-changed")
                # The callback may itself change these borrowed objects.
                if (self.approval != approval or digest(canonical(intent)) != approval.intent_sha256
                        or self.objects.old_object_id != value["old_object_id"]
                        or self.objects.old_image_id != approval.old_image_id):
                    raise Rejected("deployment-approval-or-fence-changed")
                remaining()

            current()
            for _ in range(2):
                state = self.objects.inspect(value["old_object_id"], deadline=deadline)
                if state["running"] is not False or state["image_id"] != approval.old_image_id:
                    raise Rejected("deployment-old-object-not-stopped")
                self._projection(value["old_object_id"], approval, deadline)
                current()
            # A final projection follows the last external callback. This is only
            # correspondence under the independently enforced fence, not its proof.
            state = self.objects.inspect(value["old_object_id"], deadline=deadline)
            if state["running"] is not False or state["image_id"] != approval.old_image_id:
                raise Rejected("deployment-old-object-not-stopped")
            self._projection(value["old_object_id"], approval, deadline)
            remaining()
            return {"schema": "host-recovery-deployment-result-v1", "object_id": value["old_object_id"],
                    "projection_sha256": approval.projection_sha256,
                    "deployment_matches": True, "start_authorized": False}
        except Exception:
            self.failed = True
            raise Rejected("deployment-observation-unconfirmed") from None


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
            receipt = copy.deepcopy(self.boundary.verify_baseline_stopped(copy.deepcopy(intent), deadline=deadline))
            validate_baseline_receipt(intent, receipt)
            self.gate.verify(intent, deadline=deadline)
            self.pending = (digest(canonical(intent)), canonical(receipt))
            return copy.deepcopy(receipt)
        except Exception:
            self.failed = True
            raise Rejected("deployment-baseline-oracle-unconfirmed") from None

    def start_old(self, intent, receipt, *, deadline):
        try:
            value, saved = copy.deepcopy(intent), copy.deepcopy(receipt)
            if (self.failed or self.pending is None
                    or self.pending != (digest(canonical(value)), canonical(saved))):
                raise Rejected("deployment-original-oracle-required")
            self.pending = None
            self.gate.verify(intent, deadline=deadline)
            return self.boundary.start_old(value, saved, deadline=deadline)
        except Exception:
            self.failed = True
            raise Rejected("deployment-old-start-unconfirmed") from None

    def __getattr__(self, name):
        return getattr(self.boundary, name)
