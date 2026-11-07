"""One-shot request-instance systemd dispatch; no installation or privilege grant.

Only the digest-named, pinned separate recovery unit can be enqueued. The live
supervisor authorization must retain the installation lock, revalidate the durable
request/owner and independently enforce the complete fence. A matching callback
reply alone does not authenticate that boundary. No worker execution, restoration,
service-start grant or recovery outcome is proved by the enqueue acknowledgment.
"""
import copy
import math
import os
import time

from .budget import positive
from .commands import Deadline
from .durable import Rejected, canonical, digest
from .jobs import RecoveryJobBinding, SystemdRecoveryJobs, recovery_unit
from .inventory import HASH
from .manager import fragment_hash
from .supervisor import validate_owner


def validate_request(request, binding, boot, now):
    try:
        _validate_request(request, binding, boot, now)
    except Rejected:
        raise
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise Rejected("dispatch-request-schema") from None


def _validate_request(request, binding, boot, now):
    fields = {"schema", "attempt_id", "intent_sha256", "owner", "original_arm", "failure_lower_bound",
              "deadline", "detection_upper_bound_seconds", "forward_allowed", "production_acceptance", "request_id"}
    if (type(request) is not dict or set(request) != fields
            or request["schema"] != "host-recovery-reconcile-request-v1"
            or request["request_id"] != binding.request_id
            or type(request["intent_sha256"]) is not str or HASH.fullmatch(request["intent_sha256"]) is None
            or request["forward_allowed"] is not False or request["production_acceptance"] is not False):
        raise Rejected("dispatch-request-schema")
    unsigned = {key: value for key, value in request.items() if key != "request_id"}
    if request["request_id"] != digest(canonical(unsigned)):
        raise Rejected("dispatch-request-pin")
    validate_owner(request["owner"])
    arm = request["original_arm"]
    if (request["owner"]["attempt_id"] != request["attempt_id"] or request["owner"]["boot_id"] != boot
            or request["owner"]["unit"] == recovery_unit(binding.request_id)
            or type(arm) is not dict or set(arm) != {"boot_id", "monotonic"}
            or arm["boot_id"] != boot or not positive(arm["monotonic"])
            or canonical(request["failure_lower_bound"]) != canonical(arm["monotonic"])):
        raise Rejected("dispatch-request-owner-or-arm")
    elapsed = request["detection_upper_bound_seconds"]
    if (not positive(now) or not positive(request["deadline"])
            or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0
            or arm["monotonic"] + elapsed > now
            or arm["monotonic"] + elapsed >= request["deadline"]
            or request["deadline"] > arm["monotonic"] + 180 or now >= request["deadline"]):
        raise Rejected("dispatch-original-budget-required")


class SystemdRecoveryDispatch:
    """Use once inside RecoverySupervisor's synchronous enqueue boundary.

    authorize must be the current supervisor's authorize_dispatch method in an
    integrated service, not a caller assertion. It is checked before observation,
    immediately before enqueue and after the local reply. The supervisor retains
    the durable request after any ambiguity. A new instance is NOT retry authority;
    the supervisor's persisted no-redispatch rule applies across process restarts.
    """
    def __init__(self, *, systemctl, commands, binding, authorize, boot_id, clock=time.monotonic,
                 read_fragment_hash=fragment_hash):
        if type(systemctl) is not str or not os.path.isabs(systemctl):
            raise Rejected("explicit-systemctl-required")
        if not isinstance(binding, RecoveryJobBinding) or not callable(authorize):
            raise Rejected("dispatch-binding-and-authorization-required")
        self.systemctl, self.commands, self.binding = systemctl, commands, binding
        self.authorize, self.boot_id, self.clock = authorize, boot_id, clock
        self.observer = SystemdRecoveryJobs(systemctl=systemctl, commands=commands, binding=binding,
            boot_id=boot_id, clock=clock, read_fragment_hash=read_fragment_hash)
        self.attempted = False

    def enqueue_recovery(self, request, *, deadline):
        if self.attempted:
            raise Rejected("dispatch-already-attempted")
        # Even validation/query failures exhaust this object. Never retry a lost
        # reply, replace a running worker, reset-failed or infer a vanished job.
        self.attempted = True
        request = copy.deepcopy(request)
        boot = self.boot_id()
        validate_request(request, self.binding, boot, self.clock())
        if not positive(deadline) or deadline > request["deadline"]:
            raise Rejected("dispatch-deadline-required")
        timer = Deadline(self.clock, deadline)

        def current(phase):
            timer.remaining()
            if (self.boot_id() != boot
                    or self.authorize(copy.deepcopy(request), deadline=deadline, phase=phase) is not True):
                raise Rejected("dispatch-supervisor-authorization-required")
            if self.boot_id() != boot:
                raise Rejected("dispatch-boot-changed")
            timer.remaining()

        current("observe")
        observed = self.observer.observe(request["request_id"], deadline=deadline)
        if (observed["state"] != "inactive_unverified" or observed["invocation_id"] != ""
                or observed["job_id"] != 0):
            raise Rejected("dispatch-existing-job-reconciliation-required")
        # Inactive with no invocation is necessary, NOT proof of no prior job.
        # Only the live supervisor's durable single-dispatch lease allows this.
        current("enqueue")
        raw = self.commands.run((self.systemctl, "--no-block", "start", "--",
                                 recovery_unit(request["request_id"])), deadline=deadline)
        if type(raw) is not bytes or raw != b"":
            raise Rejected("dispatch-enqueue-reply-unconfirmed")
        current("acknowledge")
        return {"request_id": request["request_id"], "accepted": True, "separate_recovery_owner": True}
