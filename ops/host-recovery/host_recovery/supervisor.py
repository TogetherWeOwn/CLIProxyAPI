"""Recovery-only restart ownership and dispatch; not an installed supervisor.

The context retains the installation lock across manager observation, durable
request, dispatch and status. The manager and complete start fence are injected
boundaries, NOT implemented or authenticated by a matching dictionary here.
No start, restore, admission, settlement or privilege operation exists.

A reopened terminal-looking journal still requires recovery. With no durable
failure timestamp, charge the reserve conservatively from the original arm.
Cross-boot, expired or missing arm evidence needs a separately approved bounded
continuation; never manufacture a fresh 300-second budget on restart. A durable
request with an absent/lost reply must be reconciled by the manager, not retried.
"""
import copy
from contextlib import contextmanager
import math
import os
import stat

from .budget import positive
from .commands import Deadline
from .durable import Rejected, canonical, decode, digest, installation_lock, notify, read_file
from .journal import Journal, identity
from .jobs import recovery_unit, validate_observation
from .manager import INVOCATION, UNIT


def validate_owner(owner):
    fields = {"installation_id", "attempt_id", "unit", "invocation_id", "boot_id"}
    if (type(owner) is not dict or set(owner) != fields
            or any(not identity(value) for value in owner.values())
            or UNIT.fullmatch(owner["unit"]) is None
            or INVOCATION.fullmatch(owner["invocation_id"]) is None):
        raise Rejected("supervisor-manager-owner-required")


def private_record(fd, name):
    raw, info = read_file(fd, name, limit=65536)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise Rejected("supervisor-private-record-required")
    return decode(raw)


@contextmanager
def recovery_owner(path, *, owner, manager, clock, boot_id, persist_alert, transport_alert, fault=None,
                   observe_existing=False):
    """Hold one installation lock until the caller exits, including after dispatch.

    manager.observe_owner must return the actual independently inspected current
    manager owner. manager.fence must enforce *all* starts/writers and pending
    daemon operations, not merely report empty cgroups or restart=no. Its strict
    True is a required boundary acknowledgment, not proof of implementation.
    manager.enqueue_recovery must address only the separate pinned recovery unit,
    with request_id as its durable idempotency identity, and bound its local wait
    by deadline. Its returned receipt is enqueue acknowledgment only.

    observe_existing enables only read-only pending-job observation; it can never
    enqueue, even if the saved request is absent. It is not recovery execution.
    """
    validate_owner(owner)
    if type(observe_existing) is not bool:
        raise Rejected("supervisor-observation-mode-required")
    with installation_lock(path, owner) as (fd, bound_owner):
        instance = RecoverySupervisor(fd, owner=bound_owner, manager=manager, clock=clock,
                                      boot_id=boot_id, persist_alert=persist_alert,
                                      transport_alert=transport_alert, fault=fault,
                                      observe_existing=observe_existing)
        try:
            yield instance
        finally:
            # A reference retained outside the context cannot dispatch after the
            # fd/lock is released (or reused for an unrelated directory).
            instance.closed = True


class RecoverySupervisor:
    """One recovery request per retained journal, never a forward-work owner.

    Construct through recovery_owner. A manager must reconcile requests left by
    a dead supervisor; this class deliberately refuses automatic redispatch even
    if the previous enqueue receipt claims success. It never clears the latch.
    """
    def __init__(self, fd, *, owner, manager, clock, boot_id, persist_alert, transport_alert, fault=None,
                 observe_existing=False):
        self.fd, self.owner = fd, copy.deepcopy(owner)
        self.observe_existing = observe_existing
        self.pending_request = None
        self.job = None
        self.manager, self.clock, self.boot_id = manager, clock, boot_id
        self.persist_alert, self.transport_alert = persist_alert, transport_alert
        self.closed = False
        self.attempted = False
        self.dispatch_request = None
        self.dispatch_phase = None
        self.watch_started = False
        self.watch = None
        self.last_clock = None
        self.alert = None
        self.state = "fenced"
        self.error = None
        self.log = None
        self.intent_sha256 = None
        self.plan = None
        self.arm_sha256 = None
        self.initial_entries = set()
        try:
            self.initial_entries = set(os.listdir(fd))
            self.log = Journal(fd, fault=fault)
            if self.log.intent is None:
                raise Rejected("supervisor-recovery-intent-required")
            value = self.log.intent
            if (value["attempt_id"] != owner["attempt_id"]
                    or value["installation_id"] != owner["installation_id"]
                    or owner["boot_id"] != boot_id()):
                raise Rejected("supervisor-intent-owner-mismatch")
            self.log.revoke_forward()
            self.intent_sha256 = digest(canonical(value))
            # Both final and staged records are evidence of a possible enqueue.
            # Neither a terminal receipt nor a new invocation clears that fact.
            if (not observe_existing
                    and any(name.startswith(("reconcile-", ".stage-reconcile-")) for name in self.initial_entries)):
                raise Rejected("supervisor-dispatch-reconciliation-required")
            arm_record = private_record(fd, "arm.json")
            self.arm_sha256 = digest(canonical(arm_record))
            if (set(arm_record) != {"schema", "arm", "intent_sha256"}
                    or arm_record["schema"] != "host-recovery-arm-v1"
                    or arm_record["intent_sha256"] != self.intent_sha256):
                raise Rejected("supervisor-arm-pin-mismatch")
            arm = arm_record["arm"]
            if (type(arm) is not dict or set(arm) != {"boot_id", "monotonic"}
                    or arm["boot_id"] != value["owner"]["boot_id"] or not positive(arm["monotonic"])):
                raise Rejected("supervisor-arm-schema")
            if arm["boot_id"] != owner["boot_id"]:
                raise Rejected("supervisor-cross-boot-continuation-required")
            now = self._now()
            if now < arm["monotonic"]:
                raise Rejected("supervisor-clock-continuation-required")
            deadline = min(arm["monotonic"] + value["budget"]["recovery_seconds"],
                           arm["monotonic"] + value["budget"]["total_seconds"])
            if now >= deadline:
                raise Rejected("supervisor-expired-continuation-required")
            self.plan = {"schema": "host-recovery-reconcile-request-v1",
                         "attempt_id": value["attempt_id"], "intent_sha256": self.intent_sha256,
                         "owner": copy.deepcopy(owner), "original_arm": arm,
                         "failure_lower_bound": arm["monotonic"], "deadline": deadline,
                         "detection_upper_bound_seconds": now - arm["monotonic"],
                         "forward_allowed": False, "production_acceptance": False}
            self.plan["request_id"] = digest(canonical(self.plan))
            self.state = "recovery_required"
            if observe_existing:
                self.pending_request = self._pending_request()
                self.pending_sha256 = digest(canonical(self.pending_request))
                self.state = "recovery_dispatch_pending"
        except Exception as failure:
            self._fail(failure, "supervisor-state-unavailable")

    def _pending_request(self):
        allowed = {"reconcile-request.json", "reconcile-enqueued.json", "reconcile-observed.json"}
        names = {name for name in self.initial_entries if name.startswith(("reconcile-", ".stage-reconcile-"))}
        if "reconcile-request.json" not in names or not names <= allowed:
            raise Rejected("supervisor-dispatch-reconciliation-required")
        request = private_record(self.fd, "reconcile-request.json")
        if set(request) != set(self.plan):
            raise Rejected("supervisor-pending-request-schema")
        unsigned = {key: item for key, item in request.items() if key != "request_id"}
        if request["request_id"] != digest(canonical(unsigned)):
            raise Rejected("supervisor-pending-request-pin")
        validate_owner(request["owner"])
        for key in ("schema", "attempt_id", "intent_sha256", "original_arm", "failure_lower_bound",
                    "forward_allowed", "production_acceptance"):
            if canonical({key: request[key]}) != canonical({key: self.plan[key]}):
                raise Rejected("supervisor-pending-request-mismatch")
        if any(request["owner"][key] != self.owner[key] for key in
               ("installation_id", "attempt_id", "unit", "boot_id")):
            raise Rejected("supervisor-pending-owner-mismatch")
        elapsed = request["detection_upper_bound_seconds"]
        if (not positive(request["deadline"]) or request["deadline"] > self.plan["deadline"]
                or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0
                or elapsed > self.plan["detection_upper_bound_seconds"]
                or self.plan["failure_lower_bound"] + elapsed >= request["deadline"]):
            raise Rejected("supervisor-pending-request-budget")
        if "reconcile-enqueued.json" in names:
            receipt = private_record(self.fd, "reconcile-enqueued.json")
            expected = {"request_id": request["request_id"], "accepted": True, "separate_recovery_owner": True}
            if canonical(receipt) != canonical(expected):
                raise Rejected("supervisor-pending-enqueue-receipt")
        return request

    def _now(self):
        value = self.clock()
        if (self.boot_id() != self.owner["boot_id"] or not positive(value)
                or self.last_clock is not None and value < self.last_clock):
            raise Rejected("supervisor-clock-continuation-required")
        self.last_clock = value
        return value

    def _fail(self, failure, fallback):
        self.state = "recovery_unresolved"
        # Do not serialize exception messages from filesystem/manager boundaries.
        allowed = {"supervisor-recovery-intent-required", "supervisor-intent-owner-mismatch",
                   "supervisor-dispatch-reconciliation-required", "supervisor-arm-pin-mismatch",
                   "supervisor-arm-schema", "supervisor-cross-boot-continuation-required",
                   "supervisor-clock-continuation-required", "supervisor-expired-continuation-required",
                   "supervisor-watch-stopped", "supervisor-watch-expired",
                   "supervisor-worker-outcome-unverified", "supervisor-watch-observation-limit"}
        self.error = str(failure) if isinstance(failure, Rejected) and str(failure) in allowed else fallback
        notice = {"schema": "host-recovery-notice-v1", "attempt_id": self.owner["attempt_id"],
                  "original_cause": "supervisor-restart-recovery-required", "recovery_error": self.error,
                  "outcome": self.state, "start_fenced": True}
        self.alert = notify(notice, self.persist_alert, self.transport_alert)

    def _current(self, deadline):
        if self.closed:
            raise Rejected("supervisor-owner-closed")
        timer = Deadline(self._now, deadline)
        timer.remaining()
        current = private_record(self.fd, "intent.json")
        if (digest(canonical(current)) != self.intent_sha256 or self.log.uncertain
                or digest(canonical(private_record(self.fd, "arm.json"))) != self.arm_sha256
                or set(os.listdir(self.fd)) != self.initial_entries):
            raise Rejected("supervisor-state-changed")
        actual = self.manager.observe_owner(copy.deepcopy(self.owner), deadline=deadline)
        if type(actual) is not dict or actual != self.owner:
            raise Rejected("supervisor-manager-owner-unconfirmed")
        if self.manager.fence(copy.deepcopy(self.log.intent), deadline=deadline) is not True:
            raise Rejected("supervisor-complete-fence-unconfirmed")
        after = self.manager.observe_owner(copy.deepcopy(self.owner), deadline=deadline)
        if type(after) is not dict or after != self.owner:
            raise Rejected("supervisor-manager-owner-unconfirmed")
        timer.remaining()

    def reconcile(self, *, deadline):
        """One bounded enqueue attempt; never interpret acknowledgment as recovery.

        deadline can shorten but cannot extend the original inclusive reserve.
        Failures before/after the durable request are latched in this invocation.
        On restart, the saved request forbids another enqueue. No automatic retry,
        terminal result, restoration permission or service-start grant is issued.
        """
        if (self.closed or self.attempted or self.plan is None or self.error is not None
                or self.observe_existing):
            raise Rejected("supervisor-reconciliation-not-authorized")
        self.attempted = True
        try:
            if not positive(deadline):
                raise Rejected("supervisor-deadline-required")
            end = min(deadline, self.plan["deadline"])
            self._current(end)
            request = copy.deepcopy(self.plan)
            request["deadline"] = end
            # Rebind the correlation digest to the exact shortened request.
            request.pop("request_id")
            request["request_id"] = digest(canonical(request))
            self.log._write("reconcile-request.json", request)
            self.initial_entries.add("reconcile-request.json")
            # Recheck after persistence: a slow fsync, owner loss or a newly
            # pending start must not be followed by an out-of-budget enqueue.
            self._current(end)
            self.dispatch_request = copy.deepcopy(request)
            self.dispatch_phase = "observe"
            try:
                receipt = self.manager.enqueue_recovery(copy.deepcopy(request), deadline=end)
                # Legacy injected managers remain an external trusted boundary.
                # Once the narrow lease is used, all three phases must complete;
                # swallowing a denied/partial lease cannot fabricate an ACK.
                if self.dispatch_phase not in ("observe", "complete"):
                    raise Rejected("supervisor-dispatch-lease-incomplete")
            finally:
                self.dispatch_request = None
                self.dispatch_phase = None
            Deadline(self._now, end).remaining()
            expected = {"request_id": request["request_id"], "accepted": True,
                        "separate_recovery_owner": True}
            if (type(receipt) is not dict or set(receipt) != set(expected)
                    or any(type(receipt[key]) is not type(item) or receipt[key] != item
                           for key, item in expected.items())):
                raise Rejected("supervisor-enqueue-unconfirmed")
            self.log._write("reconcile-enqueued.json", receipt)
            self.initial_entries.add("reconcile-enqueued.json")
            Deadline(self._now, end).remaining()
            self.pending_request = copy.deepcopy(request)
            self.pending_sha256 = digest(canonical(request))
            self.state = "recovery_enqueued"
        except Exception as failure:
            self._fail(failure, "supervisor-dispatch-unconfirmed")
        return self.status()

    def authorize_dispatch(self, request, *, deadline, phase):
        """Revalidate the synchronous dispatch lease, never create one from a file.

        Only the single enqueue call made after durable request readback has this
        lease. Before/after it, on reopen, failure or close there is no grant, even
        if the exact request remains on disk. The caller must not treat this as a
        worker/start permission or a replacement for the complete fence boundary.
        """
        try:
            next_phase = {"observe": "enqueue", "enqueue": "acknowledge", "acknowledge": "complete"}
            if (self.closed or self.dispatch_request is None or self.error is not None
                    or self.observe_existing or type(phase) is not str or phase not in next_phase
                    or phase != self.dispatch_phase or not positive(deadline)
                    or deadline > self.dispatch_request["deadline"]
                    or canonical(request) != canonical(self.dispatch_request)):
                raise Rejected("supervisor-dispatch-lease-required")
            # Consume before calling external boundaries; reentry or any failed
            # validation revokes the lease for the rest of this enqueue call.
            self.dispatch_phase = None
            self._current(deadline)
            if canonical(private_record(self.fd, "reconcile-request.json")) != canonical(self.dispatch_request):
                raise Rejected("supervisor-dispatch-request-changed")
            Deadline(self._now, deadline).remaining()
            self.dispatch_phase = next_phase[phase]
            return True
        except Exception:
            self.dispatch_request = None
            self.dispatch_phase = None
            raise

    def observe_pending(self, *, observer, deadline):
        """Reconcile one existing dispatch by observation only, never enqueue again.

        A request-digest-named pinned unit identifies the work. Bind the first
        nonempty manager invocation durably, then refuse any replacement/loss of
        that invocation. Even a stable inactive result is unverified, not a safe
        retry boundary or a recovery outcome. Complete start fencing is separate.
        """
        if (self.closed or self.attempted or not self.observe_existing
                or self.pending_request is None or self.error is not None):
            raise Rejected("supervisor-pending-observation-not-authorized")
        self.attempted = True
        return self._observe_pending(observer=observer, deadline=deadline)

    def watch_pending(self, *, observer, deadline, interval, max_observations, stop, wait):
        """Retain the installation lock while following a pending/running job.

        stop() returns a strict boolean; wait(seconds) is an interruptible local
        wait returning True for shutdown, False only after that interval elapsed
        (for example threading.Event.is_set / wait). Neither callback grants any
        permission. Every observation revalidates owner, fence and durable pins.
        Shutdown, expiry, worker exit or uncertainty ends unresolved and alerts;
        none clears the intent or restarts dispatch. This is a bounded loop core,
        not manager service installation or a recovery-outcome oracle.
        """
        fresh = self.observe_existing and not self.attempted
        enqueued = not self.observe_existing and self.state == "recovery_enqueued"
        if (self.closed or self.watch_started or self.error is not None
                or self.pending_request is None or not (fresh or enqueued)):
            raise Rejected("supervisor-watch-not-authorized")
        self.watch_started = True
        self.attempted = True
        try:
            if (not positive(deadline) or not positive(interval)
                    or type(max_observations) is not int or not 1 <= max_observations <= 4096):
                raise Rejected("supervisor-watch-budget-required")
            end = min(deadline, self.pending_request["deadline"])
            start = self._now()
            self.watch = {"started_monotonic": start, "last_monotonic": start,
                          "deadline": end, "observations": 0, "max_observations": max_observations,
                          "sampled_elapsed_seconds": 0.0}
            while True:
                now = self._now()
                self.watch["last_monotonic"] = now
                self.watch["sampled_elapsed_seconds"] = now - start
                if now >= end:
                    raise Rejected("supervisor-watch-expired")
                stopping = stop()
                if type(stopping) is not bool:
                    raise Rejected("supervisor-watch-stop-schema")
                if stopping:
                    raise Rejected("supervisor-watch-stopped")
                result = self._observe_pending(observer=observer, deadline=end)
                if result["state"] == "recovery_unresolved":
                    return result
                self.watch["observations"] += 1
                now = self._now()
                self.watch["last_monotonic"] = now
                self.watch["sampled_elapsed_seconds"] = now - start
                if result["state"] == "recovery_job_inactive_unverified":
                    raise Rejected("supervisor-worker-outcome-unverified")
                if self.watch["observations"] >= max_observations:
                    raise Rejected("supervisor-watch-observation-limit")
                delay = min(interval, end - now)
                if delay <= 0:
                    raise Rejected("supervisor-watch-expired")
                interrupted = wait(delay)
                if type(interrupted) is not bool:
                    raise Rejected("supervisor-watch-wait-schema")
                after = self._now()
                self.watch["last_monotonic"] = after
                self.watch["sampled_elapsed_seconds"] = after - start
                if interrupted:
                    raise Rejected("supervisor-watch-stopped")
                # Refuse early/spurious returns instead of spinning manager calls.
                if after <= now or after < now + delay:
                    raise Rejected("supervisor-watch-wait-incomplete")
        except Exception as failure:
            self._fail(failure, "supervisor-watch-unconfirmed")
        return self.status()

    def _observe_pending(self, *, observer, deadline):
        try:
            if not positive(deadline):
                raise Rejected("supervisor-deadline-required")
            request = self.pending_request
            end = min(deadline, request["deadline"])

            def current():
                self._current(end)
                if digest(canonical(private_record(self.fd, "reconcile-request.json"))) != self.pending_sha256:
                    raise Rejected("supervisor-pending-request-changed")
                # A previously present enqueue receipt may not change in place.
                if canonical(self._pending_request()) != canonical(request):
                    raise Rejected("supervisor-pending-request-changed")
                Deadline(self._now, end).remaining()

            current()
            value = copy.deepcopy(observer.observe(request["request_id"], deadline=end))
            validate_observation(value, request["request_id"], self.owner["boot_id"])
            if (value["unit"] == self.owner["unit"]
                    or value["invocation_id"] in (self.owner["invocation_id"], request["owner"]["invocation_id"])):
                raise Rejected("supervisor-separate-recovery-owner-unconfirmed")
            current()
            bound = {"schema": "host-recovery-job-binding-v1", "request_id": request["request_id"],
                     "unit": recovery_unit(request["request_id"]), "boot_id": self.owner["boot_id"],
                     "invocation_id": value["invocation_id"]}
            if "reconcile-observed.json" in self.initial_entries:
                if canonical(private_record(self.fd, "reconcile-observed.json")) != canonical(bound):
                    raise Rejected("supervisor-recovery-invocation-changed")
            elif value["invocation_id"]:
                self.log._write("reconcile-observed.json", bound)
                self.initial_entries.add("reconcile-observed.json")
            current()
            after = copy.deepcopy(observer.observe(request["request_id"], deadline=end))
            validate_observation(after, request["request_id"], self.owner["boot_id"])
            if canonical(value) != canonical(after):
                raise Rejected("supervisor-recovery-job-changed")
            current()
            if ("reconcile-observed.json" in self.initial_entries
                    and canonical(private_record(self.fd, "reconcile-observed.json")) != canonical(bound)):
                raise Rejected("supervisor-recovery-binding-changed")
            Deadline(self._now, end).remaining()
            self.job = copy.deepcopy(value)
            self.state = "recovery_job_" + value["state"]
        except Exception as failure:
            self._fail(failure, "supervisor-job-observation-unconfirmed")
        return self.status()

    def status(self):
        return {"schema": "host-recovery-supervisor-status-v1", "state": self.state,
                "error": self.error, "owner_closed": self.closed,
                "forward_allowed": False, "start_permission": False,
                "recovery_completed": False, "installation_start_fence_proven": False,
                "production_acceptance": False, "alert": copy.deepcopy(self.alert),
                "job": copy.deepcopy(self.job), "watch": copy.deepcopy(self.watch)}
