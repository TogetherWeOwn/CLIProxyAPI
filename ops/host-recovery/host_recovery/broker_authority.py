"""Live original-supervisor checks for the future separate privileged broker.

This is a revoking point observation, not IPC, a permit, a complete runtime fence
or an effect handler. The broker must obtain its approvals, bindings, executable
transport and topology pin independently of the requesting peer. It must repeat
these checks inside each future fixed effect barrier; a saved receipt cannot be
used as authorization. No operational runner consumes this component yet.
"""
from .bootstrap import SystemdSupervisorIdentity
from .broker_history import original_binding
from .broker_operations import positive, validate_binding
from .durable import Rejected, canonical, decode
from .installation import open_approved_directory
from .jobs import RecoveryJobBinding
from .loading import RecoveryApproval, load_recovery
from .lock_observation import OriginalLockObservation
from .supervisor import validate_owner


class SupervisorPeerAuthority:
    """Compose original journal/lock, live kernel peer and pinned manager identity.

    The independently opened journal descriptor is never locked or transferred.
    Neither a request's PID/UID claims nor environment identity supplies authority.
    All observations use the same shortened original deadline. On uncertainty this
    object is permanently revoked; reconnect/reconstruction does not reconcile
    pending broker work or revive any old operation admission.
    """
    def __init__(self, *, lock, manager, approval, recovery_binding, supervisor_owner,
                 binding, deadline):
        if (not isinstance(lock, OriginalLockObservation)
                or not isinstance(manager, SystemdSupervisorIdentity)
                or not isinstance(approval, RecoveryApproval)
                or not isinstance(recovery_binding, RecoveryJobBinding)):
            raise Rejected("broker-authority-explicit-boundaries-required")
        validate_owner(supervisor_owner)
        validate_binding(binding)
        peer = lock.peer.peer
        if ((peer["uid"], peer["gid"]) != (manager.binding.uid, manager.binding.gid)
                or (approval.uid, approval.gid) != (peer["uid"], peer["gid"])
                or manager.binding.unit != supervisor_owner["unit"]
                or any(binding[key] != supervisor_owner[key] for key in ("installation_id", "attempt_id"))
                or binding["original_boot_id"] != supervisor_owner["boot_id"]
                or not positive(deadline) or deadline > min(lock.deadline, binding["recovery_deadline"])):
            raise Rejected("broker-authority-original-owner-required")
        self.lock, self.manager = lock, manager
        self.approval, self.recovery_binding = approval, recovery_binding
        self._owner, self._binding = canonical(supervisor_owner), canonical(binding)
        self._peer = canonical(peer)
        self.deadline = deadline
        self.failed, self.last_clock, self._observed = False, None, None

    def _time(self, deadline):
        now = self.lock.clock()
        if (not positive(now) or now < decode(self._binding)["failure_monotonic"] or now >= deadline
                or self.last_clock is not None and now < self.last_clock):
            raise Rejected("broker-authority-clock-or-deadline-unconfirmed")
        self.last_clock = now
        return now

    def _live(self, deadline):
        if (self.failed or self.lock.failed or self.manager.revoked
                or not positive(deadline) or deadline > self.deadline):
            raise Rejected("broker-authority-observation-revoked")
        self._time(deadline)
        if (self.manager.boot_id() != decode(self._binding)["original_boot_id"]
                or canonical(self.lock.peer.peer) != self._peer or not self.lock.peer.alive()):
            raise Rejected("broker-authority-peer-clock-or-deadline-unconfirmed")
        # Boot and peer reads are external boundaries too. Their elapsed time
        # cannot escape the last deadline check before returning an observation.
        return self._time(deadline)

    def _manager_owner(self, deadline):
        self._live(deadline)
        peer, owner = decode(self._peer), decode(self._owner)
        # _row is the existing strict unit/fragment/static-command reader. Unlike
        # bootstrap(), a foreign MainPID needs the connection-bound pidfd around
        # every query and process-cgroup observation.
        before = self.manager._row(deadline=deadline, pid=peer["pid"])
        self._live(deadline)
        group = self.manager.read_process_cgroup(peer["pid"])
        after = self.manager._row(deadline=deadline, pid=peer["pid"])
        if (before != after or after["invocation_id"] != owner["invocation_id"]
                or after["cgroup"] != group
                or self.manager.read_process_cgroup(peer["pid"]) != group):
            raise Rejected("broker-authority-manager-identity-changed")
        raw = canonical(after)
        if self._observed is not None and raw != self._observed:
            raise Rejected("broker-authority-manager-identity-changed")
        self._live(deadline)
        return raw

    def _inputs(self, deadline):
        with open_approved_directory(self.lock.journal) as journal:
            inputs = load_recovery(journal.fd, approval=self.approval, binding=self.recovery_binding,
                supervisor_owner=decode(self._owner), boot_id=self.manager.boot_id(), now=self._live(deadline))
            actual = original_binding(inputs, topology_sha256=decode(self._binding)["topology_sha256"])
            if canonical(actual) != self._binding:
                raise Rejected("broker-authority-original-inputs-changed")
            journal.validate()
            self._live(deadline)
        self._live(deadline)

    def observe(self, *, deadline):
        """Fresh point checks only; no mutation, pending publication or start grant.

        A manager read can outlive a preceding lock read, and a protected input
        read can outlive a preceding peer read. Repeat lock/kernel observations
        after those boundaries and after directory context-exit validation. This
        cannot make the observations atomic or recall an already submitted call.
        """
        try:
            self._live(deadline)
            first = self._manager_owner(deadline)
            self.lock.observe(deadline=deadline)
            self._inputs(deadline)
            if self._manager_owner(deadline) != first:
                raise Rejected("broker-authority-manager-identity-changed")
            # Manager/helper reads may outlive the first input capture. Do not
            # return a clean original-input observation from that earlier prefix.
            self._inputs(deadline)
            self.lock.observe(deadline=deadline)
            self._live(deadline)
            self._observed = first
            # Shortening is sticky even across later observations on this object.
            self.deadline = deadline
            return {"schema": "host-recovery-broker-authority-observation-v1",
                    "original_supervisor_observed": True, "original_lock_observed": True,
                    "original_inputs_observed": True, "pending_drained": False,
                    "complete_fence_proven": False, "recovery_execution_allowed": False,
                    "start_allowed": False, "settlement_allowed": False, "production_acceptance": False}
        except Exception:
            self.failed = True
            raise Rejected("broker-authority-observation-unconfirmed") from None
