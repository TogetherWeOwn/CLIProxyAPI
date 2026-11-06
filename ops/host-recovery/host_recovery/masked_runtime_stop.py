"""Original-pending dedicated-runtime masks, stop completions and slice kill.

Explicit embedding/containment IPC only; no operational runner enables it.
Trusted provisioning must
bind every runtime/shim/task and activation/writer path to the approved domain.
A recursive kill and repeated empty observations do not establish that coverage,
old-epoch death, quarantine reconciliation, pending drain or recovery authority.
"""
from .broker_operations import OperationJournal
from .broker_runtime import RuntimeDomain
from .durable import Rejected, canonical, decode, digest
from .manager_jobs import RuntimeStopJobs, completion_name
from .masked_forward_stop import _MaskedFixedStop
from .persisted_policy import PersistedObjectPolicy
from .runtime_kill import record_names
from .runtime_processes import RuntimeProcessWitness
from .topology import RUNTIME_ROLES


class MaskedRuntimeStop(_MaskedFixedStop):
    method = "cold_quiesce_runtime"
    jobs_type = RuntimeStopJobs
    roles = RUNTIME_ROLES
    target_schema = "host-recovery-masked-runtime-stop-target-v1"
    observation_schema = "host-recovery-masked-runtime-stop-observation-v1"

    def __init__(self, *, journal, masks, jobs, domain, authority=None, policy=None):
        if policy is not None and (not isinstance(policy, PersistedObjectPolicy) or policy.authority is not authority):
            raise Rejected("masked-runtime-original-persisted-policy-required")
        self.policy = self._original_policy = policy
        self._policy_observation = None
        if (not isinstance(journal, OperationJournal) or not isinstance(domain, RuntimeDomain)
                or not isinstance(jobs, RuntimeStopJobs)
                or any(unit.cgroup != domain.cgroup + "/" + unit.unit for unit in jobs.units.values())
                or "contain_forward" not in journal._returned):
            raise Rejected("masked-runtime-original-domain-and-forward-return-required")
        # A previous return is sequencing evidence, NOT forward quiescence/drain.
        if policy is not None:
            runtime = policy.topology.manifest()["runtime"]
            if (runtime["cgroup_path"] != domain.cgroup
                    or any(runtime["units"][role] != {"unit": unit.unit, "effective_sha256": unit.properties_sha256}
                           for role, unit in jobs.units.items())):
                raise Rejected("masked-runtime-persisted-policy-topology-mismatch")
        self.domain = self._original_domain = domain
        self._forward = journal._pending.get("contain_forward")
        if self._forward is None:
            raise Rejected("masked-runtime-original-forward-required")
        self._domain_killed = False
        self._witness = None
        domain.current()
        super().__init__(journal=journal, masks=masks, jobs=jobs, authority=authority)

    def configuration(self):
        value = decode(super().configuration())
        value.update(domain=decode(self.domain.configuration()), forward_operation_sha256=digest(self._forward),
                     persisted_policy=None if self.policy is None else decode(self.policy.configuration()))
        return canonical(value)

    def _current(self):
        super()._current()
        if (self.domain is not self._original_domain or self.policy is not self._original_policy
                or self.policy is not None and (self.policy.failed or self.policy.authority is not self.authority)
                or self._forward != self.journal._pending.get("contain_forward")
                or "contain_forward" not in self.journal._returned):
            raise Rejected("masked-runtime-original-domain-or-forward-changed")
        self.domain.current()
        super()._current()

    def _before_stops(self):
        self._witness = RuntimeProcessWitness.capture(domain=self.domain, check=self._current)
        self._current()

    def _release(self):
        if self._witness is not None:
            self._witness.close()

    def _after_stops(self):
        self._current()
        if self._domain_killed:
            raise Rejected("masked-runtime-domain-kill-exhausted")
        operation = decode(self._operation)
        pending_name, return_name, empty_name = record_names(operation["sequence"])
        pending = {"schema": "host-recovery-runtime-kill-pending-v1", "operation_id": operation["operation_id"],
            "domain_sha256": digest(self.domain.configuration()),
            "stop_completions_sha256": {role: digest(self.journal._records[completion_name(operation["sequence"], role)][0])
                                        for role in self.roles}}
        # Durable intent precedes the kernel write. A lost return never permits
        # redispatch, including when the last durable record is only pending.
        self.journal._write(pending_name, pending)
        self._current()
        self._domain_killed = True
        self.domain.kill(check=self._current)
        self._current()
        returned = {"schema": "host-recovery-runtime-kill-return-v1", "pending_sha256": digest(canonical(pending)),
                    "recursive_domain_kill_returned": True, "pending_drained": False}
        self.journal._write(return_name, returned)
        self._current()
        while True:
            self._current()
            populated = self.domain.populated()
            if populated is False:
                break
            if populated is not True:
                raise Rejected("masked-runtime-populated-observation-unconfirmed")
            self._current()
            remaining = self.session.deadline - self.session.clock()
            if remaining <= 0:
                raise Rejected("masked-runtime-domain-deadline")
            self.session._connection.wait(max(1, min(50000, int(remaining * 1000000))))
        self._final_check()
        self.journal._write(empty_name, {"schema": "host-recovery-runtime-kill-empty-v1",
            "return_sha256": digest(canonical(returned)), "domain_empty_observed": True,
            "runtime_containment_coverage_proven": False})
        # Publication can itself lose authority or observe repopulation. Saved
        # observations cannot replace the final live check or grant a cold return.
        self._final_check()
        if self.policy is not None:
            self._policy_observation = canonical(self.policy.observe(deadline=self.session.deadline, check=self._current))
            self._final_check()
        return {"recursive_domain_kill_returned": True, "domain_empty_observed": True,
                "persisted_restart_policy_observed": self._policy_observation is not None, "runtime_relaunch_allowed": False,
                "observed_runtime_process_count": self._witness.count, "observed_runtime_processes_dead": True,
                "runtime_stop_completion_count": len(self.roles), "runtime_containment_coverage_proven": False}

    def _final_check(self):
        self.session._fixed_jobs_absent()
        self._execution_current()
        self._current()
        if not self._domain_killed or self.domain.populated() is not False:
            raise Rejected("masked-runtime-empty-domain-unconfirmed")
        self._current()
        if self._witness is None:
            raise Rejected("masked-runtime-process-witness-required")
        self._witness.require_dead(check=self._current)
        if self._policy_observation is not None:
            if canonical(self.policy.observe(deadline=self.session.deadline, check=self._current)) != self._policy_observation:
                raise Rejected("masked-runtime-persisted-policy-changed")
        # Authority/projection reads are external boundaries too. Recheck the
        # kernel observation after them; never turn a missing cgroup into zero.
        if self.domain.populated() is not False:
            raise Rejected("masked-runtime-trailing-domain-populated")
        self._current()
