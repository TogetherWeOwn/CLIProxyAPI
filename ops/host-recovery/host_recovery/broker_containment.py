"""Fixed forward-unit containment submission under original peer/lock checks.

This embedding adapter is not installed or exposed by the observation protocol.
It submits only stop/whole-unit SIGKILL for an independently pinned forward unit.
It does not cancel/drain daemon work, implement the cold barrier, or authorize
restoration/start. Unit-name manager calls are not invocation-atomic: exclusive
provisioned activation ownership remains a prerequisite, not an inferred fact.
"""
from dataclasses import asdict

from .broker_authority import SupervisorPeerAuthority
from .broker_operations import OperationJournal
from .durable import Rejected, canonical, decode, digest
from .manager import SystemdMutators
from .manager_jobs import ForwardStopJobs
from .topology import Topology, within
from .unit_masks import PersistentUnitMasks


class ForwardContainment:
    """One fixed operation, serialized through the existing broker journal mutex.

    No installation lock is acquired here. The peer must still own the original
    one. All constructor inputs and command/helper lifetimes belong to the trusted
    embedding broker, not an IPC packet, worker callback or returned receipt.
    """
    def __init__(self, *, authority, journal, mutators, topology, jobs=None, masks=None):
        if (not isinstance(authority, SupervisorPeerAuthority) or not isinstance(journal, OperationJournal)
                or not isinstance(mutators, SystemdMutators) or not isinstance(topology, Topology)):
            raise Rejected("broker-containment-explicit-boundaries-required")
        self.authority, self.journal, self.mutators, self.topology = authority, journal, mutators, topology
        value = topology.manifest()
        if jobs is not None and (not isinstance(jobs, ForwardStopJobs) or jobs.journal is not journal
                or jobs.units != {"forward": mutators.forward}
                or jobs.busctl_sha256 != value["tools"]["busctl"]["sha256"]):
            raise Rejected("broker-containment-original-forward-jobs-required")
        if masks is not None and (not isinstance(masks, PersistentUnitMasks)
                or masks.units != {"forward": mutators.forward} or masks.attempted):
            raise Rejected("broker-containment-original-forward-masks-required")
        self.masks = self._original_masks = masks
        self.jobs = self._original_jobs = jobs
        owner, binding = decode(authority._owner), decode(authority._binding)
        if (authority._binding != journal._binding or topology.sha256 != binding["topology_sha256"]
                or value["installation_id"] != binding["installation_id"]
                or value["roles"]["supervisor"]["unit"] != owner["unit"]
                or (value["roles"]["supervisor"]["uid"], value["roles"]["supervisor"]["gid"])
                    != (authority.manager.binding.uid, authority.manager.binding.gid)
                or value["roles"]["forward"]["unit"] != mutators.forward.unit
                or value["roles"]["forward"]["effective_sha256"] != mutators.forward.properties_sha256):
            raise Rejected("broker-containment-original-topology-required")
        runtime = value["runtime"]["cgroup_path"]
        if any(within(group, runtime) or within(runtime, group)
               for group in (mutators.forward.cgroup, mutators.recovery.cgroup)):
            raise Rejected("broker-containment-separate-runtime-required")
        self._configuration = self._config()
        self._forward = mutators.forward
        self._systemctl = mutators.systemctl
        self._role = canonical(value["roles"]["forward"])
        self.attempted, self.failed = False, False

    @property
    def target_sha256(self):
        return digest(self._configuration)

    def _config(self):
        value = {"schema": "host-recovery-forward-containment-target-v1",
            "binding_sha256": digest(self.authority._binding), "epoch_sha256": digest(self.journal._epoch),
            "topology_sha256": self.topology.sha256, "systemctl": self.mutators.systemctl,
            "forward": asdict(self.mutators.forward), "recovery": asdict(self.mutators.recovery)}
        if self.jobs is not None:
            value["manager_jobs"] = decode(self.jobs.configuration())
        if self.masks is not None:
            value["persistent_masks"] = decode(self.masks.configuration())
        return canonical(value)

    def _current(self, deadline):
        if (self.failed or self.jobs is not self._original_jobs or self.masks is not self._original_masks
                or self._config() != self._configuration):
            raise Rejected("broker-containment-configuration-changed")
        self.journal._current()
        self.journal._time(deadline)
        self.authority.observe(deadline=deadline)
        supervisor_group = decode(self.authority._observed)["cgroup"]
        if any(within(group, supervisor_group) or within(supervisor_group, group)
               for group in (self._forward.cgroup, self.mutators.recovery.cgroup)):
            raise Rejected("broker-containment-separate-supervisor-required")
        if self.masks is not None and self.masks.published:
            self.masks.observe(current=lambda: self.journal._time(deadline))
        self.journal._current()
        self.journal._time(deadline)
        if (self.jobs is not self._original_jobs or self.masks is not self._original_masks
                or self._config() != self._configuration):
            raise Rejected("broker-containment-configuration-changed")

    def _observe(self, deadline):
        self._current(deadline)
        row = self.mutators.observe(self._forward, deadline=deadline)
        role = decode(self._role)
        if (row["User"], row["Group"]) != (str(role["uid"]), str(role["gid"])):
            raise Rejected("broker-containment-forward-owner-unconfirmed")
        if self.jobs is not None and row["Job"] != "0" and not self.jobs.matches("forward", row["Job"]):
            raise Rejected("broker-containment-untracked-forward-job")
        # A unit read may outlive the peer or original lock, and vice versa.
        # These are revoking point checks, never an atomic manager transaction.
        self._current(deadline)
        return row

    @staticmethod
    def _inactive(row):
        return (row["ActiveState"] in ("inactive", "failed") and row["SubState"] in ("dead", "failed")
                and row["MainPID"] == "0" and row["Job"] == "0")

    def contain_forward(self, *, deadline):
        """Submit at most once; even a returned record never proves pending drain.

        Any exception retains pending/staged bytes and permanently closes this
        adapter and its journal. No retry, rollback of a submitted stop, ambiguous
        return repair, later phase or replacement invocation is attempted.
        """
        with self.journal._mutex:
            if self.attempted:
                raise Rejected("broker-containment-exhausted")
            self.attempted = True
            try:
                self._observe(deadline)
                if self.jobs is not None:
                    self.jobs.observe(deadline=deadline, check=lambda: self._observe(deadline))
                operation = self.journal.pending("contain_forward", target_sha256=self.target_sha256,
                                                 deadline=deadline)
                if self.masks is not None:
                    # Only persistent filesystem publication here. Reload changes
                    # the loaded configuration and needs its own job transition.
                    self.masks.publish(current=lambda: self._observe(deadline))
                before = self._observe(deadline)
                if not self._inactive(before):
                    if self.jobs is None:
                        self.mutators.commands.run((self._systemctl, "--no-block", "stop", "--", self._forward.unit),
                                                   deadline=deadline)
                    else:
                        self.jobs.submit("forward", operation=operation, deadline=deadline,
                                         check=lambda: self._observe(deadline))
                        self.jobs.observe(deadline=deadline, check=lambda: self._observe(deadline))
                    before_kill = self._observe(deadline)
                    if not self._inactive(before_kill):
                        self.mutators.commands.run((self._systemctl, "kill", "--kill-whom=all", "--signal=SIGKILL",
                                                   "--", self._forward.unit), deadline=deadline)
                after = self._observe(deadline)
                populated = self.mutators.cgroups.populated(self._forward.cgroup)
                final = self._observe(deadline)
                # Absence is unknown here: manager retirement/activation exclusion
                # belongs to the complete cold barrier, not this narrow submission.
                stopped = after == final and self._inactive(final) and populated is False
                returned = self.journal.returned(operation, result="returned")
                # Persistence is an external boundary too. Never return a fresh
                # observation based only on the prefix before the return fsync.
                populated_after = self.mutators.cgroups.populated(self._forward.cgroup)
                trailing = self._observe(deadline)
                stopped = stopped and final == trailing and populated_after is False
                job_observations = {}
                if self.jobs is not None:
                    job_observations = self.jobs.observe(deadline=deadline, check=lambda: self._observe(deadline))
                    stopped = stopped and all(value == "completion_done_observed" for value in job_observations.values())
                    stopped = stopped and trailing == self._observe(deadline)
                self._current(deadline)
                return {"schema": "host-recovery-forward-containment-return-v1",
                        "manager_job_observations": job_observations, "manager_jobs_retired": False,
                        "activation_exclusion_proven": False,
                        "persistent_masks_published": self.masks is not None and self.masks.published,
                        "manager_reload_performed": False,
                        "operation_id": operation["operation_id"], "return_sha256": digest(canonical(returned)),
                        "forward_stopped_observed": stopped, "pending_drained": False,
                        "complete_fence_proven": False, "recovery_execution_allowed": False,
                        "start_allowed": False, "settlement_allowed": False, "production_acceptance": False}
            except Exception:
                self.failed = self.journal._failed = True
                raise Rejected("broker-containment-unconfirmed") from None
