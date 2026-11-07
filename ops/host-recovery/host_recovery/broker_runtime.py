"""Fixed dedicated-runtime stop/recursive-kill submission, not a cold barrier.

No IPC method or runner enables this embedding adapter. The root broker must own
its command transport and independently provisioned cgroup descriptor/pins. Stop
returns and point observations do not prove manager-job retirement, activation
exclusion, containment provenance, quarantine inventory or pending-operation drain.
No runtime relaunch, restore, start or settlement operation exists here.
"""
from dataclasses import asdict
import os
import stat

from .broker_authority import SupervisorPeerAuthority
from .broker_operations import OperationJournal
from .durable import Rejected, canonical, decode, digest, directory
from .manager import PROPERTIES, UnitBinding, properties, static_properties
from .manager_jobs import RuntimeStopJobs
from .topology import RUNTIME_ROLES, Topology, within


class RuntimeDomain:
    """Borrow one preopened exact slice fd; never accept a kill path per call.

    The caller retains the descriptor through all effects and supplies independent
    device/inode pins. Linux mount identity, no-follow path correspondence and fd
    identity are rechecked; disappearance/recreation is uncertainty, not emptiness.
    These checks do not prove that every shim/task was contained in this domain.
    """
    def __init__(self, *, fd, mount_root, cgroup, device, inode):
        from .manager import cgroup_path
        if (type(fd) is not int or fd < 0 or not cgroup_path(mount_root) or not cgroup_path(cgroup)
                or type(device) is not int or device < 0 or type(inode) is not int or inode <= 0):
            raise Rejected("runtime-domain-explicit-pins-required")
        self.fd, self.mount_root, self.cgroup = fd, mount_root, cgroup
        self.device, self.inode = device, inode
        self._configuration = self.configuration()
        self.current()

    def configuration(self):
        return canonical({"fd": self.fd, "mount_root": self.mount_root, "cgroup": self.cgroup,
                          "device": self.device, "inode": self.inode})

    def _mount(self):
        # The fd's mount ID must be the single exact cgroup2 mount, not a bind
        # mount/subtree or a regular directory with fabricated cgroup.events.
        with open("/proc/self/mountinfo", "rb") as source:
            raw = source.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise Rejected("runtime-domain-mount-overflow")
        matches = []
        for line in raw.decode("ascii").splitlines():
            left, sep, right = line.partition(" - ")
            fields, fs = left.split(), right.split()
            if not sep or len(fields) < 6 or not fs:
                raise Rejected("runtime-domain-mount-schema")
            if fields[4] == self.mount_root:
                if fields[3] != "/" or fs[0] != "cgroup2":
                    raise Rejected("runtime-domain-cgroup2-required")
                matches.append(fields[0])
        with open("/proc/self/fdinfo/%d" % self.fd, "rb") as source:
            info = source.read(4097)
        if len(info) > 4096:
            raise Rejected("runtime-domain-fdinfo-overflow")
        ids = [line.split()[1] for line in info.decode("ascii").splitlines() if line.startswith("mnt_id:")]
        if len(matches) != 1 or ids != matches:
            raise Rejected("runtime-domain-mount-identity-unconfirmed")

    def current(self):
        if self.configuration() != self._configuration:
            raise Rejected("runtime-domain-configuration-changed")
        self._mount()
        with open("/proc/self/cgroup", "rb") as source:
            own = source.read(4097)
        # This adapter must not recursively kill its calling broker. Qualification
        # still has to prove all other control roles are outside the domain.
        if (len(own) > 4096 or not own.startswith(b"0::/") or not own.endswith(b"\n")
                or own.count(b"\n") != 1 or within(own[3:-1].decode("ascii"), self.cgroup)):
            raise Rejected("runtime-domain-calling-broker-not-separated")
        st = os.fstat(self.fd)
        if not stat.S_ISDIR(st.st_mode) or (st.st_dev, st.st_ino) != (self.device, self.inode):
            raise Rejected("runtime-domain-descriptor-changed")
        with directory(self.mount_root + self.cgroup) as current_fd:
            current = os.fstat(current_fd)
            if (current.st_dev, current.st_ino) != (self.device, self.inode):
                raise Rejected("runtime-domain-path-changed")

    def _read_control(self, name):
        self.current()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_dev != self.device
                    or os.listxattr(fd)):
                raise Rejected("runtime-domain-events-file-unconfirmed")
            blocks, size = [], 0
            while True:
                block = os.read(fd, 1025-size)
                if not block:
                    break
                size += len(block)
                if size > 1024:
                    raise Rejected("runtime-domain-events-overflow")
                blocks.append(block)
            after = os.fstat(fd)
            path = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            # kernfs event values are dynamic and do not have persistent-file
            # size/timestamp semantics. Keep mount/path/inode and metadata pins,
            # not durable.read_file's immutable-content signature contract.
            def identity(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)
            if identity(before) != identity(after) or identity(before) != identity(path) or os.listxattr(fd):
                raise Rejected("runtime-domain-events-identity-changed")
            self.current()
            return b"".join(blocks)
        finally:
            os.close(fd)

    def _events(self):
        return self._read_control("cgroup.events")

    def _event_values(self):
        raw = self._events()
        values = {}
        for line in raw.decode("ascii").splitlines():
            fields = line.split()
            if (len(fields) != 2 or fields[0] not in ("populated", "frozen")
                    or fields[0] in values or fields[1] not in ("0", "1")):
                raise Rejected("runtime-domain-events-schema")
            values[fields[0]] = fields[1]
        if "populated" not in values:
            raise Rejected("runtime-domain-populated-missing")
        self.current()
        return values

    def populated(self):
        return self._event_values()["populated"] == "1"

    def frozen(self):
        """Require an own freeze request and the kernel's completed freeze state.

        A request alone, an ancestor's freeze or a missing event is not enough.
        Privileged thaw/migration and cgroup recreation still require exclusion.
        """
        requested = self._read_control("cgroup.freeze")
        if requested not in (b"0\n", b"1\n"):
            raise Rejected("runtime-domain-freeze-schema")
        values = self._event_values()
        if "frozen" not in values:
            raise Rejected("runtime-domain-frozen-missing")
        trailing = self._read_control("cgroup.freeze")
        if trailing != requested:
            raise Rejected("runtime-domain-freeze-request-changed")
        self.current()
        return requested == b"1\n" and values["frozen"] == "1"

    def descendants_sealed(self):
        """Observe the kernel descendant-creation limit, not process migration.

        Zero forbids mkdir anywhere below this domain, including when existing
        descendants remain. It does not prevent deletion, privileged limit changes,
        root replacement, migration into existing groups or a privileged thaw.
        """
        raw = self._read_control("cgroup.max.descendants")
        if raw != b"max\n":
            if (not raw.endswith(b"\n") or not raw[:-1].isdigit()
                    or len(raw) > 11 or str(int(raw[:-1])).encode("ascii") + b"\n" != raw
                    or int(raw[:-1]) > 2147483647):
                raise Rejected("runtime-domain-descendants-limit-schema")
        self.current()
        return raw == b"0\n"

    def seal_descendants(self, *, check):
        """One fixed kernel limit write; no reopening or caller-selected value."""
        self._write_control("cgroup.max.descendants", b"0\n", "descendants-limit", check)

    def freeze(self, *, check):
        """One own-subtree freeze request; no thaw or arbitrary file operation."""
        self._write_control("cgroup.freeze", b"1\n", "freeze", check)

    def _write_control(self, name, raw, label, check):
        self.current()
        fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            def identity(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)
            if (not stat.S_ISREG(before.st_mode) or before.st_dev != self.device or before.st_nlink != 1
                    or os.listxattr(fd)
                    or identity(before) != identity(os.stat(name, dir_fd=self.fd, follow_symlinks=False))):
                raise Rejected("runtime-domain-" + label + "-file-unconfirmed")
            self.current()
            check()
            if (identity(before) != identity(os.fstat(fd))
                    or identity(before) != identity(os.stat(name, dir_fd=self.fd, follow_symlinks=False))
                    or os.listxattr(fd)):
                raise Rejected("runtime-domain-" + label + "-file-changed")
            if os.write(fd, raw) != len(raw):
                raise Rejected("runtime-domain-" + label + "-write-unconfirmed")
            self.current()
            check()
        finally:
            os.close(fd)

    def kill(self, *, check):
        """One descriptor-relative kernel write; never fall back to PID killing.

        check is the broker's internal revoking authority barrier, not an IPC or
        worker callback. It is called after opening/validating the exact kernel
        file and again after the write; a failed trailing check cannot undo it.
        """
        self.current()
        fd = os.open("cgroup.kill", os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_dev != self.device or st.st_nlink != 1:
                raise Rejected("runtime-domain-kill-file-unconfirmed")
            self.current()
            check()
            if os.write(fd, b"1\n") != 2:
                raise Rejected("runtime-domain-kill-write-unconfirmed")
            self.current()
            check()
        finally:
            os.close(fd)


class RuntimeContainment:
    """Serialized one-shot submission to the two exact dedicated runtime units.

    Require the original forward-containment return, but do not interpret it as
    quiescence or drain. No second installation lock is acquired. No new epoch is
    minted, no saved pending operation is retried, and no manager job is cancelled
    by a reusable numeric ID. Concrete job retirement remains a separate barrier.
    """
    def __init__(self, *, authority, journal, topology, units, domain, systemctl, commands,
                 read_fragment_hash, jobs):
        if (not isinstance(authority, SupervisorPeerAuthority) or not isinstance(journal, OperationJournal)
                or not isinstance(topology, Topology) or not isinstance(domain, RuntimeDomain)
                or type(units) is not dict or set(units) != set(RUNTIME_ROLES)
                or any(not isinstance(unit, UnitBinding) for unit in units.values())
                or type(systemctl) is not str or not os.path.isabs(systemctl)
                or not isinstance(jobs, RuntimeStopJobs) or jobs.journal is not journal or jobs.units != units):
            raise Rejected("runtime-containment-explicit-boundaries-required")
        self.jobs = jobs
        self.authority, self.journal, self.topology = authority, journal, topology
        self.units, self.domain = dict(units), domain
        self.systemctl, self.commands, self.read_fragment_hash = systemctl, commands, read_fragment_hash
        self.attempted, self.failed = False, False
        value, binding, owner = topology.manifest(), decode(authority._binding), decode(authority._owner)
        runtime = value["runtime"]
        if (authority._binding != journal._binding or topology.sha256 != binding["topology_sha256"]
                or value["installation_id"] != binding["installation_id"]
                or jobs.busctl_sha256 != value["tools"]["busctl"]["sha256"]
                or value["roles"]["supervisor"]["unit"] != owner["unit"]
                or (value["roles"]["supervisor"]["uid"], value["roles"]["supervisor"]["gid"])
                    != (authority.manager.binding.uid, authority.manager.binding.gid)
                or domain.cgroup != runtime["cgroup_path"]):
            raise Rejected("runtime-containment-original-topology-required")
        for role, unit in self.units.items():
            expected = runtime["units"][role]
            if (unit.unit != expected["unit"] or unit.properties_sha256 != expected["effective_sha256"]
                    or unit.cgroup != runtime["cgroup_path"] + "/" + unit.unit):
                raise Rejected("runtime-containment-fixed-runtime-required")
        self._configuration = self._config()

    def _config(self):
        return canonical({"schema": "host-recovery-runtime-containment-target-v1",
            "binding_sha256": digest(self.authority._binding), "epoch_sha256": digest(self.journal._epoch),
            "topology_sha256": self.topology.sha256, "systemctl": self.systemctl,
            "units": {role: asdict(self.units[role]) for role in RUNTIME_ROLES},
            "domain": decode(self.domain.configuration()), "manager_jobs": decode(self.jobs.configuration())})

    @property
    def target_sha256(self):
        return digest(self._configuration)

    def _current(self, deadline):
        if self.failed or self._config() != self._configuration:
            raise Rejected("runtime-containment-configuration-changed")
        self.journal._current()
        self.journal._time(deadline)
        self.authority.observe(deadline=deadline)
        group = decode(self.authority._observed)["cgroup"]
        if within(group, self.domain.cgroup) or within(self.domain.cgroup, group):
            raise Rejected("runtime-containment-separate-supervisor-required")
        self.domain.current()
        self.journal._current()
        self.journal._time(deadline)
        if self._config() != self._configuration:
            raise Rejected("runtime-containment-configuration-changed")

    @staticmethod
    def _inactive(row):
        return (row["ActiveState"] in ("inactive", "failed") and row["SubState"] in ("dead", "failed")
                and row["MainPID"] == "0" and row["Job"] == "0")

    def _observe_unit(self, role, deadline):
        self._current(deadline)
        unit = self.units[role]
        raw = self.commands.run((self.systemctl, "--no-pager", "show",
            "--property=" + ",".join(sorted(PROPERTIES)), "--", unit.unit), deadline=deadline)
        row = properties(raw)
        static = static_properties(row)
        if (row["Id"] != unit.unit or row["LoadState"] != "loaded"
                or row["FragmentPath"] != unit.fragment_path or row["DropInPaths"] != ""
                or digest(canonical(static)) != unit.properties_sha256
                or self.read_fragment_hash(unit.fragment_path) != unit.fragment_sha256
                or any(row[key] != item for key, item in {"Type": "exec", "KillMode": "control-group",
                    "SendSIGKILL": "yes", "Restart": "no", "User": "0", "Group": "0",
                    "Slice": self.topology.manifest()["runtime"]["slice"]}.items())):
            raise Rejected("runtime-containment-unit-unconfirmed")
        inactive = self._inactive(row)
        if (row["InvocationID"] != unit.invocation_id and not (inactive and row["InvocationID"] == "")
                or row["ControlGroup"] != unit.cgroup and not (inactive and row["ControlGroup"] == "")):
            raise Rejected("runtime-containment-invocation-changed")
        # Only this adapter's exact returned stop job may remain pending. Unknown
        # jobs refuse; disappearance from ListJobs still never proves retirement.
        if row["Job"] != "0" and not self.jobs.matches(role, row["Job"]):
            raise Rejected("runtime-containment-job-retirement-required")
        self._current(deadline)
        return row

    def _observe(self, role, deadline):
        row = self._observe_unit(role, deadline)
        self.jobs.observe(deadline=deadline, check=lambda: self._current(deadline))
        self._current(deadline)
        return row

    def contain_runtime(self, *, deadline):
        with self.journal._mutex:
            if self.attempted:
                raise Rejected("runtime-containment-exhausted")
            self.attempted = True
            try:
                self._current(deadline)
                prior = self.journal._pending.get("contain_forward")
                if (prior is None or "contain_forward" not in self.journal._returned
                        or decode(prior)["method"] != "contain_forward"):
                    raise Rejected("runtime-containment-forward-return-required")
                for role in RUNTIME_ROLES:
                    self._observe(role, deadline)
                operation = self.journal.pending("cold_quiesce_runtime", target_sha256=self.target_sha256,
                                                 deadline=deadline)
                # Stop the daemon before its external containerd. Each effect has
                # a fresh original-lock/peer/input/unit check after durable pending.
                for role in RUNTIME_ROLES:
                    row = self._observe(role, deadline)
                    if not self._inactive(row):
                        self.jobs.submit(role, operation=operation, deadline=deadline,
                                         check=lambda: self._observe_unit(role, deadline))
                        self._current(deadline)
                for role in RUNTIME_ROLES:
                    self._observe(role, deadline)
                self.domain.kill(check=lambda: self._current(deadline))
                before = [self._observe(role, deadline) for role in RUNTIME_ROLES]
                populated = self.domain.populated()
                after = [self._observe(role, deadline) for role in RUNTIME_ROLES]
                empty = before == after and all(self._inactive(row) for row in after) and populated is False
                returned = self.journal.returned(operation, result="returned")
                trailing_populated = self.domain.populated()
                final = [self._observe(role, deadline) for role in RUNTIME_ROLES]
                empty = empty and after == final and trailing_populated is False
                job_observations = self.jobs.observe(deadline=deadline, check=lambda: self._current(deadline))
                empty = empty and all(value == "absent_not_retired" for value in job_observations.values())
                self._current(deadline)
                return {"schema": "host-recovery-runtime-containment-return-v1",
                    "manager_job_observations": job_observations,
                    "operation_id": operation["operation_id"], "return_sha256": digest(canonical(returned)),
                    "runtime_empty_observed": empty, "manager_jobs_retired": False,
                    "activation_exclusion_proven": False, "containment_qualified": False,
                    "quarantine_reconciled": False, "pending_drained": False, "complete_fence_proven": False,
                    "recovery_execution_allowed": False, "start_allowed": False,
                    "settlement_allowed": False, "production_acceptance": False}
            except Exception:
                self.failed = self.journal._failed = True
                raise Rejected("runtime-containment-unconfirmed") from None
