"""Exclusive persistent mask publication, not a manager/start interlock.

The trusted caller owns the approved directory and all writers, retains the
original installation lock, and publishes durable operation intent BEFORE this
filesystem effect. current is its revoking peer/lock/input/deadline barrier, not
an IPC callback. No reload, cancellation, stop, overwrite or unmask is provided.
"""
from dataclasses import asdict
import os
import stat

from .durable import Rejected, canonical, digest, signature
from .installation import _Directory
from .manager import UnitBinding
from .manager_jobs import fixed_roles


class PersistentUnitMasks:
    """Borrow a protected directory for one fixed forward OR runtime mask set.

    This primitive permits owned synthetic directories for component tests.
    Operational use additionally requires authenticated root provisioning of the
    actual persistent system-manager load path. An inode pin is not that proof.
    Existing entries, including matching masks from an older run, always refuse.
    """
    def __init__(self, *, directory, units, fault=None):
        if (not isinstance(directory, _Directory) or not fixed_roles(units)
                or any(not isinstance(unit, UnitBinding) or "@" in unit.unit for unit in units.values())
                or len({unit.unit for unit in units.values()}) != len(units)
                or directory.approval.mode not in (0o700, 0o755)
                or (directory.approval.uid, directory.approval.gid) != (os.geteuid(), os.getegid())):
            raise Rejected("unit-mask-explicit-owned-boundaries-required")
        self.directory, self.units, self.fault = directory, dict(units), fault
        self._configuration = self.configuration()
        self._names = tuple(sorted(unit.unit for unit in units.values()))
        self._owner = (directory.approval.uid, directory.approval.gid)
        self._links, self.attempted, self.published, self.failed = {}, False, False, False
        self._current(lambda: None)
        self._absent()

    def configuration(self):
        return canonical({"schema": "host-recovery-persistent-unit-masks-target-v1",
            "directory": asdict(self.directory.approval),
            "units": {role: asdict(unit) for role, unit in self.units.items()}, "link_target": "/dev/null"})

    def _current(self, current):
        if self.failed or self.configuration() != self._configuration:
            raise Rejected("unit-mask-configuration-changed")
        current()
        self.directory.validate()
        if (self.configuration() != self._configuration
                or (os.geteuid(), os.getegid()) != self._owner):
            raise Rejected("unit-mask-configuration-changed")
        current()

    def _absent(self):
        for name in self._names:
            if name in self._links:
                continue
            try:
                os.stat(name, dir_fd=self.directory.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise Rejected("unit-mask-existing-entry-requires-reconciliation")

    def _link(self, name):
        before = os.stat(name, dir_fd=self.directory.fd, follow_symlinks=False)
        if (not stat.S_ISLNK(before.st_mode) or before.st_nlink != 1
                or (before.st_uid, before.st_gid) != self._owner
                or os.readlink(name, dir_fd=self.directory.fd) != "/dev/null"
                or os.listxattr("/proc/self/fd/%d/%s" % (self.directory.fd, name), follow_symlinks=False)):
            raise Rejected("unit-mask-link-unconfirmed")
        after = os.stat(name, dir_fd=self.directory.fd, follow_symlinks=False)
        if signature(before) != signature(after):
            raise Rejected("unit-mask-link-changed")
        return signature(after)

    def _observe(self, current):
        self._current(current)
        self._absent()
        for name, expected in self._links.items():
            if self._link(name) != expected:
                raise Rejected("unit-mask-link-changed")
        self._current(current)

    def _fault(self, point, current):
        if self.fault is not None:
            self.fault(point)
        # Fault hooks also model external work between revoking checks.
        self._observe(current)

    def publish(self, *, current):
        """Create only absent names; fsync and read back each, retaining all faults.

        A failed/ambiguous publication permanently revokes this object. Partial
        masks remain for separate reconciliation; neither a new object nor a
        later call may adopt/remove them or report the attempt as acknowledged.
        """
        if self.attempted:
            raise Rejected("unit-mask-publication-exhausted")
        self.attempted = True
        try:
            self._observe(current)
            for name in self._names:
                self._fault("create", current)
                # symlink creation is exclusive. Never replace an existing unit,
                # alias, mask or dangling link, and never use force/rename-overwrite.
                os.symlink("/dev/null", name, dir_fd=self.directory.fd)
                self._links[name] = self._link(name)
                self._fault("directory-fsync", current)
                os.fsync(self.directory.fd)
                self._fault("readback", current)
                self._observe(current)
            self._observe(current)
            self.published = True
            return self.observe(current=current)
        except Exception:
            self.failed = True
            raise Rejected("unit-mask-publication-unconfirmed") from None

    def observe(self, *, current):
        try:
            if not self.published or len(self._links) != len(self._names):
                raise Rejected("unit-mask-publication-incomplete")
            self._observe(current)
            return {"schema": "host-recovery-persistent-unit-masks-observation-v1",
                    "target_sha256": digest(self._configuration), "mask_count": len(self._links),
                    "persistent_masks_published": True, "manager_reload_performed": False,
                    "activation_exclusion_proven": False, "manager_jobs_retired": False,
                    "pending_drained": False, "complete_fence_proven": False,
                    "recovery_execution_allowed": False, "start_allowed": False,
                    "settlement_allowed": False, "production_acceptance": False}
        except Exception:
            self.failed = True
            raise Rejected("unit-mask-observation-unconfirmed") from None
