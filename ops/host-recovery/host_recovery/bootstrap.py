"""Read-only supervisor self-identity bootstrap; no service or start fence.

Pins and the local manager command transport are independently trusted inputs,
not authenticated by their matching hashes here. Never construct them from an
untrusted worker request. This bootstrap observes ONLY the calling MainPID, so a
PID cannot be recycled while its identity is being established. No environment
identity, arbitrary target PID, service installation or privilege grant exists.
"""
import copy
from dataclasses import dataclass
import os
import re
import time

from .commands import Deadline
from .durable import Rejected, canonical, digest
from .inventory import HASH
from .jobs import process_cgroup
from .journal import identity
from .manager import INVOCATION, PROPERTIES, UNIT, cgroup_path, fragment_hash, properties, static_properties
from .supervisor import validate_owner


BOOT = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")


def kernel_boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id", "rb") as source:
            raw = source.read(38)
        if len(raw) != 37 or raw[-1:] != b"\n":
            raise Rejected("supervisor-kernel-boot-schema")
        value = raw[:-1].decode("ascii")
        if BOOT.fullmatch(value) is None:
            raise Rejected("supervisor-kernel-boot-schema")
        return value
    except (OSError, UnicodeError):
        raise Rejected("supervisor-kernel-boot-unavailable") from None


@dataclass(frozen=True)
class SupervisorBinding:
    unit: str
    fragment_path: str
    fragment_sha256: str
    properties_sha256: str
    uid: int
    gid: int

    def __post_init__(self):
        if type(self.unit) is not str or UNIT.fullmatch(self.unit) is None:
            raise Rejected("supervisor-bootstrap-unit-required")
        if (type(self.fragment_path) is not str or not os.path.isabs(self.fragment_path)
                or self.fragment_path == "/" or self.fragment_path.endswith("/")):
            raise Rejected("supervisor-bootstrap-fragment-required")
        for pin in (self.fragment_sha256, self.properties_sha256):
            if type(pin) is not str or HASH.fullmatch(pin) is None:
                raise Rejected("supervisor-bootstrap-pin-required")
        if any(type(value) is not int or not 1 <= value <= 2147483647 for value in (self.uid, self.gid)):
            raise Rejected("supervisor-bootstrap-unprivileged-owner-required")


class SystemdSupervisorIdentity:
    """Bootstrap once, then re-observe only the same calling manager owner.

    Supplies the read-only observe_owner boundary of RecoverySupervisor. It does
    NOT implement fence or enqueue_recovery. Any uncertainty permanently revokes
    this instance; a replacement object cannot clear a durable recovery latch.
    Manager queries share one caller deadline, without fresh per-query reserves.
    """
    def __init__(self, *, systemctl, commands, binding, clock=time.monotonic,
                 boot_id=kernel_boot_id, read_fragment_hash=fragment_hash, read_process_cgroup=process_cgroup):
        if type(systemctl) is not str or not os.path.isabs(systemctl):
            raise Rejected("explicit-systemctl-required")
        if not isinstance(binding, SupervisorBinding):
            raise Rejected("supervisor-bootstrap-binding-required")
        self.systemctl, self.commands, self.binding = systemctl, commands, binding
        self.clock, self.boot_id = clock, boot_id
        self.read_fragment_hash, self.read_process_cgroup = read_fragment_hash, read_process_cgroup
        self.attempted, self.revoked, self.bound = False, False, None
        self.last_clock = None

    def _now(self):
        value = self.clock()
        # Deadline validates numeric type/finite values as well as local regression.
        if (type(value) in (int, float) and self.last_clock is not None and value < self.last_clock):
            raise Rejected("supervisor-bootstrap-clock-changed")
        self.last_clock = value
        return value

    def _row(self, *, deadline, pid):
        timer = Deadline(self._now, deadline)
        timer.remaining()
        binding = self.binding
        raw = self.commands.run((self.systemctl, "--no-pager", "show",
                                 "--property=" + ",".join(sorted(PROPERTIES)), "--", binding.unit),
                                deadline=deadline)
        row = properties(raw)
        static = static_properties(row)
        if (row["Id"] != binding.unit or row["LoadState"] != "loaded"
                or row["FragmentPath"] != binding.fragment_path or row["DropInPaths"] != ""
                or digest(canonical(static)) != binding.properties_sha256
                or self.read_fragment_hash(binding.fragment_path) != binding.fragment_sha256):
            raise Rejected("supervisor-bootstrap-unit-pin-mismatch")
        required = {"Type": "exec", "KillMode": "control-group", "SendSIGKILL": "yes", "Delegate": "no",
                    "ProtectControlGroups": "yes", "NoNewPrivileges": "yes", "Restart": "on-failure",
                    "CapabilityBoundingSet": "", "AmbientCapabilities": "", "RestrictNamespaces": "yes",
                    "ProtectSystem": "strict", "RestrictSUIDSGID": "yes",
                    "User": str(binding.uid), "Group": str(binding.gid)}
        if (any(row[key] != value for key, value in required.items())
                or static["ExecStart"]["ignore_errors"] != "no"):
            raise Rejected("supervisor-bootstrap-unit-semantics")
        if (row["ActiveState"] != "active" or row["SubState"] != "running" or row["Job"] != "0"
                or re.fullmatch(r"[1-9][0-9]{0,9}", row["MainPID"]) is None
                or int(row["MainPID"]) > 2147483647
                or pid is not None and row["MainPID"] != str(pid)
                or INVOCATION.fullmatch(row["InvocationID"]) is None
                or not cgroup_path(row["ControlGroup"])):
            raise Rejected("supervisor-bootstrap-mainpid-unconfirmed")
        timer.remaining()
        # pid=None is discovery only. Foreign-process authority additionally needs
        # a live connection-bound pidfd around repeated manager/cgroup observations.
        return {"invocation_id": row["InvocationID"], "cgroup": row["ControlGroup"], "pid": int(row["MainPID"]),
                "uid": binding.uid, "gid": binding.gid}

    def _observe(self, *, deadline):
        if self.revoked or os.geteuid() != self.binding.uid or os.getegid() != self.binding.gid:
            raise Rejected("supervisor-bootstrap-owner-unconfirmed")
        timer = Deadline(self._now, deadline)
        timer.remaining()
        boot = self.boot_id()
        if type(boot) is not str or BOOT.fullmatch(boot) is None:
            raise Rejected("supervisor-bootstrap-boot-required")
        group = self.read_process_cgroup(os.getpid())
        before = self._row(deadline=deadline, pid=os.getpid())
        if group != before["cgroup"] or self.read_process_cgroup(os.getpid()) != group:
            raise Rejected("supervisor-bootstrap-cgroup-changed")
        after = self._row(deadline=deadline, pid=os.getpid())
        if (before != after or self.boot_id() != boot or self.read_process_cgroup(os.getpid()) != group):
            raise Rejected("supervisor-bootstrap-identity-changed")
        timer.remaining()
        return {**before, "boot_id": boot}

    def bootstrap(self, *, installation_id, attempt_id, deadline):
        if self.attempted or self.revoked:
            raise Rejected("supervisor-bootstrap-exhausted")
        self.attempted = True
        try:
            if not identity(installation_id) or not identity(attempt_id):
                raise Rejected("supervisor-bootstrap-attempt-required")
            value = self._observe(deadline=deadline)
            owner = {"installation_id": installation_id, "attempt_id": attempt_id,
                     "unit": self.binding.unit, "invocation_id": value["invocation_id"], "boot_id": value["boot_id"]}
            validate_owner(owner)
            self.bound = {"schema": "host-recovery-supervisor-identity-v1", "owner": owner,
                          "pid": value["pid"], "uid": value["uid"], "gid": value["gid"], "cgroup": value["cgroup"]}
            return copy.deepcopy(self.bound)
        except Exception:
            self.revoked = True
            raise

    def observe_owner(self, owner, *, deadline):
        try:
            if self.bound is None or self.revoked or canonical(owner) != canonical(self.bound["owner"]):
                raise Rejected("supervisor-bootstrap-owner-unconfirmed")
            value = self._observe(deadline=deadline)
            expected = {"invocation_id": owner["invocation_id"], "boot_id": owner["boot_id"],
                        **{key: self.bound[key] for key in ("pid", "uid", "gid", "cgroup")}}
            if value != expected:
                raise Rejected("supervisor-bootstrap-identity-changed")
            return copy.deepcopy(self.bound["owner"])
        except Exception:
            self.revoked = True
            raise
