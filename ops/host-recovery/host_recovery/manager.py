"""Explicit Linux systemd/cgroup-v2 mutator-quiescence adapter.

No units are installed or started here. This is NOT the persistent supervisor or
Docker/start fence. A separately enforced installation-wide start fence must be
acknowledged on both sides of observation; a systemd dependency is insufficient.
Only one bounded reconciliation step runs per call. A pending job, reused unit,
unknown cgroup, or uncertain command cannot authorize restoration.
"""
from dataclasses import dataclass
import os
import re
import stat
import time

from .commands import Deadline
from .durable import Rejected, canonical, component, digest, directory, read_file
from .inventory import HASH

UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,190}\.service\Z")
INVOCATION = re.compile(r"[a-f0-9]{32}\Z")
CGROUP = re.compile(r"/[A-Za-z0-9_.@:-]+(?:/[A-Za-z0-9_.@:-]+)*\Z")
STATIC = frozenset(("Id", "LoadState", "FragmentPath", "DropInPaths", "Type", "KillMode",
                    "SendSIGKILL", "Delegate", "ProtectControlGroups", "NoNewPrivileges",
                    "Restart", "ExecStart", "User", "Group", "Slice", "ReadWritePaths",
                    "CapabilityBoundingSet", "AmbientCapabilities", "RestrictNamespaces",
                    "ProtectSystem", "RestrictSUIDSGID"))
DYNAMIC = frozenset(("InvocationID", "ControlGroup", "ActiveState", "SubState", "Job", "MainPID"))
PROPERTIES = STATIC | DYNAMIC


def cgroup_path(value):
    return (type(value) is str and len(value) <= 1024 and CGROUP.fullmatch(value) is not None
            and all(part not in (".", "..") for part in value.split("/")[1:]))


def properties(raw):
    if type(raw) is not bytes or len(raw) > 65536 or b"\0" in raw:
        raise Rejected("manager-properties-size-or-type")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise Rejected("manager-properties-encoding") from None
    value = {}
    for line in text.splitlines():
        key, sep, item = line.partition("=")
        if not sep or key not in PROPERTIES or key in value:
            raise Rejected("manager-properties-schema")
        value[key] = item
    if set(value) != PROPERTIES:
        raise Rejected("manager-properties-incomplete")
    return value


@dataclass(frozen=True)
class UnitBinding:
    unit: str
    invocation_id: str
    cgroup: str
    fragment_path: str
    fragment_sha256: str
    properties_sha256: str

    def __post_init__(self):
        if (type(self.unit) is not str or UNIT.fullmatch(self.unit) is None
                or type(self.invocation_id) is not str or INVOCATION.fullmatch(self.invocation_id) is None
                or not cgroup_path(self.cgroup)):
            raise Rejected("manager-binding-identity")
        if (type(self.fragment_path) is not str or not os.path.isabs(self.fragment_path)
                or self.fragment_path == "/" or self.fragment_path.endswith("/")):
            raise Rejected("manager-fragment-path")
        for pin in (self.fragment_sha256, self.properties_sha256):
            if type(pin) is not str or HASH.fullmatch(pin) is None:
                raise Rejected("manager-binding-pin")


def fragment_hash(path):
    parent, name = os.path.split(path)
    try:
        with directory(parent) as fd:
            raw, st = read_file(fd, name, limit=65536)
            if st.st_uid not in (0, os.geteuid()) or stat.S_IMODE(st.st_mode) & 0o022:
                raise Rejected("unsafe-manager-fragment")
            return digest(raw)
    except OSError:
        raise Rejected("manager-fragment-unavailable") from None


class CgroupV2:
    """Read the recursive kernel populated bit, never just the main PID.

    The root must be an actual cgroup2 mount (not a caller-created directory).
    Synthetic tests inject a different reader into SystemdMutators instead.
    """
    def __init__(self, root):
        if type(root) is not str or not cgroup_path(root):
            raise Rejected("explicit-cgroup-mount-required")
        self.root = root

    def populated(self, path):
        if not cgroup_path(path):
            raise Rejected("unsafe-cgroup-path")
        try:
            with open("/proc/self/mountinfo", "rb") as source:
                raw = source.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise Rejected("mount-inventory-overflow")
            mounts = []
            for line in raw.decode("ascii").splitlines():
                left, sep, right = line.partition(" - ")
                parts = left.split()
                if not sep or len(parts) < 6:
                    raise Rejected("mount-inventory-malformed")
                if parts[4] == self.root:
                    mounts.append((parts[3], right.split()[0]))
            if mounts != [("/", "cgroup2")]:
                raise Rejected("cgroup-v2-mount-unconfirmed")
            with directory(self.root) as root_fd:
                device = os.fstat(root_fd).st_dev
                fd = os.dup(root_fd)
                try:
                    for name in path.split("/")[1:]:
                        component(name)
                        try:
                            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                            dir_fd=fd)
                        except FileNotFoundError:
                            return None  # Absence alone is NOT quiescence.
                        os.close(fd)
                        fd = child
                        if os.fstat(fd).st_dev != device:
                            raise Rejected("cgroup-cross-mount")
                    raw, _ = read_file(fd, "cgroup.events", limit=1024)
                    values = {}
                    for line in raw.decode("ascii").splitlines():
                        fields = line.split()
                        if (len(fields) != 2 or fields[0] not in ("populated", "frozen")
                                or fields[0] in values or fields[1] not in ("0", "1")):
                            raise Rejected("cgroup-events-malformed")
                        values[fields[0]] = fields[1]
                    if "populated" not in values:
                        raise Rejected("cgroup-populated-missing")
                    return values["populated"] == "1"
                finally:
                    os.close(fd)
        except (OSError, UnicodeError, IndexError):
            raise Rejected("cgroup-observation-unavailable") from None


class SystemdMutators:
    """Pinned, distinct mutation/recovery units; no service-start operation.

    commands.run must bound the helper's local execution at deadline. cgroups
    must read the recursive kernel cgroup state in a real drill. start_fence must
    independently prove that all managed start/writer paths are closed; a True
    test stub proves only ordering. Even a True quiescence result covers these
    mutator units ONLY, never daemon-created containers.
    """
    def __init__(self, *, systemctl, commands, cgroups, forward, recovery, start_fence,
                 read_fragment_hash=fragment_hash, clock=time.monotonic):
        if type(systemctl) is not str or not os.path.isabs(systemctl):
            raise Rejected("explicit-systemctl-required")
        if not isinstance(forward, UnitBinding) or not isinstance(recovery, UnitBinding):
            raise Rejected("manager-unit-bindings-required")
        if (forward.unit == recovery.unit or forward.invocation_id == recovery.invocation_id
                or forward.cgroup == recovery.cgroup or forward.cgroup.startswith(recovery.cgroup + "/")
                or recovery.cgroup.startswith(forward.cgroup + "/")):
            raise Rejected("separate-recovery-ownership-required")
        self.clock = clock
        self.systemctl = systemctl
        self.commands = commands
        self.cgroups = cgroups
        self.forward, self.recovery = forward, recovery
        self.start_fence = start_fence
        self.read_fragment_hash = read_fragment_hash

    def _fenced(self):
        if self.start_fence() is not True:
            raise Rejected("installation-start-fence-unconfirmed")

    def observe(self, binding, *, deadline):
        timer = Deadline(self.clock, deadline)
        timer.remaining()
        if binding not in (self.forward, self.recovery):
            raise Rejected("unbound-manager-unit")
        raw = self.commands.run((self.systemctl, "--no-pager", "show",
                                 "--property=" + ",".join(sorted(PROPERTIES)), "--", binding.unit),
                                deadline=deadline)
        value = properties(raw)
        static = {key: value[key] for key in STATIC}
        if (value["Id"] != binding.unit or value["LoadState"] != "loaded"
                or value["FragmentPath"] != binding.fragment_path or value["DropInPaths"] != ""
                or digest(canonical(static)) != binding.properties_sha256
                or self.read_fragment_hash(binding.fragment_path) != binding.fragment_sha256):
            raise Rejected("manager-unit-pin-mismatch")
        required = {"Type": "exec", "KillMode": "control-group", "SendSIGKILL": "yes", "Delegate": "no",
                    "ProtectControlGroups": "yes", "NoNewPrivileges": "yes", "Restart": "no",
                    "CapabilityBoundingSet": "", "AmbientCapabilities": "", "RestrictNamespaces": "yes",
                    "ProtectSystem": "strict", "RestrictSUIDSGID": "yes"}
        if (value["User"] in ("", "root", "0") or value["Group"] in ("", "root", "0")
                or any(value[key] != expected for key, expected in required.items())):
            raise Rejected("unsafe-mutator-unit-semantics")
        inactive = value["ActiveState"] in ("inactive", "failed") and value["SubState"] in ("dead", "failed")
        if value["InvocationID"] != binding.invocation_id and not (inactive and value["InvocationID"] == ""):
            raise Rejected("manager-invocation-changed")
        if value["ControlGroup"] != binding.cgroup and not (inactive and value["ControlGroup"] == ""):
            raise Rejected("manager-cgroup-changed")
        if not re.fullmatch(r"0|[1-9][0-9]*", value["MainPID"]):
            raise Rejected("manager-pid-schema")
        timer.remaining()
        return value

    def quiesce_forward(self, *, deadline):
        timer = Deadline(self.clock, deadline)
        timer.remaining()
        self._fenced()
        timer.remaining()
        before = self.observe(self.forward, deadline=deadline)
        if before["ActiveState"] not in ("inactive", "failed"):
            # stop is asynchronous; a successful CLI exit is not a stop receipt.
            self.commands.run((self.systemctl, "--no-block", "stop", "--", self.forward.unit), deadline=deadline)
            self.commands.run((self.systemctl, "kill", "--kill-whom=all", "--signal=SIGKILL", "--",
                               self.forward.unit), deadline=deadline)
        after = self.observe(self.forward, deadline=deadline)
        populated = self.cgroups.populated(self.forward.cgroup)
        # Re-read after the kernel observation to catch an intervening activation
        # or queued manager job. The separately enforced start fence is essential.
        final = self.observe(self.forward, deadline=deadline)
        self._fenced()
        timer.remaining()
        if after != final:
            return False
        inactive = final["ActiveState"] in ("inactive", "failed") and final["SubState"] in ("dead", "failed")
        if not inactive or final["MainPID"] != "0" or final["Job"] != "0":
            return False
        if populated is None:
            return final["ControlGroup"] == ""
        return populated is False
