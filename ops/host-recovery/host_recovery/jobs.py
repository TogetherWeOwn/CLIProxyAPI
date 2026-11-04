"""Read-only, request-bound systemd recovery-job observation.

No start, restart, retry, reset-failed or unit installation operation exists. An
inactive unit or missing Job does not prove that dispatch never happened; an
exited worker does not prove restoration. Commands and fragment reads must use
the trusted local manager boundary; scripted replies are component evidence only.
"""
from dataclasses import dataclass
import os
import re
import time

from .commands import Deadline
from .durable import Rejected, canonical, digest
from .inventory import HASH
from .manager import INVOCATION, PROPERTIES, cgroup_path, fragment_hash, properties, static_properties


def recovery_unit(request_id):
    if type(request_id) is not str or HASH.fullmatch(request_id) is None:
        raise Rejected("recovery-job-request-digest-required")
    return "cpa-recovery@" + request_id + ".service"


@dataclass(frozen=True)
class RecoveryJobBinding:
    request_id: str
    fragment_path: str
    fragment_sha256: str
    properties_sha256: str

    def __post_init__(self):
        recovery_unit(self.request_id)
        if (type(self.fragment_path) is not str or not os.path.isabs(self.fragment_path)
                or self.fragment_path == "/" or self.fragment_path.endswith("/")):
            raise Rejected("recovery-job-fragment-path")
        for pin in (self.fragment_sha256, self.properties_sha256):
            if type(pin) is not str or HASH.fullmatch(pin) is None:
                raise Rejected("recovery-job-binding-pin")


def validate_observation(value, request_id, boot_id):
    fields = {"schema", "request_id", "boot_id", "unit", "invocation_id", "state", "job_id"}
    if (type(value) is not dict or set(value) != fields
            or value["schema"] != "host-recovery-job-observation-v1"
            or value["request_id"] != request_id or value["boot_id"] != boot_id
            or value["unit"] != recovery_unit(request_id)
            or type(value["job_id"]) is not int or not 0 <= value["job_id"] <= 4294967295
            or type(value["invocation_id"]) is not str
            or value["invocation_id"] != "" and INVOCATION.fullmatch(value["invocation_id"]) is None):
        raise Rejected("recovery-job-observation-schema")
    state = value["state"]
    if state == "pending":
        valid = value["job_id"] > 0
    elif state == "running":
        valid = value["job_id"] == 0 and value["invocation_id"] != ""
    elif state == "inactive_unverified":
        valid = value["job_id"] == 0
    else:
        valid = False
    if not valid:
        raise Rejected("recovery-job-observation-state")


def process_cgroup(pid):
    """Read only the kernel's unified-cgroup membership for one live process."""
    if type(pid) is not int or not 1 <= pid <= 2147483647:
        raise Rejected("recovery-worker-pid-required")
    try:
        with open(f"/proc/{pid}/cgroup", "rb") as source:
            raw = source.read(2049)
        text = raw.decode("ascii")
        if not text.startswith("0::") or not text.endswith("\n") or text.count("\n") != 1:
            raise Rejected("recovery-worker-unified-cgroup-required")
        group = text[3:-1]
        if not cgroup_path(group):
            raise Rejected("recovery-worker-cgroup-schema")
        return group
    except (OSError, UnicodeError):
        raise Rejected("recovery-worker-process-unavailable") from None


def validate_worker(value, request_id, boot_id, pid):
    if type(value) is not dict or set(value) != {
            "schema", "request_id", "boot_id", "unit", "invocation_id", "state", "job_id", "pid", "cgroup"}:
        raise Rejected("recovery-worker-observation-schema")
    validate_observation({k: v for k, v in value.items() if k not in ("pid", "cgroup")}, request_id, boot_id)
    if (value["state"] != "running" or type(value["pid"]) is not int or value["pid"] != pid
            or type(pid) is not int or not 1 <= pid <= 2147483647 or not cgroup_path(value["cgroup"])):
        raise Rejected("recovery-worker-observation-identity")


class SystemdRecoveryJobs:
    """Observe only one explicitly pinned digest-named recovery unit.

    The properties pin must include the fixed worker command/request identity and
    all ownership/sandbox settings. The caller authenticates the pin/manifest and
    separately enforces the complete start/writer fence. This adapter cannot do
    either by observing systemctl output, and never interprets an exit as success.
    """
    def __init__(self, *, systemctl, commands, binding, boot_id, clock=time.monotonic,
                 read_fragment_hash=fragment_hash, read_process_cgroup=process_cgroup):
        if type(systemctl) is not str or not os.path.isabs(systemctl):
            raise Rejected("explicit-systemctl-required")
        if not isinstance(binding, RecoveryJobBinding):
            raise Rejected("recovery-job-binding-required")
        self.systemctl, self.commands, self.binding = systemctl, commands, binding
        self.boot_id, self.clock, self.read_fragment_hash = boot_id, clock, read_fragment_hash
        self.read_process_cgroup = read_process_cgroup

    def observe(self, request_id, *, deadline):
        return self._observe(request_id, deadline=deadline)[0]

    def observe_worker(self, request_id, *, pid, deadline):
        """Match the connected worker to the pinned unit's running MainPID.

        The caller holds a live pidfd and verifies kernel connection AND message
        credentials around this call. Descendants, a caller-supplied invocation,
        environment variables and a reused PID are not worker authentication.
        """
        timer = Deadline(self.clock, deadline)
        timer.remaining()
        before = self.read_process_cgroup(pid)
        value, row = self._observe(request_id, deadline=deadline)
        result = {**value, "pid": pid, "cgroup": before}
        validate_worker(result, request_id, value["boot_id"], pid)
        if row["MainPID"] != str(pid) or row["ControlGroup"] != before or self.read_process_cgroup(pid) != before:
            raise Rejected("recovery-worker-manager-peer-mismatch")
        timer.remaining()
        return result

    def _observe(self, request_id, *, deadline):
        timer = Deadline(self.clock, deadline)
        timer.remaining()
        if request_id != self.binding.request_id:
            raise Rejected("unbound-recovery-job")
        boot = self.boot_id()
        if type(boot) is not str or not boot:
            raise Rejected("recovery-job-boot-required")
        unit = recovery_unit(request_id)
        raw = self.commands.run((self.systemctl, "--no-pager", "show",
                                 "--property=" + ",".join(sorted(PROPERTIES)), "--", unit),
                                deadline=deadline)
        value = properties(raw)
        if (value["Id"] != unit or value["LoadState"] != "loaded"
                or value["FragmentPath"] != self.binding.fragment_path or value["DropInPaths"] != ""
                or digest(canonical(static_properties(value))) != self.binding.properties_sha256
                or self.read_fragment_hash(self.binding.fragment_path) != self.binding.fragment_sha256):
            raise Rejected("recovery-job-unit-pin-mismatch")
        required = {"Type": "exec", "KillMode": "control-group", "SendSIGKILL": "yes", "Delegate": "no",
                    "ProtectControlGroups": "yes", "NoNewPrivileges": "yes", "Restart": "no",
                    "CapabilityBoundingSet": "", "AmbientCapabilities": "", "RestrictNamespaces": "yes",
                    "ProtectSystem": "strict", "RestrictSUIDSGID": "yes"}
        if (value["User"] in ("", "root", "0") or value["Group"] in ("", "root", "0")
                or any(value[key] != expected for key, expected in required.items())):
            raise Rejected("unsafe-recovery-job-semantics")
        for key in ("Job", "MainPID"):
            if re.fullmatch(r"0|[1-9][0-9]{0,9}", value[key]) is None or int(value[key]) > 4294967295:
                raise Rejected("recovery-job-numeric-schema")
        invocation, group = value["InvocationID"], value["ControlGroup"]
        if invocation != "" and INVOCATION.fullmatch(invocation) is None:
            raise Rejected("recovery-job-invocation-schema")
        if group != "" and not cgroup_path(group):
            raise Rejected("recovery-job-cgroup-schema")
        inactive = (value["ActiveState"] in ("inactive", "failed")
                    and value["SubState"] in ("dead", "failed") and value["MainPID"] == "0")
        running = (value["ActiveState"] == "active" and value["SubState"] == "running"
                   and value["MainPID"] != "0" and invocation != "" and group != "")
        transitional = value["ActiveState"] in ("activating", "deactivating", "reloading")
        job = int(value["Job"])
        if job > 0 and (inactive or running or transitional):
            state = "pending"
        elif job == 0 and running:
            state = "running"
        elif job == 0 and inactive:
            state = "inactive_unverified"
        else:
            raise Rejected("recovery-job-state-unconfirmed")
        observation = {"schema": "host-recovery-job-observation-v1", "request_id": request_id,
                       "boot_id": boot, "unit": unit, "invocation_id": invocation,
                       "state": state, "job_id": job}
        validate_observation(observation, request_id, boot)
        if self.boot_id() != boot:
            raise Rejected("recovery-job-boot-changed")
        timer.remaining()
        return observation, value
