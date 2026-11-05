"""Deterministic, offline manager launch definitions for conservative runners.

Nothing is installed, enabled or started. Root-provisioned service anchors avoid
hashing a launch digest into the very unit whose properties that launch pins.
These definitions do not implement the host start fence or recovery authority.
"""
from dataclasses import dataclass
import os
import re

from .durable import Rejected, digest
from .journal import identity
from .manager import UNIT


PATH = re.compile(r"/[A-Za-z0-9_.@/-]+\Z")


def absolute_path(value):
    # No systemd specifiers, environment expansion, quoting or list modifiers.
    # Unsupported paths refuse instead of attempting shell/systemd escaping.
    if (type(value) is not str or len(value) > 4096 or PATH.fullmatch(value) is None
            or len(value.split("/")) > 65
            or any(part in ("", ".", "..") for part in value.split("/")[1:])):
        raise Rejected("service-unit-literal-path-required")
    return value


def contains(parent, child):
    return os.path.commonpath((parent, child)) == parent


@dataclass(frozen=True)
class ServiceUnit:
    role: str
    unit: str
    python: str
    package: str
    anchor: str
    uid: int
    gid: int
    read_only: tuple
    read_write: tuple

    def __post_init__(self):
        if (self.role not in ("supervisor", "worker") or type(self.unit) is not str
                or UNIT.fullmatch(self.unit) is None):
            raise Rejected("service-unit-role-and-name-required")
        worker = re.fullmatch(r"cpa-recovery@[a-f0-9]{64}\.service", self.unit) is not None
        if (worker != (self.role == "worker")
                or self.role == "supervisor" and self.unit.startswith("cpa-recovery@")):
            raise Rejected("service-unit-request-instance-required")
        if self.role == "supervisor" and not identity(self.unit):
            raise Rejected("service-unit-supervisor-owner-name-required")
        if any(type(value) is not int or not 1 <= value <= 2147483647 for value in (self.uid, self.gid)):
            raise Rejected("service-unit-unprivileged-owner-required")
        for value in (self.python, self.package, self.anchor):
            absolute_path(value)
        if (type(self.read_only) is not tuple or type(self.read_write) is not tuple
                or len(self.read_only) + len(self.read_write) > 32):
            raise Rejected("service-unit-explicit-path-sets-required")
        for path in self.read_only + self.read_write:
            absolute_path(path)
        if len(set(self.read_only + self.read_write)) != len(self.read_only + self.read_write):
            raise Rejected("service-unit-duplicate-path")
        readonly = (self.python, self.package, self.anchor, *self.read_only)
        for writable in self.read_write:
            if any(contains(writable, path) or contains(path, writable) for path in readonly):
                raise Rejected("service-unit-code-anchor-or-input-write-overlap")
        for index, path in enumerate(self.read_write):
            if any(contains(path, other) or contains(other, path) for other in self.read_write[:index]):
                raise Rejected("service-unit-write-overlap")
        # The current worker is identity-only: no filesystem mutation capability.
        if self.role == "worker" and self.read_write:
            raise Rejected("service-unit-identity-worker-readonly-required")

    def render(self):
        """Return bytes only. Independently provision and pin installed readback.

        Paths and numeric identities are explicit; there is no install target,
        dependency edge, shell, environment file or root grant. Only the
        supervisor restarts on failure, matching the existing bootstrap contract.
        Supervisor and worker definitions must remain distinct manager units.
        """
        readonly = sorted(set((self.python, self.package, self.anchor, *self.read_only)))
        command = (self.python, "-I", self.package + "/service_entry.py", "--role", self.role,
                   "--anchor", self.anchor)
        lines = ["[Unit]", "Description=Conservative host recovery " + self.role,
                 "StartLimitIntervalSec=30s", "StartLimitBurst=3",
                 "", "[Service]", "Type=exec", "User=" + str(self.uid), "Group=" + str(self.gid),
                 "WorkingDirectory=/", "ExecStart=" + " ".join(command),
                 "Restart=" + ("on-failure" if self.role == "supervisor" else "no"), "RestartSec=1s",
                 "KillMode=control-group", "KillSignal=SIGTERM", "SendSIGKILL=yes",
                 "TimeoutStopSec=1s", "Delegate=no", "ProtectControlGroups=yes", "NoNewPrivileges=yes",
                 "CapabilityBoundingSet=", "AmbientCapabilities=", "RestrictNamespaces=yes",
                 "RestrictSUIDSGID=yes", "ProtectSystem=strict", "ProtectKernelTunables=yes",
                 "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "PrivateDevices=yes",
                 "LockPersonality=yes", "RestrictRealtime=yes", "RestrictAddressFamilies=AF_UNIX",
                 "UMask=0077", "ReadOnlyPaths=" + " ".join(readonly),
                 "ReadWritePaths=" + " ".join(sorted(self.read_write)),
                 # Neither pipe backpressure nor incidental paths/errors belong
                 # in a manager-controlled service's health or completion signal.
                 "StandardInput=null", "StandardOutput=null", "StandardError=null", ""]
        raw = "\n".join(lines).encode("ascii")
        if len(raw) > 65536:
            raise Rejected("service-unit-fragment-size-limit")
        return raw

    def receipt(self):
        return {"schema": "host-recovery-service-unit-v1", "role": self.role,
                "unit": self.unit, "unit_sha256": digest(self.render()),
                "recovery_authority": False, "installation_start_fence_proven": False,
                "installed": False, "production_acceptance": False}
