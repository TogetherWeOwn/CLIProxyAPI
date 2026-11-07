"""Connection-bound root broker observation; no privileged service or effect grant.

The caller must independently provision the socket, approval, manager transport
and import closure. This does not discover authority from a reply or environment.
Worker PeerSession continues to reject root; only this broker-specific session
can pin an explicitly expected root peer. No operational runner consumes it yet.
"""
from dataclasses import dataclass
import os
import socket
import struct
import time

from .alert import peer
from .bootstrap import BOOT, kernel_boot_id
from .broker_operations import positive
from .commands import Deadline
from .durable import Rejected, canonical, decode, digest
from .jobs import process_cgroup
from .loading import pin
from .manager import INVOCATION, PROPERTIES, UNIT, cgroup_path, fragment_hash, properties, static_properties
from .worker import PeerSession, cancellation_pending


class BrokerPeerSession(PeerSession):
    """Only the explicitly expected root broker, never an arbitrary privileged peer."""
    def __init__(self, sock, *, pid, clock=time.monotonic, cancel_fd=None):
        if (type(pid) is not int or not 1 <= pid <= 2147483647
                or cancellation_pending(cancel_fd)
                or sock.family != socket.AF_UNIX
                or sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET):
            raise Rejected("broker-peer-explicit-root-required")
        self.sock, self.clock, self.cancel_fd = sock, clock, cancel_fd
        self.peer = peer(sock, 0)
        if self.peer != {"pid": pid, "uid": 0, "gid": 0}:
            raise Rejected("broker-peer-explicit-root-required")
        self.pidfd = struct.unpack("i", sock.getsockopt(socket.SOL_SOCKET, 77, 4))[0]
        try:
            os.set_inheritable(self.pidfd, False)
            # Require per-message credentials as well as the connection pidfd.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            sock.setblocking(False)
        except Exception:
            os.close(self.pidfd)
            raise
        self.last_clock = None
        self.closed = self.disconnected = False


@dataclass(frozen=True)
class BrokerBinding:
    unit: str
    fragment_path: str
    fragment_sha256: str
    properties_sha256: str
    invocation_id: str
    boot_id: str

    def __post_init__(self):
        if (type(self.unit) is not str or UNIT.fullmatch(self.unit) is None or "@" in self.unit
                or type(self.fragment_path) is not str or not os.path.isabs(self.fragment_path)
                or any(part in ("", ".", "..") for part in self.fragment_path.split("/")[1:])
                or type(self.invocation_id) is not str or INVOCATION.fullmatch(self.invocation_id) is None
                or type(self.boot_id) is not str or BOOT.fullmatch(self.boot_id) is None):
            raise Rejected("broker-identity-approved-binding-required")
        pin(self.fragment_sha256)
        pin(self.properties_sha256)


class BrokerPeerIdentity:
    """Fresh pinned manager/kernel checks, not a cached receipt or start permit."""
    def __init__(self, *, session, binding, systemctl, commands, deadline,
                 boot_id=kernel_boot_id, read_fragment_hash=fragment_hash, read_process_cgroup=process_cgroup):
        if (not isinstance(session, BrokerPeerSession) or not isinstance(binding, BrokerBinding)
                or type(systemctl) is not str or not os.path.isabs(systemctl) or not positive(deadline)):
            raise Rejected("broker-identity-explicit-boundaries-required")
        self.session, self.binding = session, binding
        self.systemctl, self.commands, self.deadline = systemctl, commands, deadline
        self.boot_id, self.read_fragment_hash = boot_id, read_fragment_hash
        self.read_process_cgroup = read_process_cgroup
        self.failed, self._observed = False, None

    def _live(self, deadline):
        if self.failed or not positive(deadline) or deadline > self.deadline:
            raise Rejected("broker-identity-revoked")
        timer = Deadline(self.session._now, deadline)
        timer.remaining()
        if self.boot_id() != self.binding.boot_id or not self.session.alive():
            raise Rejected("broker-identity-peer-or-boot-unconfirmed")
        timer.remaining()

    def _row(self, deadline):
        self._live(deadline)
        binding = self.binding
        row = properties(self.commands.run((self.systemctl, "--no-pager", "show",
            "--property=" + ",".join(sorted(PROPERTIES)), "--", binding.unit), deadline=deadline))
        static = static_properties(row)
        required = {"Id": binding.unit, "LoadState": "loaded", "FragmentPath": binding.fragment_path,
                    "DropInPaths": "", "Type": "exec", "Restart": "no", "KillMode": "control-group",
                    "SendSIGKILL": "yes", "Delegate": "no", "User": "0", "Group": "0",
                    "ActiveState": "active", "SubState": "running", "Job": "0",
                    "MainPID": str(self.session.peer["pid"]), "InvocationID": binding.invocation_id}
        if (any(row[key] != value for key, value in required.items())
                or digest(canonical(static)) != binding.properties_sha256
                or self.read_fragment_hash(binding.fragment_path) != binding.fragment_sha256
                or static["ExecStart"]["ignore_errors"] != "no"):
            raise Rejected("broker-identity-manager-pin-unconfirmed")
        group = self.read_process_cgroup(self.session.peer["pid"])
        if not cgroup_path(group) or row["ControlGroup"] != group:
            raise Rejected("broker-identity-cgroup-unconfirmed")
        self._live(deadline)
        return canonical({"pid": self.session.peer["pid"], "invocation_id": row["InvocationID"], "cgroup": group})

    def observe(self, *, deadline):
        try:
            before = self._row(deadline)
            after = self._row(deadline)
            if (before != after or self._observed is not None and before != self._observed
                    or self.read_process_cgroup(self.session.peer["pid"]) != decode(after)["cgroup"]):
                raise Rejected("broker-identity-changed")
            self._live(deadline)
            self._observed, self.deadline = after, deadline
        except Exception:
            self.failed = True
            raise Rejected("broker-identity-unconfirmed") from None
