"""Linux request-instance worker handshake; no restore/start/privilege operation.

The supervisor retains its installation lock while serving one connection. Both
connection and message credentials must identify the same live process. A pidfd
pins that process against PID reuse; pinned manager MainPID/cgroup observations
are still required. The client must obtain its expected supervisor PID/owner
from a trusted manager boundary, NOT environment variables or this socket reply.
Hostile root/same-uid code and a compromised manager are outside this boundary.
No service is installed, no endpoint is replaced, and a lost reply is not retried.
"""
import copy
import math
import os
import select
import selectors
import socket
import stat
import struct
import time
import uuid

from .alert import MAX_PACKET, peer, send
from .commands import Deadline
from .durable import Rejected, canonical, decode, directory
from .inventory import HASH
from .jobs import validate_worker
from .journal import identity
from .supervisor import validate_owner


def credential_packet(sock, expected):
    raw, ancillary, flags, _ = sock.recvmsg(MAX_PACKET, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(64),
                                          socket.MSG_CMSG_CLOEXEC)
    credentials = []
    unsupported = False
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == 12:
            pid, uid, gid = struct.unpack("3i", data)
            credentials.append({"pid": pid, "uid": uid, "gid": gid})
        else:
            unsupported = True
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                for fd in struct.unpack("i" * (len(data) // 4), data[:len(data) // 4 * 4]):
                    os.close(fd)
    if (not raw or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or unsupported
            or credentials != [expected]):
        raise Rejected("worker-message-peer-unconfirmed")
    return decode(raw)


class PeerSession:
    """One bounded exchange with an exact kernel peer, held by pidfd."""
    def __init__(self, sock, *, uid, pid=None, clock=time.monotonic):
        self.sock, self.clock = sock, clock
        self.peer = peer(sock, uid)
        if uid == 0 or pid is not None and self.peer["pid"] != pid:
            raise Rejected("worker-peer-unconfirmed")
        # Linux 6.5+ SO_PEERPIDFD pins the process that connected, including if
        # it already exited. pidfd_open(numeric_pid) has a PID-reuse race here.
        self.pidfd = struct.unpack("i", sock.getsockopt(socket.SOL_SOCKET, 77, 4))[0]
        try:
            os.set_inheritable(self.pidfd, False)
        except Exception:
            os.close(self.pidfd)
            raise
        self.last_clock = None
        self.closed = False

    def alive(self):
        return (not self.closed and not select.select([self.pidfd], [], [], 0)[0]
                and peer(self.sock, self.peer["uid"]) == self.peer)

    def _now(self):
        value = self.clock()
        if (type(value) not in (int, float) or not math.isfinite(value)
                or self.last_clock is not None and value < self.last_clock):
            raise Rejected("worker-clock-invalid")
        self.last_clock = value
        return value

    def ready(self, event, deadline):
        timer = Deadline(self._now, deadline)
        with selectors.DefaultSelector() as wait:
            wait.register(self.sock, event)
            wait.register(self.pidfd, selectors.EVENT_READ)
            events = wait.select(timer.remaining())
            if not events or not self.alive() or any(key.fd == self.pidfd for key, _ in events):
                raise Rejected("worker-peer-or-deadline-lost")
            timer.remaining()

    def receive(self, deadline):
        self.ready(selectors.EVENT_READ, deadline)
        result = credential_packet(self.sock, self.peer)
        self.ready(selectors.EVENT_WRITE, deadline)
        return result

    def reply(self, value, deadline):
        self.ready(selectors.EVENT_WRITE, deadline)
        send(self.sock, value)
        Deadline(self._now, deadline).remaining()
        if not self.alive():
            raise Rejected("worker-peer-lost-after-send")

    def close(self):
        if not self.closed:
            self.closed = True
            os.close(self.pidfd)


class WorkerListener:
    """One explicit endpoint and one accept attempt, under the supervisor lock.

    A failed/idle/malformed peer exhausts this object, not the durable request.
    Close leaves the socket inode for explicit endpoint reconciliation. Serving
    does not clear the recovery latch or grant restoration or service startup.
    """
    def __init__(self, path, *, worker_uid, clock=time.monotonic):
        if (type(path) is not str or not os.path.isabs(path)
                or type(worker_uid) is not int or worker_uid <= 0):
            raise Rejected("worker-endpoint-policy-required")
        self.uid, self.clock = worker_uid, clock
        self.attempted, self.closed = False, False
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            parent, name = os.path.split(path)
            if name in ("", ".", ".."):
                raise Rejected("worker-endpoint-required")
            with directory(parent, private=True) as fd:
                self.sock.bind(f"/proc/self/fd/{fd}/{name}")
                os.chmod(name, 0o600, dir_fd=fd, follow_symlinks=False)
                self.sock.listen(1)
        except Exception:
            self.sock.close()
            raise

    def accept_once(self, *, supervisor, observer, deadline):
        if self.attempted or self.closed:
            raise Rejected("worker-listener-exhausted")
        self.attempted = True
        if supervisor.pending_request is None or supervisor.closed or supervisor.error is not None:
            raise Rejected("worker-live-supervisor-required")
        try:
            return self._accept_once(supervisor=supervisor, observer=observer, deadline=deadline)
        except Exception:
            if supervisor.error is None:
                supervisor._fail(Rejected("supervisor-worker-claim-unconfirmed"), "supervisor-worker-claim-unconfirmed")
            raise Rejected("supervisor-worker-claim-unconfirmed") from None

    def _accept_once(self, *, supervisor, observer, deadline):
        Deadline(self.clock, deadline).remaining()
        end = min(deadline, supervisor.pending_request["deadline"])
        timer = Deadline(self.clock, end)
        with selectors.DefaultSelector() as wait:
            wait.register(self.sock, selectors.EVENT_READ)
            if not wait.select(timer.remaining()):
                raise Rejected("worker-accept-expired")
            timer.remaining()
        conn, _ = self.sock.accept()
        with conn:
            conn.setblocking(False)
            session = PeerSession(conn, uid=self.uid, clock=self.clock)
            try:
                request = session.receive(end)
                if (type(request) is not dict or set(request) != {"schema", "request_id", "nonce"}
                        or request["schema"] != "host-recovery-worker-request-v1"
                        or request["request_id"] != supervisor.pending_request["request_id"]
                        or not identity(request["nonce"])):
                    raise Rejected("worker-request-mismatch")
                claim = supervisor.claim_worker(peer=session.peer, nonce=request["nonce"], observer=observer,
                                                peer_alive=session.alive, deadline=end)
                session.reply(claim, end)
                return claim
            finally:
                session.close()

    def close(self):
        self.closed = True
        self.sock.close()


class WorkerClient:
    """One claim, no automatic retry. Its reply is identity evidence only."""
    def __init__(self, path, *, supervisor_uid, supervisor_pid, supervisor_owner, request_id, intent_sha256,
                 clock=time.monotonic):
        validate_owner(supervisor_owner)
        if (type(path) is not str or not os.path.isabs(path) or type(supervisor_uid) is not int or supervisor_uid <= 0
                or type(supervisor_pid) is not int or not 1 <= supervisor_pid <= 2147483647
                or type(request_id) is not str or HASH.fullmatch(request_id) is None
                or type(intent_sha256) is not str or HASH.fullmatch(intent_sha256) is None):
            raise Rejected("worker-client-policy-required")
        self.path, self.uid, self.pid = path, supervisor_uid, supervisor_pid
        self.owner, self.request_id, self.intent_sha256 = copy.deepcopy(supervisor_owner), request_id, intent_sha256
        self.clock, self.attempted = clock, False

    def claim(self, *, deadline):
        if self.attempted:
            raise Rejected("worker-client-exhausted")
        self.attempted = True
        timer = Deadline(self.clock, deadline)
        timer.remaining()
        nonce = str(uuid.uuid4())
        parent, name = os.path.split(self.path)
        with directory(parent, private=True) as fd:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISSOCK(st.st_mode) or st.st_uid != self.uid or stat.S_IMODE(st.st_mode) != 0o600:
                raise Rejected("worker-private-socket-required")
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                sock.connect(f"/proc/self/fd/{fd}/{name}")
                session = PeerSession(sock, uid=self.uid, pid=self.pid, clock=self.clock)
                try:
                    session.reply({"schema": "host-recovery-worker-request-v1", "request_id": self.request_id,
                                   "nonce": nonce}, deadline)
                    value = session.receive(deadline)
                    fields = {"schema", "request_id", "intent_sha256", "supervisor_owner", "worker", "peer", "nonce",
                              "restoration_permission", "start_permission"}
                    if (type(value) is not dict or set(value) != fields
                            or value["schema"] != "host-recovery-worker-claim-v1"
                            or value["request_id"] != self.request_id or value["nonce"] != nonce
                            or canonical(value["supervisor_owner"]) != canonical(self.owner)
                            or value["intent_sha256"] != self.intent_sha256
                            or canonical(value["peer"]) != canonical({"pid": os.getpid(), "uid": os.geteuid(), "gid": os.getegid()})
                            or value["restoration_permission"] is not False or value["start_permission"] is not False):
                        raise Rejected("worker-claim-reply-unconfirmed")
                    validate_worker(value["worker"], self.request_id, self.owner["boot_id"], os.getpid())
                    timer.remaining()
                    return value
                finally:
                    session.close()
