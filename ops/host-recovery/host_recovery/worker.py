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
from .durable import Rejected, canonical, decode, digest, directory
from .inventory import HASH
from .jobs import validate_worker
from .journal import identity
from .outcomes import validate_result
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


def cancellation_pending(fd):
    """A caller-owned readable descriptor revokes this exchange; never consume it."""
    if fd is None:
        return False
    if type(fd) is not int or fd < 0:
        raise Rejected("worker-cancellation-descriptor-required")
    # Closed/invalid descriptors refuse rather than disabling cancellation.
    os.fstat(fd)
    return bool(select.select([fd], [], [], 0)[0])


class PeerSession:
    """One bounded exchange with an exact kernel peer, held by pidfd."""
    def __init__(self, sock, *, uid, pid=None, clock=time.monotonic, cancel_fd=None):
        if cancellation_pending(cancel_fd):
            raise Rejected("worker-exchange-cancelled")
        self.cancel_fd = cancel_fd
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
        self.disconnected = False

    def process_alive(self):
        """Transport/terminal-receipt identity only, never an execution lease.

        A final non-authorizing receipt may be buffered when the sender closes
        its socket. Kernel credentials and the pinned process must still match.
        """
        try:
            return (not self.closed and not cancellation_pending(self.cancel_fd)
                    and not select.select([self.pidfd], [], [], 0)[0]
                    and peer(self.sock, self.peer["uid"]) == self.peer)
        except (OSError, ValueError):
            return False

    def alive(self):
        if self.closed or self.disconnected:
            return False
        try:
            # A pidfd proves process lifetime, not ownership of this connection.
            # The supervisor can close its accepted socket and release the lock
            # while staying alive. Do not consume queued protocol packets here;
            # hangup/half-close must revoke even with buffered data still present.
            poll = select.poll()
            poll.register(self.sock, select.POLLIN | select.POLLRDHUP)
            lost = select.POLLHUP | select.POLLRDHUP | select.POLLERR | select.POLLNVAL
            if any(events & lost for _, events in poll.poll(0)) or not self.process_alive():
                self.disconnected = True
        except (OSError, ValueError):
            self.disconnected = True
        return not self.disconnected

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
            if self.cancel_fd is not None:
                wait.register(self.cancel_fd, selectors.EVENT_READ)
            events = wait.select(timer.remaining())
            if not events or not self.process_alive() or any(key.fd == self.pidfd for key, _ in events):
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
        if not self.process_alive():
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
    def __init__(self, path, *, worker_uid, clock=time.monotonic, cancel_fd=None):
        if cancellation_pending(cancel_fd):
            raise Rejected("worker-exchange-cancelled")
        self.cancel_fd = cancel_fd
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

    def accept_once(self, *, supervisor, observer, deadline, result_oracle=None):
        if result_oracle is not None and not callable(result_oracle):
            raise Rejected("worker-result-oracle-required")
        if self.attempted or self.closed:
            raise Rejected("worker-listener-exhausted")
        self.attempted = True
        if supervisor.pending_request is None or supervisor.closed or supervisor.error is not None:
            raise Rejected("worker-live-supervisor-required")
        try:
            return self._accept_once(supervisor=supervisor, observer=observer, deadline=deadline, result_oracle=result_oracle)
        except Exception:
            code = "supervisor-worker-result-unconfirmed" if result_oracle is not None else "supervisor-worker-claim-unconfirmed"
            if supervisor.error is None:
                supervisor._fail(Rejected(code), code)
            raise Rejected(code) from None

    def _accept_once(self, *, supervisor, observer, deadline, result_oracle):
        Deadline(self.clock, deadline).remaining()
        end = min(deadline, supervisor.pending_request["deadline"])
        timer = Deadline(self.clock, end)
        with selectors.DefaultSelector() as wait:
            wait.register(self.sock, selectors.EVENT_READ)
            if self.cancel_fd is not None:
                wait.register(self.cancel_fd, selectors.EVENT_READ)
            if not wait.select(timer.remaining()):
                raise Rejected("worker-accept-expired")
            timer.remaining()
            if cancellation_pending(self.cancel_fd):
                raise Rejected("worker-exchange-cancelled")
        conn, _ = self.sock.accept()
        with conn:
            conn.setblocking(False)
            session = PeerSession(conn, uid=self.uid, clock=self.clock, cancel_fd=self.cancel_fd)
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
                if result_oracle is not None:
                    result = session.receive(end)
                    supervisor.record_worker_result(result, peer=session.peer, observer=observer,
                                                    peer_alive=session.alive, deadline=end)
                    status = supervisor.observe_result(observer=observer, oracle=result_oracle, deadline=end)
                    if status["worker_result_observed"] is not True:
                        raise Rejected("supervisor-worker-result-unconfirmed")
                    if not session.alive():
                        raise Rejected("supervisor-worker-result-unconfirmed")
                    session.reply({"schema": "host-recovery-worker-result-receipt-v1",
                                   "result_sha256": digest(canonical(result)), "observed": True,
                                   "installation_settled": False, "start_permission": False}, end)
                return claim
            finally:
                session.close()

    def close(self):
        self.closed = True
        self.sock.close()


class WorkerClient:
    """One claim, no automatic retry. Its reply is identity evidence only."""
    def __init__(self, path, *, supervisor_uid, supervisor_pid, supervisor_owner, request_id, intent_sha256,
                 clock=time.monotonic, verify_identity=None):
        validate_owner(supervisor_owner)
        if verify_identity is not None and not callable(verify_identity):
            raise Rejected("worker-client-verifier-required")
        if (type(path) is not str or not os.path.isabs(path) or type(supervisor_uid) is not int or supervisor_uid <= 0
                or type(supervisor_pid) is not int or not 1 <= supervisor_pid <= 2147483647
                or type(request_id) is not str or HASH.fullmatch(request_id) is None
                or type(intent_sha256) is not str or HASH.fullmatch(intent_sha256) is None):
            raise Rejected("worker-client-policy-required")
        self.path, self.uid, self.pid = path, supervisor_uid, supervisor_pid
        self.owner, self.request_id, self.intent_sha256 = copy.deepcopy(supervisor_owner), request_id, intent_sha256
        self.clock, self.attempted = clock, False
        self.verify_identity = verify_identity
        self.result_receipt = None

    def _verify_identity(self, session, deadline, *, receipt_only=False):
        if self.verify_identity is None:
            return None
        # Only final non-authorizing receipt validation may outlive socket close.
        # Execution callbacks always require the live connection, not just its PID.
        alive = session.process_alive if receipt_only else session.alive
        if not alive():
            raise Rejected("worker-peer-unconfirmed")
        result = self.verify_identity(peer=copy.deepcopy(session.peer), peer_alive=alive, deadline=deadline)
        validate_worker(result, self.request_id, self.owner["boot_id"], os.getpid())
        if not alive():
            raise Rejected("worker-peer-unconfirmed")
        Deadline(self.clock, deadline).remaining()
        return copy.deepcopy(result)

    def claim(self, *, deadline, result_provider=None, recovery_provider=None):
        """Optionally report evidence on the same live connection after identity.

        result_provider(claim, deadline=...) returns only outcome/evidence_sha256.
        recovery_provider additionally receives check(deadline=...), valid only
        during its call, for live manager/peer revalidation at execution barriers.
        It requires an independent identity verifier and recovery authorization;
        the claim and check callback grant neither restoration nor starts. No
        retry occurs after a provider failure, lost report or ambiguous receipt.
        The original inclusive deadline covers the entire exchange and provider.
        """
        if (result_provider is not None and not callable(result_provider)
                or recovery_provider is not None and not callable(recovery_provider)
                or result_provider is not None and recovery_provider is not None
                or recovery_provider is not None and self.verify_identity is None):
            raise Rejected("worker-result-provider-required")
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
                    observed = self._verify_identity(session, deadline)
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
                    if self.verify_identity is not None:
                        after = self._verify_identity(session, deadline,
                            receipt_only=result_provider is None and recovery_provider is None)
                        if canonical(after) != canonical(observed) or canonical(value["worker"]) != canonical(observed):
                            raise Rejected("worker-manager-claim-mismatch")
                    timer.remaining()
                    if result_provider is not None or recovery_provider is not None:
                        if recovery_provider is None:
                            supplied = result_provider(copy.deepcopy(value), deadline=deadline)
                        else:
                            active, revoked = True, False
                            def check(*, deadline):
                                nonlocal revoked
                                try:
                                    if not active or revoked or deadline > timer.deadline:
                                        raise Rejected("worker-recovery-lease-unavailable")
                                    Deadline(self.clock, deadline).remaining()
                                    if canonical(self._verify_identity(session, deadline)) != canonical(observed):
                                        raise Rejected("worker-manager-claim-mismatch")
                                    Deadline(self.clock, deadline).remaining()
                                    return True
                                except BaseException:
                                    revoked = True
                                    raise
                            try:
                                check(deadline=deadline)
                                supplied = recovery_provider(copy.deepcopy(value), deadline=deadline, check=check)
                                check(deadline=deadline)
                            finally:
                                active = False
                        if type(supplied) is not dict or set(supplied) != {"outcome", "evidence_sha256"}:
                            raise Rejected("worker-result-provider-schema")
                        result = {"schema": "host-recovery-worker-result-v1", "request_id": self.request_id,
                                  "intent_sha256": self.intent_sha256, "claim_sha256": digest(canonical(value)),
                                  **supplied}
                        validate_result(result, {"request_id": self.request_id, "intent_sha256": self.intent_sha256}, value)
                        if self.verify_identity is not None:
                            if canonical(self._verify_identity(session, deadline)) != canonical(observed):
                                raise Rejected("worker-manager-claim-mismatch")
                        session.reply(result, deadline)
                        receipt = session.receive(deadline)
                        expected = {"schema": "host-recovery-worker-result-receipt-v1",
                                    "result_sha256": digest(canonical(result)), "observed": True,
                                    "installation_settled": False, "start_permission": False}
                        if canonical(receipt) != canonical(expected):
                            raise Rejected("worker-result-receipt-unconfirmed")
                        if self.verify_identity is not None:
                            if canonical(self._verify_identity(session, deadline, receipt_only=True)) != canonical(observed):
                                raise Rejected("worker-manager-claim-mismatch")
                        timer.remaining()
                        self.result_receipt = copy.deepcopy(receipt)
                    return value
                finally:
                    session.close()
