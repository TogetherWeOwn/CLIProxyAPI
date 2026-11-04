"""Bounded Linux local alert admission, independent of recovery receipt storage.

A receipt means admission to this listener's VOLATILE bounded inbox, not durable
external delivery or human acknowledgment. The service owner must drain it into
an independently approved route. No host paths, credentials, install commands or
external-network defaults exist. A private same-uid directory is required; hostile
root/same-uid actors are outside this boundary. This is not a supervisor or fence.
"""
from collections import deque
import math
import os
import select
import selectors
import socket
import stat
import struct
import time
import uuid

from .durable import Rejected, canonical, decode, digest, directory
from .journal import identity

MAX_PACKET = 4096
SUPERVISOR_ERRORS = frozenset((
    "supervisor-recovery-intent-required", "supervisor-intent-owner-mismatch",
    "supervisor-dispatch-reconciliation-required", "supervisor-arm-pin-mismatch", "supervisor-arm-schema",
    "supervisor-cross-boot-continuation-required", "supervisor-clock-continuation-required",
    "supervisor-expired-continuation-required", "supervisor-watch-stopped", "supervisor-watch-expired",
    "supervisor-worker-outcome-unverified", "supervisor-watch-observation-limit",
    "supervisor-state-unavailable", "supervisor-dispatch-unconfirmed", "supervisor-watch-unconfirmed",
    "supervisor-job-observation-unconfirmed", "supervisor-worker-claim-unconfirmed"))
CAUSES = {
    "original_cause": frozenset(("admission-persistence-or-clock-failed", "explicit-recovery-request",
                                  "forward-stop-failed", "forward-revalidate-failed", "forward-mutate-failed",
                                  "forward-candidate-start-failed", "forward-postchecks-failed", "forward-persistence-failed",
                                  "supervisor-restart-recovery-required", "restart-original-cause-unavailable")),
    "recovery_error": frozenset(("recovery-resume-inputs-failed", "recovery-detection-failed", "recovery-quiescence-failed", "recovery-restore-failed",
                                  "recovery-verification-start-failed", "recovery-persistence-failed",
                                  "alert-budget-or-clock-unavailable", "independent-alert-delivery-failed")) | SUPERVISOR_ERRORS,
}
NOTICE_FIELDS = {"schema", "attempt_id", "original_cause", "recovery_error", "outcome", "start_fenced"}


def validate_notice(value):
    if type(value) is not dict or set(value) != NOTICE_FIELDS or value["schema"] != "host-recovery-notice-v1":
        raise Rejected("alert-notice-schema")
    attempt = value["attempt_id"]
    if attempt is not None:
        try:
            if str(uuid.UUID(attempt)) != attempt:
                raise ValueError()
        except (ValueError, AttributeError, TypeError):
            raise Rejected("alert-attempt-identity") from None
    for key in ("original_cause", "recovery_error"):
        code = value[key]
        if code is not None and (type(code) is not str or code not in CAUSES[key]):
            raise Rejected("alert-fixed-code-required")
    if (value["outcome"] not in ("fenced", "recovery_unresolved", "baseline_restored", "candidate_verified")
            or value["start_fenced"] is not True):
        raise Rejected("alert-outcome-schema")


def peer(sock, uid):
    pid, actual_uid, gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if actual_uid != uid or pid <= 0:
        raise Rejected("alert-peer-mismatch")
    return {"pid": pid, "uid": actual_uid, "gid": gid}


def packet(sock):
    raw, ancillary, flags, _ = sock.recvmsg(MAX_PACKET, socket.CMSG_SPACE(16), socket.MSG_CMSG_CLOEXEC)
    if not raw or ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        # Close any received descriptors even though SCM_RIGHTS is not supported.
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                for fd in struct.unpack("i" * (len(data) // 4), data[:len(data) // 4 * 4]):
                    os.close(fd)
        raise Rejected("alert-packet-invalid")
    return decode(raw)


def send(sock, value):
    raw = canonical(value)
    if len(raw) > MAX_PACKET or sock.send(raw) != len(raw):
        raise Rejected("alert-send-unconfirmed")


class AlertClient:
    """One request per connection; no retries after an ambiguous send/receipt.

    Deadlines are inclusive local IPC phase deadlines supplied by the supervisor,
    not fresh allowances or upstream network timeouts. A preflight receipt pins
    the listener instance; a replacement cannot silently inherit that receipt.
    """
    def __init__(self, path, route_id, *, listener_uid, clock=time.monotonic):
        if not os.path.isabs(path) or not identity(route_id) or type(listener_uid) is not int or listener_uid < 0:
            raise Rejected("alert-route-required")
        self.path = path
        self.route_id = route_id
        self.uid = listener_uid
        self.clock = clock
        self.instance_id = None
        self.delivery_receipt = None
        self.last_clock = None

    def _remaining(self, deadline):
        now = self.clock()
        if (type(deadline) not in (int, float) or not math.isfinite(deadline)
                or type(now) not in (int, float) or not math.isfinite(now) or now >= deadline
                or self.last_clock is not None and now < self.last_clock):
            raise Rejected("alert-deadline-or-clock-invalid")
        self.last_clock = now
        return deadline - now

    def _exchange(self, request, deadline):
        self._remaining(deadline)
        parent, name = os.path.split(self.path)
        with directory(parent, private=True) as fd:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISSOCK(st.st_mode) or st.st_uid != self.uid or stat.S_IMODE(st.st_mode) != 0o600:
                raise Rejected("private-alert-socket-required")
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK) as sock:
                # fd-relative endpoint prevents an ancestor rename/replacement
                # from silently redirecting this connection's path lookup.
                try:
                    sock.connect(f"/proc/self/fd/{fd}/{name}")
                except BlockingIOError:
                    raise Rejected("alert-connect-unconfirmed") from None
                peer(sock, self.uid)
                with selectors.DefaultSelector() as wait:
                    wait.register(sock, selectors.EVENT_WRITE)
                    if not wait.select(self._remaining(deadline)):
                        raise Rejected("alert-deadline-expired")
                    send(sock, request)
                    wait.modify(sock, selectors.EVENT_READ)
                    if not wait.select(self._remaining(deadline)):
                        raise Rejected("alert-deadline-expired")
                    response = packet(sock)
                    self._remaining(deadline)
        return response

    def preflight(self, *, deadline):
        self.instance_id = None
        nonce = str(uuid.uuid4())
        request = {"schema": "host-alert-request-v1", "kind": "challenge", "route_id": self.route_id, "nonce": nonce}
        response = self._exchange(request, deadline)
        expected = {"schema", "kind", "route_id", "nonce", "instance_id", "admission", "durable", "human_acknowledged"}
        if (set(response) != expected or response["schema"] != "host-alert-receipt-v1"
                or response["kind"] != "challenge" or response["route_id"] != self.route_id
                or response["nonce"] != nonce or not identity(response["instance_id"])
                or response["admission"] != "available" or response["durable"] is not False
                or response["human_acknowledged"] is not False):
            raise Rejected("alert-challenge-unconfirmed")
        self.instance_id = response["instance_id"]
        return response

    def deliver(self, notice, *, deadline):
        self.delivery_receipt = None
        validate_notice(notice)
        if self.instance_id is None:
            raise Rejected("alert-preflight-required")
        nonce = str(uuid.uuid4())
        request = {"schema": "host-alert-request-v1", "kind": "notice", "route_id": self.route_id,
                   "nonce": nonce, "instance_id": self.instance_id, "notice": notice}
        response = self._exchange(request, deadline)
        expected = {"schema": "host-alert-receipt-v1", "kind": "notice", "route_id": self.route_id,
                    "nonce": nonce, "instance_id": self.instance_id, "admission": "volatile-inbox",
                    "notice_sha256": digest(canonical(notice)), "durable": False, "human_acknowledged": False}
        if set(response) != set(expected) or any(type(response[k]) is not type(v) or response[k] != v for k, v in expected.items()):
            raise Rejected("alert-delivery-unconfirmed")
        self.delivery_receipt = response
        return True


class AlertListener:
    """Explicit single-owner listener, with no implicit file cleanup or sink I/O.

    Call poll() from its independent service loop. Work per call, open peers,
    packet sizes and inbox are capped. Idle peers expire on the same clock.
    drain() transfers admitted notices to the caller; it is NOT external delivery.
    Socket files remain after close so a lost/restarted service needs explicit
    endpoint reconciliation, never unlink-and-replace a possibly live owner.
    """
    def __init__(self, path, route_id, *, sender_uid, capacity, max_peers, peer_seconds, clock=time.monotonic):
        if (not os.path.isabs(path) or not identity(route_id) or type(sender_uid) is not int or sender_uid < 0
                or type(capacity) is not int or not 1 <= capacity <= 1024
                or type(max_peers) is not int or not 1 <= max_peers <= 64
                or type(peer_seconds) not in (int, float) or not math.isfinite(peer_seconds) or not 0 < peer_seconds <= 10):
            raise Rejected("alert-listener-policy-required")
        self.route_id = route_id
        self.uid = sender_uid
        self.capacity = capacity
        self.max_peers = max_peers
        self.peer_seconds = peer_seconds
        self.clock = clock
        self.last_clock = None
        self.instance_id = str(uuid.uuid4())
        self.inbox = deque()
        self.peers = {}
        self.wait = selectors.DefaultSelector()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK)
        try:
            parent, name = os.path.split(path)
            if not name or name in (".", ".."):
                raise Rejected("alert-endpoint-required")
            with directory(parent, private=True) as fd:
                # Binding never removes an existing socket, file or symlink.
                self.sock.bind(f"/proc/self/fd/{fd}/{name}")
                os.chmod(name, 0o600, dir_fd=fd, follow_symlinks=False)
                self.sock.listen(max_peers)
            self.wait.register(self.sock, selectors.EVENT_READ)
        except Exception:
            self.sock.close()
            self.wait.close()
            raise

    def _drop(self, conn):
        self.wait.unregister(conn)
        del self.peers[conn]
        conn.close()

    def _request(self, value):
        common = {"schema", "kind", "route_id", "nonce"}
        kind = value.get("kind")
        expected = common if kind == "challenge" else common | {"instance_id", "notice"}
        if (kind not in ("challenge", "notice") or set(value) != expected
                or value["schema"] != "host-alert-request-v1" or value["route_id"] != self.route_id
                or not identity(value["nonce"]) or len(self.inbox) >= self.capacity):
            raise Rejected("alert-request-refused")
        result = {"schema": "host-alert-receipt-v1", "kind": kind, "route_id": self.route_id,
                  "nonce": value["nonce"], "instance_id": self.instance_id,
                  "admission": "available", "durable": False, "human_acknowledged": False}
        if kind == "notice":
            if value["instance_id"] != self.instance_id:
                raise Rejected("alert-listener-replaced")
            validate_notice(value["notice"])
            # Canonical bytes isolate the admitted value from caller mutation.
            raw = canonical(value["notice"])
            self.inbox.append(raw)
            result.update(admission="volatile-inbox", notice_sha256=digest(raw))
        return result

    def _now(self):
        now = self.clock()
        if (type(now) not in (int, float) or not math.isfinite(now)
                or self.last_clock is not None and now < self.last_clock):
            raise Rejected("alert-listener-clock-invalid")
        self.last_clock = now
        return now

    def poll(self):
        now = self._now()
        for conn, expires in list(self.peers.items()):
            if now >= expires:
                self._drop(conn)
        for key, _ in self.wait.select(0):
            conn = key.fileobj
            if conn is self.sock:
                for _ in range(self.max_peers):
                    try:
                        child, _ = self.sock.accept()
                    except BlockingIOError:
                        break
                    child.setblocking(False)
                    try:
                        peer(child, self.uid)
                        if len(self.peers) >= self.max_peers:
                            raise Rejected("alert-peer-capacity")
                        expires = self._now() + self.peer_seconds
                        self.wait.register(child, selectors.EVENT_READ)
                        self.peers[child] = expires
                    except Exception:
                        child.close()
            else:
                try:
                    send(conn, self._request(packet(conn)))
                except (OSError, Rejected):
                    # No reply is never success. An admitted notice whose ACK is
                    # lost remains in the inbox; clients must not retry it.
                    pass
                finally:
                    self._drop(conn)

    def serve(self, stop_fd):
        """Serve until an explicitly owned stop descriptor is readable/closed.

        The loop performs no persistence or external sink I/O. Its receipt only
        attests volatile admission; a standalone inbox is not an operator route.
        """
        while True:
            now = self._now()
            delay = max(0, min(self.peers.values()) - now) if self.peers else None
            ready, _, _ = select.select([stop_fd, self.sock, *self.peers], [], [], delay)
            if stop_fd in ready:
                return
            self.poll()

    def drain(self):
        return decode(self.inbox.popleft()) if self.inbox else None

    def close(self):
        for conn in list(self.peers):
            self._drop(conn)
        self.wait.close()
        self.sock.close()
