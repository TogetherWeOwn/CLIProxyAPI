"""Fixed connected-session observation protocol for the separate broker.

Only observe_installation is implemented, and only its original-supervisor
projection. All effect methods are denied before any pending record or effect.
This is not a privileged daemon, socket provisioning, runtime inventory, cold
barrier or execution interface. Existing operational runners retain their denies.
"""
import socket

from .broker_authority import SupervisorPeerAuthority
from .broker_operations import positive, shape, validate_epoch
from .durable import Rejected, canonical, decode, digest
from .loading import pin


OBSERVATION = {"schema": "host-recovery-broker-authority-observation-v1",
               "original_supervisor_observed": True, "original_lock_observed": True,
               "original_inputs_observed": True, "pending_drained": False,
               "complete_fence_proven": False, "recovery_execution_allowed": False,
               "start_allowed": False, "settlement_allowed": False, "production_acceptance": False}


def request(*, binding_sha256, epoch_sha256, nonce, deadline):
    for value in (binding_sha256, epoch_sha256, nonce):
        pin(value)
    if not positive(deadline):
        raise Rejected("broker-protocol-original-deadline-required")
    return {"schema": "host-recovery-broker-request-v1", "method": "observe_installation",
            "binding_sha256": binding_sha256, "epoch_sha256": epoch_sha256,
            "nonce": nonce, "deadline": deadline}


def response(value):
    return {"schema": "host-recovery-broker-response-v1", "request_sha256": digest(canonical(value)),
            "binding_sha256": value["binding_sha256"], "epoch_sha256": value["epoch_sha256"],
            "nonce": value["nonce"], "observation": decode(canonical(OBSERVATION))}


def acknowledgment(value):
    return {"schema": "host-recovery-broker-ack-v1", "request_sha256": digest(canonical(value))}


class ObservationServer:
    """One exchange on the authenticated ORIGINAL supervisor connection.

    The embedding service owns listening/accept, provisioning, per-installation
    serialization, root self-identity and cleanup. None may come from the packet.
    It constructs authority on this exact session using independent approvals.
    An exhausted exchange is never reset or transparently retried. This class
    borrows the peer, never closes it, acquires no lock and writes no journal.
    """
    def __init__(self, *, authority, epoch):
        if not isinstance(authority, SupervisorPeerAuthority):
            raise Rejected("broker-protocol-explicit-authority-required")
        validate_epoch(epoch)
        if epoch["boot_id"] != decode(authority._binding)["original_boot_id"]:
            raise Rejected("broker-protocol-original-boot-required")
        self.authority, self.session = authority, authority.lock.peer
        if (self.session.sock.family != socket.AF_UNIX
                or self.session.sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET):
            raise Rejected("broker-protocol-seqpacket-required")
        self._binding_sha256 = digest(authority._binding)
        self._epoch_sha256 = digest(canonical(epoch))
        self.attempted, self.failed = False, False
        self.session.sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.session.sock.setblocking(False)

    def serve_once(self, *, deadline):
        if self.attempted:
            raise Rejected("broker-protocol-exhausted")
        self.attempted = True
        try:
            # Recheck before reading, so an idle peer cannot hold an expired or
            # already revoked original owner open with a renewed exchange budget.
            self.authority.observe(deadline=deadline)
            value = self.session.receive(deadline)
            shape(value, ("schema", "method", "binding_sha256", "epoch_sha256", "nonce", "deadline"))
            expected = request(binding_sha256=self._binding_sha256, epoch_sha256=self._epoch_sha256,
                               nonce=value["nonce"], deadline=value["deadline"])
            if canonical(value) != canonical(expected) or value["deadline"] > deadline:
                raise Rejected("broker-protocol-request-unbound")
            end = value["deadline"]
            self.authority.observe(deadline=end)
            receipt = response(expected)
            self.session.reply(receipt, end)
            # Keep the connection alive while the client independently checks the
            # broker after the reply. ACK is transport only, never durable outcome.
            actual = self.session.receive(end)
            if canonical(actual) != canonical(acknowledgment(expected)):
                raise Rejected("broker-protocol-ack-unbound")
            self.authority.observe(deadline=end)
            return receipt
        except Exception:
            self.failed = self.authority.failed = True
            raise Rejected("broker-protocol-observation-unconfirmed") from None
