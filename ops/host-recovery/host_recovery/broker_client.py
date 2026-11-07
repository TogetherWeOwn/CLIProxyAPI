"""One-shot, non-authorizing observation client on a provisioned broker session.

No endpoint default/discovery, reconnect/retry, mutation method, worker/root role
promotion or runtime grant. An embedding service must supply independent binding,
epoch, broker identity and a connected socket; this module provisions none of them.
"""
import secrets
import uuid

from .broker_identity import BrokerPeerIdentity
from .broker_operations import positive, validate_binding, validate_epoch
from .commands import Deadline
from .durable import Rejected, canonical, digest
from .privileged_broker import acknowledgment, request, response


class ObservationClient:
    def __init__(self, *, broker, binding, epoch, deadline):
        if not isinstance(broker, BrokerPeerIdentity):
            raise Rejected("broker-client-independent-identity-required")
        validate_binding(binding)
        validate_epoch(epoch)
        if (not positive(deadline) or deadline > min(broker.deadline, binding["recovery_deadline"])
                or epoch["boot_id"] != binding["original_boot_id"]
                or epoch["boot_id"] != broker.binding.boot_id
                or epoch["broker_invocation_id"] != str(uuid.UUID(broker.binding.invocation_id))):
            raise Rejected("broker-client-original-epoch-required")
        self.broker, self.deadline = broker, deadline
        self._binding_sha256, self._epoch_sha256 = digest(canonical(binding)), digest(canonical(epoch))
        self.attempted, self.failed = False, False

    def observe_installation(self, *, deadline):
        if self.attempted:
            raise Rejected("broker-client-exhausted")
        self.attempted = True
        try:
            if not positive(deadline) or deadline > self.deadline:
                raise Rejected("broker-client-original-deadline-required")
            session = self.broker.session
            timer = Deadline(session._now, deadline)
            self.broker.observe(deadline=deadline)
            value = request(binding_sha256=self._binding_sha256, epoch_sha256=self._epoch_sha256,
                            nonce=secrets.token_hex(32), deadline=deadline)
            session.reply(value, deadline)
            actual = session.receive(deadline)
            if canonical(actual) != canonical(response(value)):
                raise Rejected("broker-client-response-unbound")
            # Neither a root socket's UID nor its JSON reply authenticates a
            # manager invocation. Observe again after every reply, before ACK.
            self.broker.observe(deadline=deadline)
            session.reply(acknowledgment(value), deadline)
            timer.remaining()
            return actual
        except Exception:
            self.failed = self.broker.failed = True
            raise Rejected("broker-client-observation-unconfirmed") from None
