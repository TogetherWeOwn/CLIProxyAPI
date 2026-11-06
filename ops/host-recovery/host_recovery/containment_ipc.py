"""Fixed connected broker containment; never a complete fence or start grant.

Trusted embedding supplies the original live authority and pinned mask/manager/
domain adapters. Packets choose no unit, path, signal, argv, callback or runtime.
No service entrypoint enables this protocol before provisioning qualification.
The separate observation-only protocol and all operational runner denies remain.
"""
import secrets

from .broker_client import ObservationClient
from .broker_operations import positive, shape
from .commands import Deadline
from .durable import Rejected, canonical, decode, digest
from .loading import pin
from .masked_forward_stop import MaskedForwardStop
from .masked_runtime_stop import MaskedRuntimeStop
from .privileged_broker import ObservationServer, acknowledgment, request

METHODS = {"contain_forward": MaskedForwardStop, "cold_quiesce_runtime": MaskedRuntimeStop}
DENIES = ("manager_jobs_retired", "activation_exclusion_proven", "cgroup_quiescence_proven",
          "pending_drained", "complete_fence_proven", "recovery_execution_allowed", "start_allowed",
          "settlement_allowed", "production_acceptance")


def containment_request(*, method, target_sha256, **kwargs):
    if type(method) is not str or method not in METHODS:
        raise Rejected("containment-fixed-method-required")
    pin(target_sha256)
    value = request(**kwargs)
    value.update(schema="host-recovery-containment-request-v1", method=method, target_sha256=target_sha256)
    return value


def operation_for(value):
    # This protocol admits only the first two fixed recovery submissions. It does
    # not resume, adopt or fill gaps in a retained broker history.
    operation = {"schema": "host-recovery-broker-operation-v1", "state": "pending",
        "binding_sha256": value["binding_sha256"], "epoch_sha256": value["epoch_sha256"],
        "sequence": 1 if value["method"] == "contain_forward" else 2, "method": value["method"],
        "target_sha256": value["target_sha256"], "deadline": value["deadline"]}
    operation["operation_id"] = digest(canonical(operation))
    return operation


def return_for(operation):
    return {"schema": "host-recovery-broker-return-v1", "operation_id": operation["operation_id"],
            "result": "returned", "pending_drained": False}


def containment_response(value):
    operation = operation_for(value)
    observation = {key: False for key in DENIES}
    observation.update(fixed_stop_completion_observed=True, masked_inactive_observed=True,
                       auxiliary_commands_empty_observed=True, control_pid_zero_observed=True,
                       autonomous_launch_policy_observed=True)
    if value["method"] == "cold_quiesce_runtime":
        observation.update(recursive_domain_kill_returned=True, domain_empty_observed=True,
                           observed_runtime_processes_dead=True, runtime_containment_coverage_proven=False,
                           persisted_restart_policy_observed=True, runtime_relaunch_allowed=False)
    return {"schema": "host-recovery-containment-response-v1", "request_sha256": digest(canonical(value)),
        "binding_sha256": value["binding_sha256"], "epoch_sha256": value["epoch_sha256"],
        "nonce": value["nonce"], "method": value["method"], "target_sha256": value["target_sha256"],
        "operation_id": operation["operation_id"], "return_sha256": digest(canonical(return_for(operation))),
        "observation": observation}


class ContainmentServer(ObservationServer):
    """One fixed submission on the original supervisor's authenticated connection.

    Owns the sequence's retained witnesses through durable return and peer ACK,
    not the listening socket, installation lock or manager session. The embedding
    broker owns those lifetimes. A lost response/ACK cannot reissue any effect.
    """
    def __init__(self, *, authority, sequence):
        if (type(sequence) not in (MaskedForwardStop, MaskedRuntimeStop)
                or sequence.authority is not authority or sequence.attempted or sequence.failed):
            raise Rejected("containment-original-unused-sequence-required")
        super().__init__(authority=authority, epoch=decode(sequence.journal._epoch))
        if authority._binding != sequence.journal._binding:
            raise Rejected("containment-original-journal-required")
        if type(sequence) is MaskedRuntimeStop and sequence.policy is None:
            raise Rejected("containment-runtime-persisted-policy-required")
        self.sequence, self.journal = sequence, sequence.journal
        self._original = authority, sequence, sequence.journal
        self._target = sequence.target_sha256
        self._method = sequence.method

    def _current(self):
        if (self.failed or (self.authority, self.sequence, self.journal) != self._original
                or type(self.sequence) is not METHODS.get(self._method)
                or self.sequence.method != self._method or self.sequence.target_sha256 != self._target
                or self.sequence.authority is not self.authority):
            raise Rejected("containment-configuration-changed")
        self.journal._current()
        self.journal._time(self.sequence.session.deadline)
        self.authority.observe(deadline=self.sequence.session.deadline)

    def serve_once(self, *, deadline):
        if self.attempted:
            raise Rejected("containment-protocol-exhausted")
        self.attempted = True
        try:
            # Keep the journal's own serialization across receive, pending,
            # effects, return durability and ACK. This is not a second flock.
            with self.journal._mutex:
                end = self.sequence.session.deadline
                if not positive(deadline) or end > deadline:
                    raise Rejected("containment-original-deadline-required")
                self.authority.observe(deadline=end)
                self._current()
                prior = set() if self._method == "contain_forward" else {"contain_forward"}
                if set(self.journal._pending) != prior or self.journal._returned != prior:
                    raise Rejected("containment-original-operation-order-required")
                value = self.session.receive(end)
                shape(value, ("schema", "method", "binding_sha256", "epoch_sha256", "nonce", "deadline", "target_sha256"))
                expected = containment_request(method=self._method, target_sha256=self._target,
                    binding_sha256=self._binding_sha256, epoch_sha256=self._epoch_sha256,
                    nonce=value["nonce"], deadline=self.sequence.session.deadline)
                if canonical(value) != canonical(expected) or value["deadline"] > deadline:
                    raise Rejected("containment-request-unbound")
                self._current()
                operation = self.journal.pending(self._method, target_sha256=self._target, deadline=value["deadline"])
                if canonical(operation) != canonical(operation_for(expected)):
                    raise Rejected("containment-operation-unbound")
                self._current()
                observed = self.sequence.stop(operation=operation)
                wanted = containment_response(expected)
                if (observed["operation_id"] != operation["operation_id"]
                        or observed["target_sha256"] != self._target
                        or any(type(observed.get(key)) is not type(item) or observed[key] != item
                               for key, item in wanted["observation"].items())):
                    raise Rejected("containment-observation-unconfirmed")
                self._current()
                returned = self.sequence.record_return()
                if canonical(returned) != canonical(return_for(operation)):
                    raise Rejected("containment-return-unbound")
                self._current()
                self.session.reply(wanted, value["deadline"])
                if canonical(self.session.receive(value["deadline"])) != canonical(acknowledgment(expected)):
                    raise Rejected("containment-ack-unbound")
                self.sequence.revalidate_completed()
                self._current()
                return wanted
        except Exception:
            self.failed = self.authority.failed = self.journal._failed = self.sequence.failed = True
            raise Rejected("containment-protocol-unconfirmed") from None
        finally:
            try:
                self.sequence.close()
            except Exception:
                self.failed = self.authority.failed = self.journal._failed = True
                raise Rejected("containment-resource-release-unconfirmed") from None


class ContainmentClient(ObservationClient):
    """No reconnect/retry; a returned submission never authorizes restoration."""
    def __init__(self, *, method, target_sha256, **kwargs):
        if type(method) is not str or method not in METHODS:
            raise Rejected("containment-fixed-method-required")
        pin(target_sha256)
        super().__init__(**kwargs)
        self._method, self._target = method, target_sha256

    def submit(self, *, deadline):
        if self.attempted:
            raise Rejected("containment-client-exhausted")
        self.attempted = True
        try:
            if type(deadline) not in (int, float) or not 0 < deadline <= self.deadline:
                raise Rejected("containment-original-deadline-required")
            session = self.broker.session
            timer = Deadline(session._now, deadline)
            self.broker.observe(deadline=deadline)
            value = containment_request(method=self._method, target_sha256=self._target,
                binding_sha256=self._binding_sha256, epoch_sha256=self._epoch_sha256,
                nonce=secrets.token_hex(32), deadline=deadline)
            session.reply(value, deadline)
            actual = session.receive(deadline)
            if canonical(actual) != canonical(containment_response(value)):
                raise Rejected("containment-client-response-unbound")
            self.broker.observe(deadline=deadline)
            session.reply(acknowledgment(value), deadline)
            self.broker.observe(deadline=deadline)
            timer.remaining()
            return actual
        except Exception:
            self.failed = self.broker.failed = True
            raise Rejected("containment-client-unconfirmed") from None
