"""Recovery-only Docker authorization policy, not an installed daemon fence.

This handles a strict subset of the AuthZReq/AuthZRes plugin protocol. A trusted
transport must restrict calls to the pinned daemon and the daemon must apply this
policy to EVERY API route. Neither is installed or proved by this module. Docker
internal restart/restore paths do not necessarily invoke HTTP authorization:
restart=no inspections alone therefore cannot establish the required boot fence.

There is intentionally NO start/create/update/exec or general command grant.
Only the pinned TLS supervisor principal can inspect a bound object or execute a
single explicitly prepared KILL. An operation header correlates the two daemon
callbacks; it is not a credential. Peer authentication and exclusive daemon
configuration remain prerequisites. No credentials are generated or configured.

The installation-lock owner serializes all calls. Any ambiguous disk write or
restart closes mutation admission. A response callback is NOT proof of stopped
state: separate strict object reinspection is required before pending work drains.
"""
import copy
import math
import os
import re

from .commands import Deadline
from .daemon import FIELDS
from .durable import Rejected, canonical, decode, digest
from .journal import OBJECT_ID, identity, validate_intent

OPERATION_HEADER = "X-CPA-Recovery-Operation"
REQUEST_FIELDS = frozenset(("User", "UserAuthNMethod", "RequestMethod", "RequestURI",
                            "RequestHeaders", "RequestBody"))
RESPONSE_FIELDS = REQUEST_FIELDS | {"ResponseStatusCode", "ResponseHeaders", "ResponseBody"}
MAX_OPERATIONS = 64


def reply(allow, code):
    return {"Allow": allow, "Msg": code, "Err": ""}


class RecoveryAuthorization:
    """Deny-first, single-flight, recovery-only authorization decision engine.

    Caller owns the installation lock and supplies its already-open Journal.
    This object has no socket, Docker access or privileged subprocess operation.
    Methods that prepare/reconcile are supervisor-internal, never plugin RPCs.
    No existing journal is automatically adopted after process/manager/boot loss.
    A new reviewed reconciliation protocol must resolve that conservative hold.
    """
    def __init__(self, journal, *, principal, api_version, clock, boot_id):
        if journal.intent is None:
            raise Rejected("authorization-intent-required")
        validate_intent(journal.intent)
        if (not identity(principal) or type(api_version) is not str
                or re.fullmatch(r"1\.[0-9]{2,3}", api_version) is None):
            raise Rejected("authorization-principal-and-api-version-required")
        self.journal = journal
        self.intent = copy.deepcopy(journal.intent)
        self.intent_sha256 = digest(canonical(self.intent))
        self.principal = principal
        self.prefix = "/v" + api_version + "/containers/"
        self.clock, self.boot_id = clock, boot_id
        self.boot = boot_id()
        if self.boot != self.intent["owner"]["boot_id"]:
            raise Rejected("authorization-boot-mismatch")
        self.planned = None
        self.pending = None
        self.returned = False
        self.sealed = False
        self.sequence = 0
        self.uncertain = journal.reopened or journal.uncertain
        self.last_clock = None
        self.objects = {}
        self.receipts = set()

    def _now(self):
        now = self.clock()
        if (type(now) not in (int, float) or not math.isfinite(now) or now <= 0
                or self.boot_id() != self.boot or self.last_clock is not None and now < self.last_clock):
            self.uncertain = True
            self.planned = None
            raise Rejected("authorization-clock-or-boot-discontinuity")
        self.last_clock = now
        return now

    def _time(self, deadline):
        timer = Deadline(self._now, deadline)
        timer.remaining()
        return timer

    def _current(self):
        entries = {name for name in os.listdir(self.journal.fd)
                   if name.startswith(("daemon-operation-", ".stage-daemon-operation-"))}
        if (self.journal.uncertain or self.journal.reopened or self.boot_id() != self.boot
                or entries != self.receipts
                or digest(canonical(self.journal.intent)) != self.intent_sha256):
            self.uncertain = True
            self.planned = None
        if self.uncertain:
            raise Rejected("authorization-reconciliation-required")

    def _observation(self, value):
        if type(value) is not dict or set(value) != FIELDS:
            raise Rejected("authorization-object-observation-required")
        object_id = value["object_id"]
        if type(object_id) is not str or OBJECT_ID.fullmatch(object_id) is None:
            raise Rejected("authorization-full-object-id-required")
        for key in ("running", "paused", "restarting", "dead", "auto_remove"):
            if type(value[key]) is not bool:
                raise Rejected("authorization-object-state-required")
        if (value["restart_policy"] != "no" or type(value["restart_retries"]) is not int
                or value["restart_retries"] != 0 or value["auto_remove"]
                or any(value[key] for key in ("paused", "restarting", "dead"))
                or value["status"] not in (("running",) if value["running"] else ("created", "exited"))):
            raise Rejected("authorization-object-not-restart-fenced")
        expected_image = self.objects.get(object_id)
        if expected_image is None or value["image_id"] != expected_image:
            raise Rejected("authorization-unbound-object-or-image")
        if object_id != self.intent["old_object_id"] and (
                value["installation_id"] != self.intent["installation_id"]
                or value["ownership_id"] != self.intent["candidate_ownership_id"]):
            raise Rejected("authorization-candidate-ownership-mismatch")
        return copy.deepcopy(value)

    def bind(self, *, old_image_id, candidates):
        """Bind only full pinned IDs; this is not daemon discovery or inspection.

        Candidate IDs must already be durably registered by the supervisor. On
        restart the Journal deliberately does not trust these records, so this
        component cannot enable kills of rediscovered candidates after restart.
        """
        self._current()
        if self.objects or self.pending or self.planned or self.sequence:
            raise Rejected("authorization-binding-already-active")
        if type(old_image_id) is not str or OBJECT_ID.fullmatch(old_image_id) is None:
            raise Rejected("authorization-old-image-pin-required")
        if type(candidates) is not list or len(candidates) > 1:
            raise Rejected("authorization-candidate-set")
        objects = {self.intent["old_object_id"]: old_image_id}
        for record in candidates:
            if (type(record) is not dict or type(record.get("object_id")) is not str
                    or record != self.journal.registered.get(record["object_id"])
                    or record["object_id"] in objects):
                raise Rejected("authorization-durable-registration-required")
            objects[record["object_id"]] = record["image_id"]
        self.objects = objects

    def prepare_kill(self, observation, *, deadline):
        self._current()
        timer = self._time(deadline)
        if self.journal.armed is None or not self.journal.forward_revoked:
            raise Rejected("authorization-armed-recovery-required")
        if self.sealed or self.pending or self.planned or self.sequence >= MAX_OPERATIONS:
            raise Rejected("authorization-operation-pending-or-exhausted")
        value = self._observation(observation)
        if value["running"] is not True:
            raise Rejected("authorization-running-object-required")
        operation = {"schema": "host-recovery-daemon-operation-v1", "sequence": self.sequence + 1,
                     "intent_sha256": self.intent_sha256, "boot_id": self.boot,
                     "object_id": value["object_id"], "image_id": value["image_id"],
                     "method": "POST", "uri": self.prefix + value["object_id"] + "/kill?signal=KILL",
                     "deadline": deadline}
        # This hash is a correlation ID, not authority. Identity comes only from
        # the authenticated daemon's TLS User fields on the trusted plugin channel.
        operation["operation_id"] = digest(canonical(operation))
        timer.remaining()
        self.planned = operation
        return copy.deepcopy(operation)

    def _request(self, value, response=False):
        expected = RESPONSE_FIELDS if response else REQUEST_FIELDS
        if type(value) is not dict or set(value) != expected:
            raise Rejected("authorization-protocol-schema")
        if value["User"] != self.principal or value["UserAuthNMethod"] != "TLS":
            raise Rejected("authorization-authenticated-principal-required")
        if (type(value["RequestMethod"]) is not str or type(value["RequestURI"]) is not str
                or value["RequestBody"] not in (None, "") or type(value["RequestHeaders"]) is not dict):
            raise Rejected("authorization-request-schema")
        headers = value["RequestHeaders"]
        if any(type(k) is not str or type(v) is not str for k, v in headers.items()):
            raise Rejected("authorization-header-schema")
        lowered = [k.lower() for k in headers]
        if len(set(lowered)) != len(lowered):
            raise Rejected("authorization-duplicate-header")
        ids = [v for k, v in headers.items() if k.lower() == OPERATION_HEADER.lower()]
        if len(ids) > 1:
            raise Rejected("authorization-duplicate-operation")
        return ids[0] if ids else None

    def _persist(self, kind):
        # Persist intent BEFORE allow, retain all evidence, never delete pending
        # records merely because an HTTP response looked successful.
        value = {**self.pending, "state": kind}
        try:
            self._current()
            name = "daemon-operation-%03d-%s.json" % (self.sequence, kind)
            if name in self.receipts:
                raise Rejected("authorization-operation-record-exists")
            self.journal._write(name, value)
            self.receipts.add(name)
        except Exception:
            self.uncertain = True
            raise

    def request(self, raw):
        """AuthZReq decision. Unknown/malformed operations always return deny."""
        try:
            value = decode(raw)
            operation_id = self._request(value)
            self._current()
            # No list, arbitrary read, archive, attach, events, exec, create,
            # start, restart, rename, update, DELETE or unversioned route grant.
            if value["RequestMethod"] == "GET" and operation_id is None:
                if value["RequestURI"] not in {self.prefix + oid + "/json" for oid in self.objects}:
                    raise Rejected("authorization-read-not-bound")
                if self.boot_id() != self.boot:
                    self.uncertain = True
                    raise Rejected("authorization-boot-discontinuity")
                return reply(True, "bound-inspection-only")
            operation = self.planned
            if (self.sealed or operation is None or self.pending is not None or operation_id != operation["operation_id"]
                    or value["RequestMethod"] != operation["method"] or value["RequestURI"] != operation["uri"]):
                raise Rejected("authorization-operation-not-prepared")
            if self.journal.armed is None or not self.journal.forward_revoked:
                raise Rejected("authorization-armed-recovery-required")
            timer = self._time(operation["deadline"])
            self.pending, self.planned = operation, None
            self.sequence += 1
            self.returned = False
            self._persist("pending")
            timer.remaining()
            return reply(True, "prepared-kill-only")
        except Exception:
            return reply(False, "recovery-authorization-denied")

    def response(self, raw):
        """AuthZRes records return only; it NEVER drains the pending operation."""
        try:
            value = decode(raw)
            operation_id = self._request(value, response=True)
            # Reads do not mutate daemon state or settle any pending mutation.
            if value["RequestMethod"] == "GET" and operation_id is None:
                request = {key: value[key] for key in REQUEST_FIELDS}
                return self.request(canonical(request))
            self._current()
            if (self.pending is None or self.returned or operation_id != self.pending["operation_id"]
                    or value["RequestMethod"] != self.pending["method"]
                    or value["RequestURI"] != self.pending["uri"]
                    or type(value["ResponseStatusCode"]) is not int
                    or not 100 <= value["ResponseStatusCode"] <= 599):
                raise Rejected("authorization-response-not-correlated")
            # Even 2xx is not a stop oracle. Error responses still require an
            # independent reinspection; denied callbacks do not cancel daemon I/O.
            self._persist("returned")
            self.returned = True
            return reply(True, "return-recorded-not-quiescence")
        except Exception:
            return reply(False, "recovery-authorization-denied")

    def reconcile_stopped(self, observation, *, deadline):
        self._current()
        timer = self._time(deadline)
        if self.pending is None or not self.returned:
            raise Rejected("authorization-return-not-observed")
        value = self._observation(observation)
        if value["object_id"] != self.pending["object_id"] or value["running"] is not False:
            raise Rejected("authorization-stop-not-confirmed")
        self._persist("observed-stopped")
        timer.remaining()
        self.pending = None
        self.returned = False

    def seal(self):
        """Irreversibly stop kill admission; outstanding operations still drain."""
        self.sealed = True
        self.planned = None

    def status(self):
        try:
            self._current()
        except Exception:
            self.uncertain = True
        return {"schema": "host-recovery-daemon-fence-status-v1", "starts_denied": True,
                "mutations_sealed": self.sealed,
                "pending_operation": self.pending is not None, "operation_returned": self.returned,
                "pending_drained": self.sealed and self.pending is None and not self.uncertain,
                "uncertain": self.uncertain or self.journal.uncertain or self.journal.reopened,
                "daemon_configuration_verified": False, "internal_restart_fenced": False,
                "installation_start_fence_proven": False, "production_acceptance": False}
