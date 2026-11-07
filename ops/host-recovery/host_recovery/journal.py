"""Durable attempt latch and registered-object ledger for a single installation.

The supervisor holds the installation-directory lock for this object's lifetime.
The original intent is never replaced by progress or a terminal-looking receipt.
There is deliberately no automatic retirement: after supervisor loss, an active
latch always requires recovery reconciliation, even if a terminal file is visible.
A later reviewed settlement protocol must handle archival/new admission. This is
conservative component behavior, not a complete host start-fence implementation.
"""
import copy
import os
import re
import stat
import uuid

from .budget import positive, validate_policy
from .durable import Rejected, atomic_write, canonical, decode, digest, read_file
from .inventory import HASH

OBJECT_ID = re.compile(r"[a-f0-9]{64}\Z")
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def identity(value):
    return type(value) is str and IDENTITY.fullmatch(value) is not None


def validate_intent(value):
    fields = {"schema", "attempt_id", "installation_id", "package_sha256", "manifest_sha256",
              "baseline_sha256", "policy_sha256", "budget", "old_object_id", "candidate_image_id",
              "candidate_ownership_id", "owner"}
    if type(value) is not dict or set(value) != fields or value["schema"] != "host-recovery-intent-v1":
        raise Rejected("intent-schema")
    try:
        if str(uuid.UUID(value["attempt_id"])) != value["attempt_id"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Rejected("attempt-uuid-required") from None
    if not identity(value["installation_id"]) or value["candidate_ownership_id"] != value["attempt_id"]:
        raise Rejected("intent-installation-or-ownership")
    for key in ("package_sha256", "manifest_sha256", "baseline_sha256", "policy_sha256"):
        if type(value[key]) is not str or not HASH.fullmatch(value[key]):
            raise Rejected("intent-pin-required")
    for key in ("old_object_id", "candidate_image_id"):
        if type(value[key]) is not str or not OBJECT_ID.fullmatch(value[key]):
            raise Rejected("immutable-daemon-identity-required")
    owner = value["owner"]
    if type(owner) is not dict or set(owner) != {"installation_id", "attempt_id", "unit", "invocation_id", "boot_id"}:
        raise Rejected("intent-manager-owner")
    if any(not identity(v) for v in owner.values()):
        raise Rejected("intent-manager-identity")
    if owner["attempt_id"] != value["attempt_id"] or owner["installation_id"] != value["installation_id"]:
        raise Rejected("intent-owner-mismatch")
    validate_policy(value["budget"])
    if digest(canonical(value["budget"])) != value["policy_sha256"]:
        raise Rejected("intent-policy-pin-mismatch")


def validate_registration(record, intent):
    """Validate a stopped candidate record, never grant adoption or startup."""
    expected = {"object_id", "image_id", "ownership_id", "running", "restart_policy"}
    if type(record) is not dict or set(record) != expected:
        raise Rejected("daemon-registration-schema")
    object_id = record["object_id"]
    if type(object_id) is not str or not OBJECT_ID.fullmatch(object_id) or object_id == intent["old_object_id"]:
        raise Rejected("daemon-registration-id")
    if (record["image_id"] != intent["candidate_image_id"]
            or record["ownership_id"] != intent["candidate_ownership_id"]
            or record["running"] is not False or record["restart_policy"] != "no"):
        raise Rejected("daemon-registration-not-stopped-and-fenced")


class Journal:
    def __init__(self, fd, *, fault=None):
        st = os.fstat(fd)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise Rejected("private-journal-required")
        self.fd = fd
        self.fault = fault
        self.intent = None
        self.armed = None
        self.registered = {}
        self.terminal = None
        self.uncertain = False
        self.forward_revoked = False
        self.reopened = bool(os.listdir(fd))
        if self.reopened:
            raw, st = read_file(fd, "intent.json")
            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600:
                raise Rejected("private-intent-required")
            value = decode(raw)
            validate_intent(value)
            self.intent = value
            # Progress/object/terminal files are not trusted for startup permission.
            # Daemon ownership must be rediscovered from the immutable intent.

    def _write(self, name, value):
        try:
            return atomic_write(self.fd, name, canonical(value), fault=self.fault,
                                stage_name=".stage-" + name)
        except Exception:
            self.uncertain = True
            raise

    def prepare(self, intent):
        validate_intent(intent)
        if self.intent is not None or os.listdir(self.fd):
            raise Rejected("active-or-ambiguous-intent-exists")
        self._write("intent.json", intent)
        self.intent = copy.deepcopy(intent)

    def arm(self, arm):
        if self.intent is None or self.reopened or self.uncertain or self.armed is not None:
            raise Rejected("new-durable-intent-required")
        if (type(arm) is not dict or set(arm) != {"boot_id", "monotonic"}
                or arm["boot_id"] != self.intent["owner"]["boot_id"] or not positive(arm["monotonic"])):
            raise Rejected("arm-clock-identity")
        self._write("arm.json", {"schema": "host-recovery-arm-v1", "arm": arm,
                                 "intent_sha256": digest(canonical(self.intent))})
        self.armed = dict(arm)

    def register(self, record):
        if self.intent is None or self.armed is None or self.reopened or self.uncertain or self.terminal or self.forward_revoked:
            raise Rejected("registration-not-authorized")
        validate_registration(record, self.intent)
        object_id = record["object_id"]
        if object_id in self.registered:
            if self.registered[object_id] != record:
                raise Rejected("daemon-registration-conflict")
            return
        if self.registered:
            raise Rejected("multiple-candidate-objects")
        self._write("object-" + object_id + ".json", record)
        self.registered[object_id] = copy.deepcopy(record)

    def can_start_candidate(self, object_id):
        return (not self.reopened and not self.uncertain and not self.forward_revoked and self.armed is not None
                and self.terminal is None and object_id in self.registered)

    def revoke_forward(self):
        self.forward_revoked = True

    def finish(self, outcome, receipt):
        if outcome not in ("candidate_verified", "baseline_restored") or type(receipt) is not dict:
            raise Rejected("terminal-schema")
        if self.intent is None or self.terminal == "baseline_restored":
            raise Rejected("terminal-write-not-authorized")
        if outcome == "candidate_verified" and (self.uncertain or self.reopened or self.terminal is not None
                                                or self.armed is None or not self.registered or self.forward_revoked):
            raise Rejected("candidate-terminal-write-not-authorized")
        value = {"schema": "host-recovery-outcome-v1", "attempt_id": self.intent["attempt_id"],
                 "outcome": outcome, "receipt": receipt, "intent_sha256": digest(canonical(self.intent))}
        self._write("recovery-outcome.json" if outcome == "baseline_restored" else "outcome.json", value)
        self.terminal = outcome
        # intent.json deliberately remains; terminal presence alone cannot clear
        # the startup latch or allow a fresh forward attempt after a restart.
