"""Narrow, explicit Docker object observation and fail-closed quiescence.

No create/start/update/restart/remove operation is exposed. This adapter does not
install a Docker authorization broker or prove its existence. Quiescence requires
a separate start-fence acknowledgment covering pending daemon operations, Compose
and all cooperating writers; restart=no alone does not close those paths. A CLI
helper's death is never interpreted as a container stop or a canceled daemon job.
"""
import os
import re
import time

from .commands import Deadline
from .durable import Rejected, decode
from .journal import OBJECT_ID, identity, validate_intent

INSTALLATION_LABEL = "cpa.recovery.installation"
ATTEMPT_LABEL = "cpa.recovery.attempt"
MAX_CANDIDATES = 16
# Project only state needed by the guard. Never emit environment, mount paths,
# credentials, request bodies, daemon errors or unrelated labels in receipts.
INSPECT_FORMAT = ('{"object_id":{{json .Id}},"image_id":{{json .Image}},'
                  '"running":{{json .State.Running}},"paused":{{json .State.Paused}},'
                  '"restarting":{{json .State.Restarting}},"dead":{{json .State.Dead}},'
                  '"status":{{json .State.Status}},'
                  '"restart_policy":{{json .HostConfig.RestartPolicy.Name}},'
                  '"restart_retries":{{json .HostConfig.RestartPolicy.MaximumRetryCount}},'
                  '"auto_remove":{{json .HostConfig.AutoRemove}},'
                  '"installation_id":{{json (index .Config.Labels "' + INSTALLATION_LABEL + '")}},'
                  '"ownership_id":{{json (index .Config.Labels "' + ATTEMPT_LABEL + '")}}}')
FIELDS = frozenset(("object_id", "image_id", "running", "paused", "restarting", "dead", "status",
                    "restart_policy", "restart_retries", "auto_remove", "installation_id", "ownership_id"))


class DockerObjects:
    def __init__(self, *, docker, endpoint, commands, intent, old_image_id, start_fence, clock=time.monotonic):
        validate_intent(intent)
        if type(docker) is not str or not os.path.isabs(docker):
            raise Rejected("explicit-docker-executable-required")
        # No ambient DOCKER_HOST/context or network endpoint. Any eventual socket
        # access must be supplied by a separately authorized narrow host boundary.
        if (type(endpoint) is not str or not endpoint.startswith("unix:///")
                or re.fullmatch(r"unix:///[A-Za-z0-9_.\/-]+", endpoint) is None
                or any(part in (".", "..", "") for part in endpoint[8:].split("/"))):
            raise Rejected("explicit-local-daemon-endpoint-required")
        if type(old_image_id) is not str or OBJECT_ID.fullmatch(old_image_id) is None:
            raise Rejected("immutable-old-image-required")
        self.clock = clock
        self.prefix = (docker, "--host=" + endpoint)
        self.commands = commands
        self.installation_id = intent["installation_id"]
        self.attempt_id = intent["attempt_id"]
        self.old_object_id = intent["old_object_id"]
        self.old_image_id = old_image_id
        self.candidate_image_id = intent["candidate_image_id"]
        self.start_fence = start_fence
        self._quiescence_binding = None
        self._quiescing = self._quiescence_failed = False

    def _quiescence_bound(self):
        values = (self.prefix, self.installation_id, self.attempt_id, self.old_object_id,
                  self.old_image_id, self.candidate_image_id)
        readers = (self.commands, self.clock, self.start_fence)
        if self._quiescence_binding is None:
            self._quiescence_binding = values, readers
        original, retained = self._quiescence_binding
        if (self._quiescence_failed or values != original
                or any(actual is not expected for actual, expected in zip(readers, retained))):
            raise Rejected("daemon-quiescence-boundaries-changed")

    def _quiescence_clock(self):
        self._quiescence_bound()
        now = self.clock()
        self._quiescence_bound()
        return now

    def _fenced(self):
        if self.start_fence() is not True:
            raise Rejected("daemon-start-and-pending-operation-fence-unconfirmed")

    def _run(self, args, deadline):
        if self._quiescing:
            self._quiescence_bound()
        raw = self.commands.run(self.prefix + args, deadline=deadline)
        if self._quiescing:
            self._quiescence_bound()
        return raw

    def inspect(self, object_id, *, deadline):
        timer = Deadline(self.clock, deadline)
        timer.remaining()
        if type(object_id) is not str or OBJECT_ID.fullmatch(object_id) is None:
            raise Rejected("full-daemon-object-id-required")
        raw = self._run(("container", "inspect", "--format=" + INSPECT_FORMAT, object_id), deadline)
        value = decode(raw)
        if set(value) != FIELDS or value["object_id"] != object_id:
            raise Rejected("daemon-observation-schema-or-id")
        image = value["image_id"]
        if type(image) is not str or not image.startswith("sha256:") or OBJECT_ID.fullmatch(image[7:]) is None:
            raise Rejected("daemon-image-identity")
        value["image_id"] = image[7:]
        for key in ("running", "paused", "restarting", "dead", "auto_remove"):
            if type(value[key]) is not bool:
                raise Rejected("daemon-state-boolean-required")
        if (value["restart_policy"] != "no" or type(value["restart_retries"]) is not int
                or value["restart_retries"] != 0 or value["auto_remove"] is not False):
            raise Rejected("daemon-restart-or-removal-not-fenced")
        if value["dead"] or value["paused"] or value["restarting"]:
            raise Rejected("daemon-state-uncertain")
        if value["running"]:
            if value["status"] != "running":
                raise Rejected("daemon-state-conflict")
        elif value["status"] not in ("created", "exited"):
            raise Rejected("daemon-state-conflict")
        for key in ("installation_id", "ownership_id"):
            if value[key] not in (None, "") and not identity(value[key]):
                raise Rejected("daemon-ownership-schema")
        if object_id == self.old_object_id:
            if value["image_id"] != self.old_image_id:
                raise Rejected("old-daemon-image-mismatch")
        elif (value["installation_id"] != self.installation_id or value["ownership_id"] != self.attempt_id
              or value["image_id"] != self.candidate_image_id):
            raise Rejected("candidate-daemon-ownership-or-image-mismatch")
        timer.remaining()
        return value

    def _owned_ids(self, deadline):
        raw = self._run(("container", "ls", "--all", "--no-trunc",
                         "--filter=label=" + INSTALLATION_LABEL + "=" + self.installation_id,
                         "--filter=label=" + ATTEMPT_LABEL + "=" + self.attempt_id, "--format={{.ID}}"), deadline)
        try:
            rows = raw.decode("ascii").splitlines()
        except (UnicodeError, AttributeError):
            raise Rejected("daemon-ownership-list-encoding") from None
        if (len(rows) > MAX_CANDIDATES or any(OBJECT_ID.fullmatch(row) is None for row in rows)
                or len(set(rows)) != len(rows) or self.old_object_id in rows):
            raise Rejected("daemon-ownership-list-ambiguous")
        return sorted(rows)

    def owned_candidates(self, *, deadline):
        timer = Deadline(self.clock, deadline)
        timer.remaining()
        before = self._owned_ids(deadline)
        values = [self.inspect(object_id, deadline=deadline) for object_id in before]
        if before != self._owned_ids(deadline):
            raise Rejected("daemon-ownership-changed-during-inspection")
        timer.remaining()
        return [{key: value[key] for key in ("object_id", "image_id", "ownership_id", "running", "restart_policy")}
                for value in values]

    def quiesce(self, *, deadline):
        entered = False
        try:
            if self._quiescing or self._quiescence_failed:
                raise Rejected("daemon-quiescence-unavailable")
            self._quiescing = entered = True
            timer = Deadline(self._quiescence_clock, deadline)
            timer.remaining()
            self._fenced()
            timer.remaining()
            owned = self._owned_ids(deadline)
            all_ids = [self.old_object_id] + owned
            # Inspect every object before any stop, so an ownership/policy mismatch
            # cannot cause an unrelated object to be killed as a guessed candidate.
            before = [self.inspect(object_id, deadline=deadline) for object_id in all_ids]
            for value in before:
                if value["running"]:
                    self._run(("container", "kill", "--signal=KILL", value["object_id"]), deadline)
            after = [self.inspect(object_id, deadline=deadline) for object_id in all_ids]
            if owned != self._owned_ids(deadline):
                raise Rejected("daemon-ownership-changed-during-quiescence")
            self._fenced()
            timer.remaining()
            return all(value["running"] is False for value in after)
        except BaseException:
            self._quiescence_failed = True
            raise
        finally:
            if entered:
                self._quiescing = False
