"""Protected closed interpolation inputs around the existing seven-file capture.

No .env discovery, ambient environment, tool lookup, file writes or service I/O.
The trusted caller still authenticates every pin/role and retains the installation
lock and writer fence. Captures cannot grant approval or a service start.
"""
from contextlib import ExitStack
import re
import stat

from .commands import Deadline
from .durable import Rejected, canonical, decode, digest
from .input_gate import MAX_REQUEST
from .input_snapshot import InputPairApproval, ProtectedInputSnapshot, ROLES
from .installation import open_approved_directory
from .protected_file import ProtectedFile

RENDERER = "compose-go/v2@v2.16.2:single-file-model-v1"
MAX_ENVIRONMENT = 64 * 1024
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}\Z", re.ASCII)
VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z", re.ASCII)
META_PROFILE = ("meta@c54c8c86989032f269ebfb49e95c6fb16fb9f2db:"
                "config.go@4665020ba0b2688dda79578f3f8717878a50212c8fd092f856c728c563ddbfd8:strict-replay-v1")


class ProtectedComposeSnapshot:
    """Fresh nine-file request; retained environment descriptors enclose base capture.

    The helper re-renders both sources with these closed JSON string maps, then
    compares to the corresponding independently pinned frozen models. Frozen
    outputs must use this renderer version, not an arbitrary Docker CLI version.
    """
    def _envelope(self, inputs, captured):
        return {"schema": "host-recovery-compose-request-v1", "renderer": RENDERER,
                "project_name": self.project_name, "inputs": decode(inputs),
                "before_environment": captured["before"], "after_environment": captured["after"]}

    def __init__(self, *, snapshot, environment, project_name, check, clock):
        if (not isinstance(snapshot, ProtectedInputSnapshot) or not isinstance(environment, InputPairApproval)
                or type(project_name) is not str or PROJECT.fullmatch(project_name) is None
                or not callable(check) or not callable(clock)):
            raise Rejected("compose-snapshot-explicit-boundary-required")
        specs = [snapshot.approval.policy, environment.before, environment.after]
        for role in ROLES:
            specs.extend((getattr(snapshot.approval, role).before, getattr(snapshot.approval, role).after))
        identities = {(spec.root.device, spec.root.inode, spec.name) for spec in specs}
        if len(identities) != len(specs):
            raise Rejected("compose-snapshot-distinct-files-required")
        self.snapshot, self.environment, self.project_name = snapshot, environment, project_name
        self.check, self.clock = check, clock

    def __call__(self, intent, *, deadline):
        try:
            remaining = Deadline(self.clock, deadline).remaining
            def current():
                remaining()
                if self.check() is not True:
                    raise Rejected("compose-snapshot-boundary-unconfirmed")
                remaining()

            current()
            with ExitStack() as stack:
                roots, files, captured, seen = {}, {}, {}, set()
                for side in ("before", "after"):
                    spec = getattr(self.environment, side)
                    if spec.root not in roots:
                        roots[spec.root] = stack.enter_context(open_approved_directory(spec.root))
                    source = ProtectedFile(roots[spec.root], spec.name, uid=spec.root.uid, gid=spec.root.gid,
                                           limit=MAX_ENVIRONMENT, current=current)
                    stack.callback(source.close)
                    identity = (source.info.st_dev, source.info.st_ino)
                    if identity in seen or stat.S_IMODE(source.info.st_mode) not in (0o400, 0o600):
                        raise Rejected("compose-snapshot-private-files-required")
                    seen.add(identity)
                    files[side] = source
                    raw = b"".join(source.blocks())
                    if digest(raw) != spec.sha256:
                        raise Rejected("compose-snapshot-pin-mismatch")
                    values = decode(raw)
                    if (len(values) > 256 or any(VARIABLE.fullmatch(key) is None or type(value) is not str
                            or "\0" in value or len(value.encode("utf-8")) > 4096 for key, value in values.items())
                            or sum(len(key) + len(value.encode("utf-8")) for key, value in values.items()) > MAX_ENVIRONMENT):
                        raise Rejected("compose-snapshot-environment-invalid")
                    captured[side] = values
                inputs = self.snapshot(intent, deadline=deadline)
                result = canonical(self._envelope(inputs, captured))
                if len(result) > MAX_REQUEST:
                    raise Rejected("compose-snapshot-request-limit")
                for side, source in files.items():
                    if source.checksum() != getattr(self.environment, side).sha256:
                        raise Rejected("compose-snapshot-environment-changed")
                    source.validate()
                # Recapture under the same writer exclusion: base inputs may not
                # change while the interpolation envelope is being serialized.
                if self.snapshot(intent, deadline=deadline) != inputs:
                    raise Rejected("compose-snapshot-source-changed")
                for side, source in files.items():
                    if source.checksum() != getattr(self.environment, side).sha256:
                        raise Rejected("compose-snapshot-environment-changed")
                    source.validate()
                current()
            current()
            return result
        except Exception:
            raise Rejected("compose-snapshot-unconfirmed") from None


class ProtectedMetaSnapshot(ProtectedComposeSnapshot):
    """Same retained nine-file capture with a source-pinned Meta shape profile.

    This changes only the helper envelope. Authentication of policy, installation
    roles and actual producer artifact remains external; no plugin is executed.
    """
    def _envelope(self, inputs, captured):
        return {"schema": "host-recovery-meta-input-request-v1", "producer_config": META_PROFILE,
                "inputs": super()._envelope(inputs, captured)}
