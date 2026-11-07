"""Protected source/policy capture for ExactInputGate, with no rendering authority.

The trusted caller supplies independently authenticated approvals and the mapping
from actual installation/baseline/proposed/frozen-render objects to these handles.
A frozen file's existence/hash does not prove it was rendered from those inputs.
No policy discovery, credential reads, file writes, install or service operations.
"""
import base64
from contextlib import ExitStack
from dataclasses import dataclass
import stat

from .commands import Deadline
from .durable import Rejected, canonical, decode, digest
from .input_gate import MAX_REQUEST
from .installation import DirectoryApproval, open_approved_directory
from .loading import NAME, pin
from .protected_file import ProtectedFile

ROLES = ("config", "compose_source", "frozen_rendered_compose")
MAX_DOCUMENT = 4 * 1024 * 1024
MAX_POLICY = 256 * 1024


@dataclass(frozen=True)
class InputFileApproval:
    root: DirectoryApproval
    name: str
    sha256: str

    def __post_init__(self):
        pin(self.sha256)
        if (not isinstance(self.root, DirectoryApproval) or self.root.mode not in (0o500, 0o700)
                or type(self.name) is not str or NAME.fullmatch(self.name) is None
                or self.name in (".", "..")):
            raise Rejected("input-snapshot-private-file-approval-required")


@dataclass(frozen=True)
class InputPairApproval:
    before: InputFileApproval
    after: InputFileApproval

    def __post_init__(self):
        if not all(isinstance(value, InputFileApproval) for value in (self.before, self.after)):
            raise Rejected("input-snapshot-pair-approval-required")


@dataclass(frozen=True)
class SnapshotApproval:
    intent_sha256: str
    policy: InputFileApproval
    config: InputPairApproval
    compose_source: InputPairApproval
    frozen_rendered_compose: InputPairApproval

    def __post_init__(self):
        pin(self.intent_sha256)
        if (not isinstance(self.policy, InputFileApproval)
                or not all(isinstance(getattr(self, role), InputPairApproval) for role in ROLES)):
            raise Rejected("input-snapshot-explicit-approval-required")


class ProtectedInputSnapshot:
    """Fresh capture of seven pinned files at every call, under one external lock.

    check() must strictly confirm current owner/lock and complete writer exclusion.
    Root identity and private-file checks are additional necessary conditions, not
    a substitute for that boundary. All retained files are rehashed and all paths
    revalidated before returning; no captured request or receipt is cached.
    """
    def __init__(self, *, approval, check, clock):
        if (not isinstance(approval, SnapshotApproval)
                or not callable(check) or not callable(clock)):
            raise Rejected("input-snapshot-explicit-boundary-required")
        self.approval, self.check, self.clock = approval, check, clock

    def __call__(self, intent, *, deadline):
        try:
            remaining = Deadline(self.clock, deadline).remaining
            def current():
                remaining()
                if self.check() is not True:
                    raise Rejected("input-snapshot-boundary-unconfirmed")
                remaining()

            approval = self.approval
            if digest(canonical(intent)) != approval.intent_sha256:
                raise Rejected("input-snapshot-intent-mismatch")
            current()
            specs = {"policy": approval.policy}
            for role in ROLES:
                for side in ("before", "after"):
                    specs[role + "-" + side] = getattr(getattr(approval, role), side)
            with ExitStack() as stack:
                roots, files, captured, seen = {}, {}, {}, set()
                for key, spec in specs.items():
                    current()
                    if spec.root not in roots:
                        roots[spec.root] = stack.enter_context(open_approved_directory(spec.root))
                    source = ProtectedFile(roots[spec.root], spec.name, uid=spec.root.uid, gid=spec.root.gid,
                                           limit=MAX_POLICY if key == "policy" else MAX_DOCUMENT, current=current)
                    stack.callback(source.close)
                    identity = (source.info.st_dev, source.info.st_ino)
                    if identity in seen or stat.S_IMODE(source.info.st_mode) not in (0o400, 0o600):
                        raise Rejected("input-snapshot-distinct-private-files-required")
                    seen.add(identity)
                    files[key] = source
                for key, source in files.items():
                    raw = b"".join(source.blocks())
                    if digest(raw) != specs[key].sha256:
                        raise Rejected("input-snapshot-byte-pin-mismatch")
                    captured[key] = raw
                policy = decode(captured["policy"])
                if (set(policy) != {"schema", *ROLES} or policy["schema"] != "host-recovery-input-policy-v1"
                        or any(type(policy[role]) is not list or len(policy[role]) > 256 for role in ROLES)):
                    raise Rejected("input-snapshot-policy-schema")
                request = {"schema": "host-recovery-input-request-v1"}
                for role in ROLES:
                    request[role] = {"changes": policy[role]}
                    for side in ("before", "after"):
                        key = role + "-" + side
                        request[role][side] = base64.b64encode(captured[key]).decode("ascii")
                        request[role][side + "_sha256"] = specs[key].sha256
                raw = canonical(request)
                if len(raw) > MAX_REQUEST:
                    raise Rejected("input-snapshot-request-limit")
                # Re-read the same descriptors, not just stat: timestamp equality
                # cannot prove that previously captured bytes are still current.
                for key, source in files.items():
                    if source.checksum() != specs[key].sha256:
                        raise Rejected("input-snapshot-bytes-changed")
                for source in files.values():
                    source.validate()
                current()
            current()
            return raw
        except Exception:
            raise Rejected("input-snapshot-unconfirmed") from None
