"""Read-only approved-content and original recovery-request loading.

Trust starts at independently approved pins and already-open installation-owned
root descriptors. Neither an index found beside its files nor a self-consistent
journal authenticates approval. The caller obtains these handles/pins through the
reviewed installation boundary, excludes cooperating writers and retains the
installation lock. Hostile root/same-uid actors are outside this boundary.

No extraction, import, execution, mutation, archive attestation or start grant is
provided. Returned content is captured bytes, never a path reopened for execution.
"""
from dataclasses import dataclass
import os
import re
import stat
from types import MappingProxyType

from .dispatch import validate_request
from .durable import Rejected, canonical, decode, digest, read_file, signature
from .inventory import HASH
from .jobs import RecoveryJobBinding
from .journal import identity, validate_intent
from .supervisor import validate_owner

INDEX = "content-index.json"
MAX_ENTRIES = 128
MAX_TOTAL_BYTES = 16 * 1024 * 1024
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
REVISION = re.compile(r"[a-f0-9]{40}\Z")
MODES = {0o400, 0o444, 0o500, 0o555, 0o600, 0o644, 0o700, 0o755}


def pin(value):
    if type(value) is not str or HASH.fullmatch(value) is None:
        raise Rejected("loading-pin-required")


def owner(uid, gid):
    if any(type(value) is not int or not 0 <= value <= 2147483647 for value in (uid, gid)):
        raise Rejected("loading-numeric-owner-required")


def relative(path):
    if (type(path) is not str or len(path) > 512 or len(path.split("/")) > 8
            or any(NAME.fullmatch(part) is None for part in path.split("/"))):
        raise Rejected("loading-relative-path-required")
    return path


def metadata(fd, *, uid, gid, directory=False, private=False):
    st = os.fstat(fd)
    mode = stat.S_IMODE(st.st_mode)
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    modes = ({0o700} if private else {0o500, 0o555, 0o700, 0o755}) if directory else MODES
    if (not kind(st.st_mode) or (st.st_uid, st.st_gid) != (uid, gid)
            or mode not in modes
            or os.listxattr(fd)):
        raise Rejected("loading-owned-protected-entry-required")
    return st


def names(fd):
    result = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(result) >= MAX_ENTRIES:
                raise Rejected("loading-entry-limit")
            result.append(entry.name)
    return sorted(result)


def inventory(fd, *, uid, gid):
    """Bounded descriptor-relative walk; retain signatures for a final rewalk."""
    device = os.fstat(fd).st_dev
    result = {}

    def walk(parent, prefix):
        before = metadata(parent, uid=uid, gid=gid, directory=True)
        if before.st_dev != device:
            raise Rejected("loading-cross-device-entry")
        result[prefix] = ("directory", signature(before))
        children = names(parent)
        for name in children:
            path = relative(prefix + "/" + name if prefix else name)
            if len(result) >= MAX_ENTRIES:
                raise Rejected("loading-entry-limit")
            st = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                try:
                    if signature(st) != signature(os.fstat(child)):
                        raise Rejected("loading-entry-changed")
                    walk(child, path)
                finally:
                    os.close(child)
            elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                if ((st.st_uid, st.st_gid) != (uid, gid) or stat.S_IMODE(st.st_mode) not in MODES
                        or st.st_dev != device):
                    raise Rejected("loading-owned-protected-entry-required")
                result[path] = ("file", signature(st))
            else:
                raise Rejected("loading-regular-single-link-entry-required")
        if children != names(parent) or signature(before) != signature(os.fstat(parent)):
            raise Rejected("loading-tree-changed")

    walk(fd, "")
    return result


def read_relative(fd, path):
    parts = relative(path).split("/")
    parent = os.dup(fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
        return read_file(parent, parts[-1])
    finally:
        os.close(parent)


@dataclass(frozen=True)
class ContentApproval:
    index_sha256: str
    source_revision: str
    uid: int
    gid: int

    def __post_init__(self):
        pin(self.index_sha256)
        owner(self.uid, self.gid)
        if type(self.source_revision) is not str or REVISION.fullmatch(self.source_revision) is None:
            raise Rejected("loading-source-revision-required")


@dataclass(frozen=True)
class ContentSnapshot:
    approval: ContentApproval
    files: object

    def json(self, path):
        return decode(self.files[relative(path)])


def load_content(fd, approval):
    """Verify exact installed content against an external approved index digest.

    The archive hash, index approval, interpreter and service installation remain
    separate provenance/operational prerequisites. This function cannot bootstrap
    trust in itself or safely execute mutable installed paths after validation.
    """
    if not isinstance(approval, ContentApproval):
        raise Rejected("loading-content-approval-required")
    before = inventory(fd, uid=approval.uid, gid=approval.gid)
    raw, index_st = read_file(fd, INDEX)
    if digest(raw) != approval.index_sha256:
        raise Rejected("loading-index-pin-mismatch")
    value = decode(raw)
    if (set(value) != {"schema", "source_revision", "files"}
            or value["schema"] != "host-recovery-content-v1"
            or value["source_revision"] != approval.source_revision
            or type(value["files"]) is not list or not 1 <= len(value["files"]) < MAX_ENTRIES):
        raise Rejected("loading-content-schema")
    expected, directories, content, total = {}, {""}, {}, len(raw)
    for entry in value["files"]:
        if type(entry) is not dict or set(entry) != {"path", "sha256", "mode"}:
            raise Rejected("loading-content-entry-schema")
        path = relative(entry["path"])
        pin(entry["sha256"])
        if (path == INDEX or path in expected or type(entry["mode"]) is not int or entry["mode"] not in MODES):
            raise Rejected("loading-content-entry-conflict")
        expected[path] = entry
        parts = path.split("/")
        directories.update("/".join(parts[:i]) for i in range(1, len(parts)))
    if (set(before) != set(expected) | directories | {INDEX}
            or any(before[path][0] != "directory" for path in directories)
            or any(before[path][0] != "file" for path in set(expected) | {INDEX})):
        raise Rejected("loading-content-inventory-mismatch")
    if signature(index_st) != before[INDEX][1]:
        raise Rejected("loading-index-changed")
    for path, entry in expected.items():
        raw, st = read_relative(fd, path)
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise Rejected("loading-total-byte-limit")
        if (signature(st) != before[path][1] or stat.S_IMODE(st.st_mode) != entry["mode"]
                or digest(raw) != entry["sha256"]):
            raise Rejected("loading-content-pin-mismatch")
        content[path] = raw
    if before != inventory(fd, uid=approval.uid, gid=approval.gid):
        raise Rejected("loading-content-changed")
    return ContentSnapshot(approval, MappingProxyType(content))


@dataclass(frozen=True)
class RecoveryApproval:
    intent_sha256: str
    package_sha256: str
    manifest_sha256: str
    baseline_sha256: str
    policy_sha256: str
    installation_id: str
    attempt_id: str
    uid: int
    gid: int

    def __post_init__(self):
        for key in ("intent_sha256", "package_sha256", "manifest_sha256", "baseline_sha256", "policy_sha256"):
            pin(getattr(self, key))
        owner(self.uid, self.gid)
        if not identity(self.installation_id) or not identity(self.attempt_id):
            raise Rejected("loading-attempt-identity-required")


@dataclass(frozen=True)
class RecoveryInputs:
    intent_raw: bytes
    request_raw: bytes
    arm_raw: bytes

    @property
    def intent(self):
        return decode(self.intent_raw)

    @property
    def request(self):
        return decode(self.request_raw)


def load_recovery(fd, *, approval, binding, supervisor_owner, boot_id, now):
    """Read fixed journal names under the retained lock; never retire the latch.

    Progress, outcomes and prior claims cannot renew a deadline or supply approval.
    Same-boot requests only: reboot/expired continuations need their own protocol.
    This validates input correspondence, not baseline bytes or a complete fence.
    """
    if not isinstance(approval, RecoveryApproval) or not isinstance(binding, RecoveryJobBinding):
        raise Rejected("loading-recovery-approval-required")
    validate_owner(supervisor_owner)
    before = metadata(fd, uid=approval.uid, gid=approval.gid, directory=True, private=True)
    if any(name.startswith((".stage-", ".recovery-stage-")) for name in names(fd)):
        raise Rejected("loading-ambiguous-staging-record")
    records, signatures = {}, {}
    for name in ("intent.json", "arm.json", "reconcile-request.json"):
        raw, st = read_file(fd, name)
        if ((st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (approval.uid, approval.gid, 0o600)
                or st.st_dev != before.st_dev):
            raise Rejected("loading-private-record-required")
        records[name], signatures[name] = raw, signature(st)
    intent = decode(records["intent.json"])
    validate_intent(intent)
    if digest(canonical(intent)) != approval.intent_sha256:
        raise Rejected("loading-intent-pin-mismatch")
    for key in ("package_sha256", "manifest_sha256", "baseline_sha256", "policy_sha256", "installation_id", "attempt_id"):
        if intent[key] != getattr(approval, key):
            raise Rejected("loading-intent-approval-mismatch")
    arm = decode(records["arm.json"])
    request = decode(records["reconcile-request.json"])
    validate_request(request, binding, boot_id, now)
    if (set(arm) != {"schema", "arm", "intent_sha256"} or arm["schema"] != "host-recovery-arm-v1"
            or arm["intent_sha256"] != approval.intent_sha256
            or request["intent_sha256"] != approval.intent_sha256
            or request["owner"] != supervisor_owner or request["attempt_id"] != intent["attempt_id"]
            or request["owner"]["installation_id"] != intent["installation_id"]
            or request["owner"]["boot_id"] != intent["owner"]["boot_id"]
            or canonical(arm["arm"]) != canonical(request["original_arm"])):
        raise Rejected("loading-original-request-unbound")
    for name, raw in records.items():
        again, st = read_file(fd, name)
        if again != raw or signature(st) != signatures[name]:
            raise Rejected("loading-record-changed")
    if signature(before) != signature(metadata(fd, uid=approval.uid, gid=approval.gid, directory=True, private=True)):
        raise Rejected("loading-journal-changed")
    return RecoveryInputs(canonical(intent), canonical(request), canonical(arm))
