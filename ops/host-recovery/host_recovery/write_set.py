"""Pinned multi-root filesystem recovery; no service or semantic start oracle.

The caller retains the existing installation lock. Independent approval of all
pins/paths and complete manager/daemon/writer quiescence remain prerequisites.
The strict check callback must revalidate that boundary within the supplied
original phase deadline. A matching Boolean in a test is not its implementation.
"""
from contextlib import ExitStack, contextmanager
import copy
import os
import stat

from .budget import positive
from .commands import Deadline
from .durable import Rejected, canonical, decode, digest, read_file
from .installation import DirectoryApproval, open_approved_directory
from .inventory import HASH, MAX_ENTRIES, MAX_TREE_BYTES, load_baseline, relative_path, selected_auths, snapshot
from .journal import identity, validate_intent
from .restore import inspect_restore, restore_tree, stages, validate_plan

MAX_ROOTS = 16


def separate_paths(approvals):
    for index, first in enumerate(approvals):
        if not isinstance(first, DirectoryApproval):
            raise Rejected("write-set-directory-approval-required")
        for second in approvals[:index]:
            if ((first.device, first.inode) == (second.device, second.inode)
                    or first.path == second.path or first.path.startswith(second.path + "/")
                    or second.path.startswith(first.path + "/")):
                raise Rejected("write-set-separate-roots-required")


def read_manifest(fd, pin):
    raw, info = read_file(fd, "manifest.json")
    if ((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            != (os.geteuid(), os.getegid(), 0o600) or digest(raw) != pin):
        raise Rejected("write-set-manifest-pin-or-owner")
    value = decode(raw)
    if (set(value) != {"schema", "roots", "auth"} or value["schema"] != "host-recovery-write-set-v1"
            or type(value["roots"]) is not dict or not 1 <= len(value["roots"]) <= MAX_ROOTS):
        raise Rejected("write-set-manifest-schema")
    for name, row in value["roots"].items():
        if (not identity(name) or type(row) is not dict or set(row) != {"baseline_sha256", "additions"}
                or type(row["baseline_sha256"]) is not str or not HASH.fullmatch(row["baseline_sha256"])):
            raise Rejected("write-set-root-schema")
    auth = value["auth"]
    if (type(auth) is not dict or set(auth) != {"root", "selected", "expected_type"}
            or type(auth["root"]) is not str or auth["root"] not in value["roots"]):
        raise Rejected("write-set-auth-schema")
    if set(os.listdir(fd)) != {"manifest.json", *value["roots"]}:
        raise Rejected("write-set-baseline-inventory")
    return value


@contextmanager
def open_write_set(*, baseline, roots, baseline_sha256, check, clock):
    """Open all independently approved paths; never create/relax paths or lock anew.

    The restricted aggregate manifest binds each per-root baseline and candidate
    additions, plus the exact-nine selection. It is integrity-pinned by the
    original intent, not authenticated merely because its own hashes agree.
    """
    if (not isinstance(baseline, DirectoryApproval) or baseline.mode != 0o700
            or (baseline.uid, baseline.gid) != (os.geteuid(), os.getegid())
            or type(roots) is not dict or not 1 <= len(roots) <= MAX_ROOTS
            or any(not identity(name) for name in roots)
            or type(baseline_sha256) is not str or not HASH.fullmatch(baseline_sha256)
            or not callable(check) or not callable(clock)):
        raise Rejected("write-set-explicit-inputs-required")
    roots = dict(roots)
    separate_paths([baseline, *roots.values()])
    with ExitStack() as stack:
        backup = stack.enter_context(open_approved_directory(baseline))
        handles = {name: stack.enter_context(open_approved_directory(approval)) for name, approval in roots.items()}
        recovery = WriteSetRecovery(backup, handles, baseline_sha256, check, clock)
        try:
            yield recovery
        finally:
            recovery.closed = True


@contextmanager
def open_write_set_verifier(**kwargs):
    """Open fresh approved handles without restoring or trusting a restorer flag.

    This view exposes observation only. Separate observer provisioning/identity and
    filesystem permissions are still required; a Python facade is not a sandbox.
    The existing installation lock and complete external fence remain mandatory.
    """
    with open_write_set(**kwargs) as reader:
        yield WriteSetVerifier(reader)


class WriteSetVerifier:
    """Fresh complete-file observations, not semantic, fence or start authority."""
    def __init__(self, reader):
        if not isinstance(reader, WriteSetRecovery) or reader.restored:
            raise Rejected("write-set-fresh-verifier-required")
        self._reader = reader
        self._failed = False

    def _observe(self, intent, deadline, capture, validate=None):
        try:
            if self._failed:
                raise Rejected("write-set-verifier-unavailable")
            original = canonical(intent)
            value = decode(original)
            reader = self._reader
            reader._bound(value, deadline)
            result = capture(reader, value)
            # Fence/clock/descriptor callbacks are external boundaries. Do not
            # accept a caller's changed intent after reading the original files.
            reader._current(deadline)
            if (self._reader is not reader or self._failed or reader.failed
                    or canonical(intent) != original or reader.intent_sha256 != digest(original)):
                raise Rejected("write-set-verifier-original-intent-changed")
            if validate is not None:
                validate(reader)
            return result
        except BaseException:
            self._failed = self._reader.failed = True
            raise

    def verify_files(self, intent, *, deadline):
        def capture(reader, value):
            reader._verify_all(deadline)
            reader._verify_all(deadline)
            return {"schema": "host-recovery-write-set-observed-v1", "baseline_sha256": reader.pin,
                    "roots": len(reader.roots), "entries": sum(len(tree["entries"]) for tree, _ in reader.baselines.values()),
                    "selected": 9, "disabled": 7, "enabled": 2, "filesystem_verified": True,
                    "semantic_start_oracle_proven": False, "start_permission": False, "production_acceptance": False}
        return self._observe(intent, deadline, capture)

    def capture_files(self, intent, roles, *, deadline):
        return self._observe(intent, deadline, lambda reader, value: reader._capture_files(value, roles, deadline=deadline))

    def verify_bind_sources(self, intent, mounts, *, deadline):
        """Match restricted bind sources to approved roots in the caller namespace.

        The deployment gate must independently pin the complete mount projection.
        This does not inspect a container mount namespace or exclude other writers.
        File binds, volumes, subpaths and overlapping destinations are unsupported.
        """
        saved = copy.deepcopy(mounts)
        original_reader = self._reader
        roots = dict(original_reader.roots)
        approvals = {name: handle.approval for name, handle in roots.items()}

        def validate(reader):
            if (mounts != saved or reader is not original_reader or set(reader.roots) != set(roots)
                    or any(reader.roots[name] is not handle or handle.approval != approvals[name]
                           for name, handle in roots.items())):
                raise Rejected("write-set-bind-source-observer-changed")

        def capture(reader, value):
            validate(reader)
            if type(saved) is not list or not 1 <= len(saved) <= MAX_ROOTS:
                raise Rejected("write-set-bind-mount-inventory-required")
            sources = {approval.path for approval in approvals.values()}
            destinations, seen = [], set()
            for mount in saved:
                if (type(mount) is not dict
                        or set(mount) != {"Type", "Source", "Destination", "Mode", "RW", "Propagation"}
                        or mount["Type"] != "bind" or mount["RW"] is not False
                        or mount["Mode"] != "ro" or mount["Propagation"] != "rprivate"
                        or type(mount["Source"]) is not str or mount["Source"] not in sources
                        or mount["Source"] in seen):
                    raise Rejected("write-set-approved-private-readonly-bind-required")
                path = mount["Destination"]
                if (type(path) is not str or not path.startswith("/") or len(path) > 4096
                        or "\0" in path or any(part in ("", ".", "..") for part in path[1:].split("/"))
                        or any(path == other or path.startswith(other + "/") or other.startswith(path + "/")
                               for other in destinations)):
                    raise Rejected("write-set-distinct-bind-destination-required")
                destinations.append(path)
                seen.add(mount["Source"])
            reader._verify_all(deadline)
            reader._verify_all(deadline)
            return {"schema": "host-recovery-bind-source-result-v1", "baseline_sha256": reader.pin,
                    "mounts": len(saved), "bind_source_baseline_verified": True,
                    "container_namespace_verified": False, "start_authorized": False}
        return self._observe(intent, deadline, capture, validate)


class WriteSetRecovery:
    """Restore files only; receipts deliberately cannot satisfy the start oracle.

    A failure poisons this instance. A fresh context may reconcile deterministic
    restore staging from a partial prior attempt; no in-memory progress is trusted.
    No outcome, request/claim, latch retirement or service start is written here.
    """
    def __init__(self, backup, roots, pin, check, clock):
        self.backup, self.roots, self.pin = backup, roots, pin
        self.check, self.clock = check, clock
        self.closed, self.failed, self.restored = False, False, False
        self.manifest, self.baselines = None, None
        self.last_clock = None
        self.intent_sha256 = None

    def _now(self):
        now = self.clock()
        if not positive(now) or self.last_clock is not None and now < self.last_clock:
            raise Rejected("write-set-clock-discontinuity")
        self.last_clock = now
        return now

    def _current(self, deadline):
        if self.closed or self.failed:
            raise Rejected("write-set-context-unavailable")
        timer = Deadline(self._now, deadline)
        timer.remaining()
        if self.check(deadline=deadline) is not True:
            raise Rejected("write-set-quiescence-unconfirmed")
        self.backup.validate()
        for handle in self.roots.values():
            handle.validate()
        timer.remaining()

    def _load(self, deadline):
        self._current(deadline)
        value = read_manifest(self.backup.fd, self.pin)
        if set(value["roots"]) != set(self.roots):
            raise Rejected("write-set-root-inventory-mismatch")
        baselines, entries, total = {}, 0, 0
        for name, row in sorted(value["roots"].items()):
            self._current(deadline)
            root = self.roots[name].approval
            before = os.stat(name, dir_fd=self.backup.fd, follow_symlinks=False)
            if (not stat.S_ISDIR(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o700
                    or (before.st_uid, before.st_gid) != (os.geteuid(), os.getegid())):
                raise Rejected("write-set-private-baseline-required")
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.backup.fd)
            try:
                if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != (before.st_dev, before.st_ino):
                    raise Rejected("write-set-baseline-directory-changed")
                tree, blobs = load_baseline(fd, row["baseline_sha256"])
                if os.listxattr(fd):
                    raise Rejected("write-set-baseline-metadata-unsupported")
            finally:
                os.close(fd)
            validate_plan(tree, blobs, row["additions"])
            expected = tree["entries"]["."]
            if (expected["uid"], expected["gid"], expected["mode"]) != (root.uid, root.gid, root.mode):
                raise Rejected("write-set-root-metadata-mismatch")
            entries += len(tree["entries"]) + len(row["additions"]) + len(stages(tree))
            total += sum(item.get("size", 0) for item in tree["entries"].values())
            if entries > MAX_ENTRIES or total > MAX_TREE_BYTES:
                raise Rejected("write-set-aggregate-limit")
            baselines[name] = (tree, blobs)
        auth = value["auth"]
        selected_auths(*baselines[auth["root"]], auth["selected"], auth["expected_type"])
        self._current(deadline)
        if read_manifest(self.backup.fd, self.pin) != value:
            raise Rejected("write-set-manifest-changed")
        if self.manifest is not None and (value != self.manifest or baselines != self.baselines):
            raise Rejected("write-set-baseline-changed")
        self.manifest, self.baselines = copy.deepcopy(value), baselines

    def _bound(self, intent, deadline):
        validate_intent(intent)
        pin = digest(canonical(intent))
        if (intent["baseline_sha256"] != self.pin
                or self.intent_sha256 is not None and pin != self.intent_sha256):
            raise Rejected("write-set-original-intent-pin-required")
        self.intent_sha256 = pin
        self._load(deadline)

    def _inspect_all(self, deadline):
        for name, (tree, blobs) in sorted(self.baselines.items()):
            inspect_restore(self.roots[name].fd, tree, blobs, self.manifest["roots"][name]["additions"],
                            check=lambda: self._current(deadline))

    def validate_recovery(self, intent, *, deadline):
        """Precheck every baseline and current root before the first mutation."""
        try:
            self._bound(intent, deadline)
            self._inspect_all(deadline)
            return True
        except BaseException:
            self.failed = True
            raise

    def restore_complete(self, intent, *, deadline, fault=None):
        try:
            if self.restored:
                raise Rejected("write-set-restore-once-only")
            self.validate_recovery(intent, deadline=deadline)
            for name, (tree, blobs) in sorted(self.baselines.items()):
                self._load(deadline)
                restore_tree(self.roots[name].fd, tree, blobs, self.manifest["roots"][name]["additions"],
                             fault=fault, check=lambda: self._current(deadline))
            # Earlier roots may have changed while a later root was being restored.
            self._verify_all(deadline)
            self.restored = True
            return True
        except BaseException:
            self.failed = True
            raise

    def _verify_all(self, deadline):
        self._load(deadline)
        captured = {}
        for name, (tree, blobs) in sorted(self.baselines.items()):
            self._current(deadline)
            root = self.roots[name].approval
            actual, actual_blobs = snapshot(self.roots[name].fd, uid=root.uid, gid=root.gid)
            if actual != tree or actual_blobs != blobs:
                raise Rejected("write-set-final-inventory-mismatch")
            captured[name] = (actual, actual_blobs)
            if name == self.manifest["auth"]["root"]:
                auth = self.manifest["auth"]
                selected_auths(actual, actual_blobs, auth["selected"], auth["expected_type"])
            self._current(deadline)
        # All cooperating writers must remain excluded across the whole scan.
        self._current(deadline)
        return captured

    def capture_files(self, intent, roles, *, deadline):
        """Read actual restored role bytes, not backup blobs or cached proposals.

        roles is an independently approved mapping to (root, relative file).
        Returned bytes remain restricted; no paths/content belong in receipts.
        """
        if not self.restored:
            self.failed = True
            raise Rejected("write-set-restored-role-mapping-required")
        return self._capture_files(intent, roles, deadline=deadline)

    def _capture_files(self, intent, roles, *, deadline):
        try:
            if (type(roles) is not dict or not 1 <= len(roles) <= 16
                    or any(not identity(role) for role in roles)):
                raise Rejected("write-set-restored-role-mapping-required")
            roles = copy.deepcopy(roles)
            locations = set()
            for location in roles.values():
                if (type(location) is not tuple or len(location) != 2
                        or type(location[0]) is not str or location[0] not in self.roots):
                    raise Rejected("write-set-restored-role-mapping-required")
                relative_path(location[1])
                if location in locations:
                    raise Rejected("write-set-distinct-role-files-required")
                locations.add(location)
            self._bound(intent, deadline)
            actual = self._verify_all(deadline)
            result = {}
            for role, (root, path) in roles.items():
                tree, blobs = actual[root]
                row = tree["entries"].get(path)
                if row is None or row["kind"] != "file":
                    raise Rejected("write-set-restored-role-file-required")
                result[role] = blobs[row["sha256"]]
            self._verify_all(deadline)
            return result
        except BaseException:
            self.failed = True
            raise

    def verify_files(self, intent, *, deadline):
        """Fresh all-root oracle, not config/image/replay semantics or start grant."""
        try:
            if not self.restored:
                raise Rejected("write-set-restoration-required")
            self._bound(intent, deadline)
            self._verify_all(deadline)
            return {"schema": "host-recovery-write-set-restored-v1", "baseline_sha256": self.pin,
                    "roots": len(self.roots), "entries": sum(len(tree["entries"]) for tree, _ in self.baselines.values()),
                    "selected": 9, "disabled": 7, "enabled": 2, "filesystem_verified": True,
                    "semantic_start_oracle_proven": False, "start_permission": False, "production_acceptance": False}
        except BaseException:
            self.failed = True
            raise
