"""Root-owned launch anchors for fixed conservative service entrypoints.

The trust anchor is protected root ownership, not a digest stored beside mutable
inputs. No file is provisioned, no owner is changed and no credential is minted.
These anchors may configure only the existing unresolved/identity runners.
"""
import copy
import os
import stat

from .budget import positive
from .durable import Rejected, canonical, decode, read_file, signature
from .installation import DirectoryApproval, _Directory, protected
from .journal import identity
from .loading import pin
from .manager import UNIT
from .service_units import absolute_path

COMMON = frozenset(("approval", "sha256", "uid", "gid", "endpoint", "endpoint-device", "endpoint-inode", "deadline"))
SUPERVISOR = COMMON | {"alert-endpoint", "alert-endpoint-device", "alert-endpoint-inode",
    "alert-receipts", "alert-receipts-device", "alert-receipts-inode", "alert-route",
    "listener-uid", "listener-instance", "alert-deadline"}
PATHS = frozenset(("approval", "endpoint", "alert-endpoint", "alert-receipts"))
NUMBERS = frozenset(("uid", "gid", "endpoint-device", "endpoint-inode", "alert-endpoint-device",
                    "alert-endpoint-inode", "alert-receipts-device", "alert-receipts-inode", "listener-uid"))


def parse_anchor(raw, *, role):
    value = decode(raw)
    if (role not in ("supervisor", "worker") or set(value) != {"schema", "role", "unit", "arguments"}
            or value["schema"] != "host-recovery-service-anchor-v1" or value["role"] != role
            or type(value["unit"]) is not str or UNIT.fullmatch(value["unit"]) is None):
        raise Rejected("service-anchor-schema-or-role")
    arguments = value["arguments"]
    fields = SUPERVISOR if role == "supervisor" else COMMON
    if type(arguments) is not dict or set(arguments) != fields:
        raise Rejected("service-anchor-arguments-schema")
    for name, item in arguments.items():
        if name in PATHS:
            absolute_path(item)
        elif name in NUMBERS:
            limit = 2 ** 64 - 1 if name.endswith(("-inode", "-device")) else 2147483647
            minimum = 1 if name.endswith("-inode") else 0
            if type(item) is not int or not minimum <= item <= limit:
                raise Rejected("service-anchor-numeric-argument")
        elif name in ("deadline", "alert-deadline"):
            if not positive(item):
                raise Rejected("service-anchor-original-deadline-required")
        elif name == "sha256":
            pin(item)
        elif not identity(item):
            raise Rejected("service-anchor-identity-argument")
    # Prevent a configuration owner from being promoted into the privileged
    # installer role. Runtime identities remain the unprivileged launch pins.
    if arguments["uid"] == 0 or arguments["gid"] == 0:
        raise Rejected("service-anchor-unprivileged-launch-owner-required")
    return copy.deepcopy(value)


def anchor_argv(value):
    """Build an argv list, never a shell command or a systemd command string."""
    parsed = parse_anchor(canonical(value), role=value.get("role"))
    return [word for name, item in sorted(parsed["arguments"].items()) for word in ("--" + name, str(item))]


def _read_anchor(path, *, role, uid, gid):
    """Private numeric-owner seam for owned-filesystem tests, not CLI authority."""
    absolute_path(path)
    parent, name = os.path.split(path)
    info = os.stat(parent, follow_symlinks=False)
    directory = _Directory(DirectoryApproval(parent, info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                                               stat.S_IMODE(info.st_mode)))
    try:
        for _, fd, _ in directory.chain:
            protected(fd, uid)
        raw, before = read_file(directory.fd, name, limit=65536)
        if ((before.st_uid, before.st_gid) != (uid, gid)
                or stat.S_IMODE(before.st_mode) not in (0o400, 0o444, 0o600, 0o644)
                or before.st_dev != os.fstat(directory.fd).st_dev):
            raise Rejected("service-anchor-protected-owner-required")
        result = parse_anchor(raw, role=role)
        again, after = read_file(directory.fd, name, limit=65536)
        if raw != again or signature(before) != signature(after):
            raise Rejected("service-anchor-changed")
        directory.validate()
        return result
    finally:
        directory.close()


def read_service_anchor(path, *, role):
    """Accept only root:root protected anchors; no environment/argument override.

    All ancestors must be protected root-owned directories. A matching local
    checksum cannot promote an unprivileged file to this administrative authority.
    The trusted installed interpreter/package/unit remain provisioning prerequisites.
    """
    return _read_anchor(path, role=role, uid=0, gid=0)
