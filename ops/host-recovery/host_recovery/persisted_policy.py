"""Version-bound offline Docker policy observations, never a relaunch grant.

Trusted provisioning supplies the exact containers-root inode and approved whole
hostconfig hashes. No metadata is edited, adopted or normalized. The original
registry and live supervisor authority remain required at every read boundary.
This checks only persisted object policy/identity, not the entire Moby decoder,
exclusive ownership history, daemon configuration, task death or pending drain.
"""
from dataclasses import asdict
import os
import stat
import threading

from .broker_authority import SupervisorPeerAuthority
from .broker_operations import shape
from .durable import Rejected, canonical, decode, digest, read_file, signature
from .installation import DirectoryApproval, FLAGS, open_approved_directory
from .journal import OBJECT_ID
from .loading import metadata, names, pin
from .quarantine_inventory import MAX_OBJECTS, original_registry
from .topology import Topology

SOURCE = "6430e49a55babd9b8f4d08e70ecb2b68900770fe"
FILES = ("config.v2.json", "hostconfig.json")
MAX_BYTES = 1024 * 1024


def policy_json(raw):
    # json.loads(bytes) also auto-detects UTF-16/32 and accepts BOMs; Moby's
    # encoding/json does not. Do not validate a Python-only interpretation.
    if (not raw.lstrip(b" \t\r\n").startswith(b"{") or b"\0" in raw):
        raise Rejected("persisted-policy-utf8-json-required")
    raw.decode("utf-8")
    value = decode(raw)
    # Go's encoding/json matches struct field names case-insensitively. Reject
    # aliases instead of letting Python validate a different effective policy.
    def keys(item):
        if type(item) is dict:
            folded = [key.casefold() for key in item]
            if any(not key.isascii() for key in item) or len(set(folded)) != len(folded):
                raise Rejected("persisted-policy-ambiguous-json-fields")
            for child in item.values():
                keys(child)
        elif type(item) is list:
            for child in item:
                keys(child)
    keys(value)
    return value


class PersistedObjectPolicy:
    """Protected read-only policy barrier for the original cold submission.

    approved_hosts is an independently provisioned canonical full-ID -> complete
    hostconfig hash map, never a hash learned from the files being checked. The
    supplied directory is data_root/containers, not a caller-selected IPC path.
    A valid observation cannot authorize Docker startup or reconstruct provenance.
    """
    def __init__(self, *, authority, topology, directory, approved_hosts):
        if (not isinstance(authority, SupervisorPeerAuthority) or not isinstance(topology, Topology)
                or not isinstance(directory, DirectoryApproval) or type(approved_hosts) is not bytes):
            raise Rejected("persisted-policy-explicit-boundaries-required")
        value, binding = topology.manifest(), decode(authority._binding)
        if (topology.sha256 != binding["topology_sha256"] or value["installation_id"] != binding["installation_id"]
                or value["tools"]["dockerd"]["source_revision"] != SOURCE
                or directory.path != value["resources"]["data_root"] + "/containers"):
            raise Rejected("persisted-policy-original-versioned-root-required")
        hosts = decode(approved_hosts)
        if (approved_hosts != canonical(hosts) or not 1 <= len(hosts) <= MAX_OBJECTS
                or any(OBJECT_ID.fullmatch(key) is None for key in hosts)):
            raise Rejected("persisted-policy-approved-full-ids-required")
        for expected in hosts.values():
            pin(expected)
        self.authority, self.topology, self.directory = authority, topology, directory
        self._hosts = bytes(approved_hosts)
        self._original = authority, topology, directory
        self.failed, self._mutex = False, threading.Lock()
        self._configuration = self.configuration()

    def configuration(self):
        return canonical({"schema": "host-recovery-persisted-policy-target-v1",
            "binding_sha256": digest(self.authority._binding), "topology_sha256": self.topology.sha256,
            "directory": asdict(self.directory), "source_revision": SOURCE,
            "approved_hosts_sha256": digest(self._hosts)})

    def _current(self, deadline, check):
        if (self.failed or self._original != (self.authority, self.topology, self.directory)
                or self.configuration() != self._configuration):
            raise Rejected("persisted-policy-configuration-changed")
        check()
        self.authority.observe(deadline=deadline)
        if self._original != (self.authority, self.topology, self.directory) or self.configuration() != self._configuration:
            raise Rejected("persisted-policy-configuration-changed")

    def _snapshot(self, root, intent, registered, deadline, check):
        self._current(deadline, check)
        root.validate()
        before = metadata(root.fd, uid=self.directory.uid, gid=self.directory.gid, directory=True)
        expected = sorted([intent["old_object_id"], *registered])
        if sorted(decode(self._hosts)) != expected or names(root.fd) != expected:
            # No label filtering, partial-create adoption, unknown directory or
            # missing registered object can be hidden by a valid old policy.
            raise Rejected("persisted-policy-whole-object-inventory-mismatch")
        records = {}
        for object_id in expected:
            self._current(deadline, check)
            original = os.stat(object_id, dir_fd=root.fd, follow_symlinks=False)
            fd = os.open(object_id, FLAGS, dir_fd=root.fd)
            try:
                info = metadata(fd, uid=self.directory.uid, gid=self.directory.gid, directory=True)
                if signature(info) != signature(original) or info.st_dev != before.st_dev:
                    raise Rejected("persisted-policy-object-directory-changed")
                first_names = names(fd)
                if not set(FILES) <= set(first_names):
                    raise Rejected("persisted-policy-required-metadata-missing")
                entries = {}
                for name in FILES:
                    self._current(deadline, check)
                    raw, st = read_file(fd, name, limit=MAX_BYTES)
                    if (st.st_dev != before.st_dev or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode))
                            != (self.directory.uid, self.directory.gid, 0o600)):
                        raise Rejected("persisted-policy-protected-file-required")
                    entries[name] = (raw, signature(st))
                    self._current(deadline, check)
                config, host = (policy_json(entries[name][0]) for name in FILES)
                image = (self.topology.manifest()["pins"]["rollback_image_sha256"]
                         if object_id == intent["old_object_id"] else registered[object_id]["image_id"])
                if config.get("ID") != object_id or config.get("Image") != "sha256:" + image:
                    raise Rejected("persisted-policy-original-object-image-required")
                policy = host.get("RestartPolicy")
                shape(policy, ("Name", "MaximumRetryCount"))
                if (policy["Name"] != "no" or type(policy["Name"]) is not str
                        or type(policy["MaximumRetryCount"]) is not int or policy["MaximumRetryCount"] != 0
                        or host.get("AutoRemove") is not False or host.get("Privileged") is not False
                        or host.get("CgroupParent") != self.topology.manifest()["runtime"]["slice"]
                        or digest(entries["hostconfig.json"][0]) != decode(self._hosts)[object_id]):
                    raise Rejected("persisted-policy-restart-disabled-approved-host-required")
                # config.v2 State may be stale after SIGKILL. It is deliberately
                # NOT read as a stopped-task oracle or rewritten to look stopped.
                for name, (raw, stamp) in entries.items():
                    self._current(deadline, check)
                    again, st = read_file(fd, name, limit=MAX_BYTES)
                    if again != raw or signature(st) != stamp:
                        raise Rejected("persisted-policy-file-changed")
                if (first_names != names(fd) or signature(info) != signature(os.fstat(fd))
                        or signature(info) != signature(os.stat(object_id, dir_fd=root.fd, follow_symlinks=False))):
                    raise Rejected("persisted-policy-object-directory-changed")
                records[object_id] = {name: {"sha256": digest(raw), "signature": stamp}
                                      for name, (raw, stamp) in entries.items()}
            finally:
                os.close(fd)
        if names(root.fd) != expected or signature(before) != signature(os.fstat(root.fd)):
            raise Rejected("persisted-policy-object-inventory-changed")
        root.validate()
        self._current(deadline, check)
        return canonical(records)

    def observe(self, *, deadline, check):
        with self._mutex:
            try:
                current = lambda: self._current(deadline, check)
                intent, registered, registry = original_registry(authority=self.authority, topology=self.topology,
                    deadline=deadline, check=current)
                with open_approved_directory(self.directory) as root:
                    first = self._snapshot(root, intent, registered, deadline, check)
                    second = self._snapshot(root, intent, registered, deadline, check)
                    if first != second or original_registry(authority=self.authority, topology=self.topology,
                            deadline=deadline, check=current) != (intent, registered, registry):
                        raise Rejected("persisted-policy-observation-changed")
                    current()
                current()
                return {"schema": "host-recovery-persisted-policy-observation-v1",
                    "target_sha256": digest(self._configuration), "registry_sha256": digest(registry),
                    "metadata_sha256": digest(first), "object_count": len(registered) + 1,
                    "restart_disabled_policy_observed": True, "ownership_history_proven": False,
                    "runtime_relaunch_allowed": False, "pending_drained": False, "start_allowed": False,
                    "complete_fence_proven": False, "production_acceptance": False}
            except Exception:
                self.failed = True
                raise Rejected("persisted-policy-observation-unconfirmed") from None
