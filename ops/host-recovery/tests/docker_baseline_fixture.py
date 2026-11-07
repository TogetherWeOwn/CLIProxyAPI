"""Synthetic private bind sources for the hosted Docker qualification only.

Approvals and the original intent are diagnostic fixture inputs, not installed
supervisor authority. No real auth/config/plugin bytes are read or restored.
"""
from contextlib import ExitStack, contextmanager
import errno
import os
from pathlib import Path
import re
import shutil
import stat
import time

from host_recovery import budget, durable, inventory, journal, mounted_baseline, write_set
from host_recovery.installation import DirectoryApproval


SCHEMA = "host-recovery-docker-baseline-fixture-v1"


def baseline_root(runtime_root):
    if not re.fullmatch(r"/tmp/cpa-containerd-config\.d[0-9a-f]{12}", str(runtime_root)):
        raise durable.Rejected("baseline-fixture-runtime-root-required")
    # /tmp is deliberately NOT a trusted ancestor. Exclusively create a separate
    # protected root on the disposable runner; never chmod an existing ancestor.
    return Path("/cpa-docker-baseline." + runtime_root.name.rsplit(".", 1)[1])


def marker(runtime_root):
    return {"schema": SCHEMA, "runtime_root": str(runtime_root)}


def approval(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise durable.Rejected("baseline-fixture-directory-required")
    return DirectoryApproval(str(path), info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                             stat.S_IMODE(info.st_mode))


def prepare(runtime_root):
    root = baseline_root(runtime_root)
    root.mkdir(mode=0o700)
    with durable.directory(str(root), private=True) as fd:
        durable.atomic_write(fd, "owner.json", durable.canonical(marker(runtime_root)))
    paths = {name: root / name for name in ("auth", "config", "plugin")}
    backup = root / "backup"
    for path in (*paths.values(), backup):
        path.mkdir(mode=0o700)
    selected = {}
    for index in range(9):
        name = "synthetic-%d.json" % index
        selected[name] = index < 7
        put(paths["auth"] / name, durable.canonical({"type": "meta", "disabled": index < 7}))
    put(paths["auth"] / "unrelated.json", b'{"type":"other","disabled":false}\n')
    (paths["auth"] / "nested").mkdir(mode=0o700)
    put(paths["auth"] / "nested/unrelated.bin", b"synthetic-unrelated-provider\0bytes", mode=0o640)
    put(paths["config"] / "config.yaml", b"replay: true\nplugins: {}\n")
    put(paths["config"] / "compose.yaml", b"services:\n  old:\n    image: synthetic-old\n")
    manifest = {"schema": "host-recovery-write-set-v1", "roots": {}, "auth": {
        "root": "auth", "selected": selected, "expected_type": "meta"}}
    with durable.directory(str(backup), private=True) as parent:
        for name, path in paths.items():
            with durable.directory(str(path)) as fd:
                tree, blobs = inventory.snapshot(fd, uid=0, gid=0)
            pin = inventory.save_baseline(parent, name, tree, blobs)
            manifest["roots"][name] = {"baseline_sha256": pin, "additions": {}}
        pin = durable.atomic_write(parent, "manifest.json", durable.canonical(manifest))
    mounts = [{"Type": "bind", "Source": str(path), "Destination": "/baseline/" + name,
               "Mode": "ro", "RW": False, "Propagation": "rprivate"} for name, path in paths.items()]
    return {"root": root, "backup": approval(backup), "paths": paths,
            "roots": {name: approval(path) for name, path in paths.items()}, "pin": pin, "mounts": mounts}


def put(path, raw, *, mode=0o600):
    path.write_bytes(raw)
    path.chmod(mode)


def intent(pin, object_id):
    attempt = "60e14471-66ce-4d2a-9a16-aa57b1658bc5"
    policy = {"schema": "host-recovery-budget-v1", "work_seconds": 120,
              "recovery_seconds": 180, "total_seconds": 300, "measurement_sha256": "a" * 64,
              "forward": {"caps": dict.fromkeys(budget.FORWARD_PHASES, 10), "safety_margin": 5},
              "recovery": {"caps": dict.fromkeys(budget.RECOVERY_PHASES, 20), "safety_margin": 5}}
    value = {"schema": "host-recovery-intent-v1", "attempt_id": attempt, "installation_id": "fixture",
             "package_sha256": "b" * 64, "manifest_sha256": "c" * 64, "baseline_sha256": pin,
             "policy_sha256": durable.digest(durable.canonical(policy)), "budget": policy,
             "old_object_id": object_id, "candidate_image_id": "f" * 64, "candidate_ownership_id": attempt,
             "owner": {"installation_id": "fixture", "attempt_id": attempt, "unit": "supervisor.service",
                       "invocation_id": "invocation", "boot_id": "boot-a"}}
    journal.validate_intent(value)
    return value


@contextmanager
def observe(fixture, *, object_id, pid, witness, check, deadline):
    value = intent(fixture["pin"], object_id)
    approved = mounted_baseline.MountedBaselineApproval(durable.digest(durable.canonical(value)), object_id,
        durable.digest(durable.canonical(fixture["mounts"])))
    with ExitStack() as stack:
        verifier = stack.enter_context(write_set.open_write_set_verifier(baseline=fixture["backup"],
            roots=fixture["roots"],
            baseline_sha256=fixture["pin"], check=check, clock=time.monotonic))
        view = stack.enter_context(mounted_baseline.open_mounted_baseline(pid=pid, witness=witness,
            approval=approved, mounts=fixture["mounts"], verifier=verifier, check=check, clock=time.monotonic))
        with view.observe(value, deadline=deadline) as receipt:
            yield receipt


@contextmanager
def restore_stopped(fixture, *, object_id, check, deadline, fault=None):
    """Actual synthetic-root restoration; caller retains its fixture lock.

    This is not a complete writer fence or a semantic service-start oracle. The
    fixture must independently keep its old task stopped throughout this context.
    A fresh reader, not the restorer's progress bit, verifies all approved roots.
    """
    value = intent(fixture["pin"], object_id)
    arguments = {"baseline": fixture["backup"], "roots": fixture["roots"],
                 "baseline_sha256": fixture["pin"], "check": check, "clock": time.monotonic}
    with write_set.open_write_set(**arguments) as recovery:
        recovery.validate_recovery(value, deadline=deadline)
        recovery.restore_complete(value, deadline=deadline, fault=fault)
        with write_set.open_write_set_verifier(**arguments) as verifier:
            receipt = verifier.verify_files(value, deadline=deadline)
            yield receipt
            verifier.verify_files(value, deadline=deadline)


def rehearse_restore_faults(fixture, *, object_id, check, deadline):
    """Reached storage faults while the caller proves the original task is dead.

    Faults are injected exceptions at the real filesystem publication hooks, not
    a kernel/storage-device failure. Each fresh retry must verify every root.
    No daemon launch, task start or operational authority is available here.
    """
    results = []
    def stopped():
        if time.monotonic() >= deadline or check(deadline=deadline) is not True:
            raise durable.Rejected("baseline-fixture-stopped-boundary-required")
    for code in (errno.EIO, errno.ENOSPC):
        for point in ("create", "write", "file-fsync", "rename", "directory-fsync", "readback"):
            stopped()
            put(fixture["paths"]["auth"] / "nested/unrelated.bin", b"synthetic-partial-restore", mode=0o640)
            reached = []
            def fault(stage):
                if stage == point:
                    reached.append(stage)
                    raise OSError(code, "synthetic restoration storage failure")
            try:
                with restore_stopped(fixture, object_id=object_id, check=check, deadline=deadline, fault=fault):
                    raise AssertionError("failed restoration yielded a usable receipt")
            except OSError as err:
                if err.errno != code or reached != [point]:
                    raise AssertionError("restoration fault did not reach its exact storage hook") from err
            else:
                raise AssertionError("restoration storage fault was swallowed")
            stopped()
            with restore_stopped(fixture, object_id=object_id, check=check, deadline=deadline) as receipt:
                if (receipt["filesystem_verified"] is not True or receipt["roots"] != 3
                        or receipt["start_permission"] is not False):
                    raise AssertionError("fresh restoration retry was not independently verified")
            stopped()
            results.append({"errno": code, "hook": point, "reached": True,
                            "failed_restore_yielded": False, "fresh_retry_verified": True})
    return results


def cleanup(runtime_root):
    root = baseline_root(runtime_root)
    if not os.path.lexists(root):
        return
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, 0o700)):
        raise durable.Rejected("baseline-fixture-cleanup-owner-required")
    with durable.directory(str(root), private=True) as fd:
        raw, _ = durable.read_file(fd, "owner.json")
        if raw != durable.canonical(marker(runtime_root)):
            raise durable.Rejected("baseline-fixture-cleanup-marker-mismatch")
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 4 and (fields[4] == str(root) or fields[4].startswith(str(root) + "/")):
            raise durable.Rejected("baseline-fixture-cleanup-mounted")
    shutil.rmtree(root)
    if os.path.lexists(root):
        raise durable.Rejected("baseline-fixture-cleanup-remains")
