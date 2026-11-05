"""Actions-only real system-manager stop/completion and descendant evidence.

Unlike the private-bus matrix, neither the bus address, manager credentials nor
native transport is patched. Test-local library pins and owned fixture units
are NOT independently approved production provisioning, complete activation
exclusion, daemon/shim containment, a cold runtime barrier or recovery acceptance.
"""
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from host_recovery.durable import canonical, digest
from host_recovery.installation import DirectoryApproval, open_approved_directory
from host_recovery.manager import PROPERTIES, UnitBinding, properties, static_properties
from host_recovery.manager_bus import MAX_EVENTS, RESULTS, ManagerJobSession, _ok, _text
from host_recovery.manager_jobs import MANAGER, MANAGER_PATH, job_path
from host_recovery.protected_file import ProtectedFile

ENABLED = (os.environ.get("CPA_RECOVERY_SYSTEM_MANAGER_TEST") == "1"
           and os.environ.get("GITHUB_ACTIONS") == "true"
           and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted")


def command(*argv):
    result = subprocess.run(argv, env={"PATH": os.defpath, "LANG": "C"},
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15.)
    if result.returncode:
        raise AssertionError("fixture command failed: " + repr((argv, result.returncode,
                                                               result.stdout, result.stderr)))
    return result.stdout


def unit_name(suffix):
    run, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    if not all(re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run, attempt)):
        raise AssertionError("bounded Actions run identity required")
    if suffix not in ("active", "inactive", "masked", "dependent", "queue-control", "gate-control",
                      "queue-fenced", "gate-fenced", "runtime-dockerd", "runtime-containerd", "runtime-task"):
        raise AssertionError("fixed fixture suffix required")
    return "cpa-manager-fixture-" + run + "-" + attempt + "-" + suffix + ".service"


def cleanup_units(*suffixes):
    systemctl = shutil.which("systemctl", path=os.defpath)
    for suffix in suffixes:
        unit = unit_name(suffix)
        def listed(*options):
            return command(systemctl, "list-units", "--all", "--no-legend", "--plain", *options, "--", unit).strip()
        if listed():
            command(systemctl, "stop", "--", unit)
            if listed("--state=active,activating,deactivating"):
                raise AssertionError("owned fixture still active after cleanup")
            if listed():
                command(systemctl, "reset-failed", "--", unit)
            if listed():
                raise AssertionError("owned transient fixture was not collected")
        print(json.dumps({"cleanup_unit": unit, "remaining_loaded": False}), flush=True)


def activation_paths(*, queued=False):
    suffixes = (("queue-control", "queue-fenced", "gate-control", "gate-fenced")
                if queued else ("masked", "dependent"))
    return {suffix: Path("/run/systemd/system") / unit_name(suffix) for suffix in suffixes}


def owned_fragment(path):
    # Never overwrite or collect another unit, even on the disposable runner.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        raw = os.read(fd, 8193)
        marker = ("# cpa-owned-fixture=" + path.name + "\n").encode()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or len(raw) > 8192 or not raw.startswith(marker)):
            raise AssertionError("owned activation fragment unconfirmed")
        return raw
    finally:
        os.close(fd)


def cleanup_activation(*, queued=False):
    systemctl = shutil.which("systemctl", path=os.defpath)
    paths = activation_paths(queued=queued)
    mask = Path("/etc/systemd/system") / unit_name("queue-fenced" if queued else "masked")
    if os.path.lexists(mask):
        info = mask.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or os.readlink(mask) != "/dev/null":
            raise AssertionError("owned activation mask unconfirmed")
    for path in paths.values():
        if os.path.lexists(path):
            owned_fragment(path)
    for suffix in (("queue-control", "queue-fenced", "gate-control", "gate-fenced")
                   if queued else ("dependent", "masked")):
        unit = unit_name(suffix)
        loaded = command(systemctl, "list-units", "--all", "--no-legend", "--plain", "--", unit).strip()
        active = command(systemctl, "list-units", "--all", "--no-legend", "--plain",
                         "--state=active,activating,deactivating", "--", unit).strip()
        if active:
            # Do not depend on pre-mask stop configuration surviving reload.
            # Explicitly terminate the exact TERM-ignoring owned fixture group.
            command(systemctl, "kill", "--kill-whom=all", "--signal=SIGKILL", "--", unit)
        if loaded:
            command(systemctl, "stop", "--", unit)
        if command(systemctl, "list-units", "--all", "--no-legend", "--plain",
                   "--state=active,activating,deactivating", "--", unit).strip():
            raise AssertionError("owned activation fixture still active")
    # Inspect immediately before each exact-name unlink. No prefix sweep, recursive
    # deletion or systemctl unmask that could remove a different file is used.
    for path in paths.values():
        if os.path.lexists(path):
            owned_fragment(path)
            path.unlink()
    if os.path.lexists(mask):
        if not mask.is_symlink() or os.readlink(mask) != "/dev/null":
            raise AssertionError("owned activation mask changed")
        mask.unlink()
    for parent in (Path("/run/systemd/system"), Path("/etc/systemd/system")):
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    command(systemctl, "daemon-reload")
    for path in paths.values():
        loaded = command(systemctl, "list-units", "--all", "--no-legend", "--plain", "--", path.name).strip()
        if loaded:
            command(systemctl, "reset-failed", "--", path.name)
        state = command(systemctl, "show", "--property=LoadState", "--value", "--", path.name).strip()
        if state != b"not-found":
            raise AssertionError("owned activation fixture still loadable")
        print(json.dumps({"cleanup_unit": path.name, "load_state": "not-found",
                          "fragment_removed": True, "mask_removed": True}), flush=True)


def runtime_paths():
    # Calling unit_name also validates the numeric Actions identity.
    unit_name("runtime-dockerd")
    slice_name = "system-cpafixture" + os.environ["GITHUB_RUN_ID"] + "a" + os.environ["GITHUB_RUN_ATTEMPT"] + ".slice"
    return {"slice": Path("/run/systemd/system") / slice_name,
            **{role: Path("/run/systemd/system") / unit_name("runtime-" + role)
               for role in ("dockerd", "containerd", "task")}}


def cleanup_runtime():
    paths = runtime_paths()
    systemctl = shutil.which("systemctl", path=os.defpath)
    masks = [Path("/etc/systemd/system") / paths[role].name for role in ("dockerd", "containerd")]
    for path in paths.values():
        if os.path.lexists(path):
            owned_fragment(path)
    for mask in masks:
        if os.path.lexists(mask):
            info = mask.lstat()
            if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or os.readlink(mask) != "/dev/null":
                raise AssertionError("owned runtime mask unconfirmed")
    for role in ("dockerd", "containerd", "task", "slice"):
        unit = paths[role].name
        loaded = command(systemctl, "list-units", "--all", "--no-legend", "--plain", "--", unit).strip()
        active = command(systemctl, "list-units", "--all", "--no-legend", "--plain",
                         "--state=active,activating,deactivating", "--", unit).strip()
        if active and role != "slice":
            command(systemctl, "kill", "--kill-whom=all", "--signal=SIGKILL", "--", unit)
        if loaded:
            command(systemctl, "stop", "--", unit)
        if command(systemctl, "list-units", "--all", "--no-legend", "--plain",
                   "--state=active,activating,deactivating", "--", unit).strip():
            raise AssertionError("owned runtime fixture still active")
    for path in paths.values():
        if os.path.lexists(path):
            owned_fragment(path)
            path.unlink()
    for mask in masks:
        if os.path.lexists(mask):
            if not mask.is_symlink() or os.readlink(mask) != "/dev/null":
                raise AssertionError("owned runtime mask changed")
            mask.unlink()
    for parent in (Path("/run/systemd/system"), Path("/etc/systemd/system")):
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    command(systemctl, "daemon-reload")
    for path in paths.values():
        if command(systemctl, "list-units", "--all", "--no-legend", "--plain", "--", path.name).strip():
            command(systemctl, "reset-failed", "--", path.name)
        state = command(systemctl, "show", "--property=LoadState", "--value", "--", path.name).strip()
        if path == paths["slice"]:
            # systemd can synthesize a named slice without any fragment. Require
            # the exact stopped/empty builtin projection, not service not-found.
            fields = {"Id", "LoadState", "ActiveState", "SubState", "ControlGroup", "FragmentPath", "Job"}
            raw = command(systemctl, "show", "--property=" + ",".join(sorted(fields)), "--", path.name)
            print(json.dumps({"cleanup_slice_raw":raw.decode()}), flush=True)
            row = {}
            for line in raw.decode().splitlines():
                key,sep,value = line.partition("=")
                if not sep or key not in fields or key in row:
                    raise AssertionError("cleanup slice projection ambiguous")
                row[key] = value
            if (set(row) != fields or row["Id"] != path.name or row["LoadState"] not in ("loaded", "not-found")
                    or row["ActiveState"] != "inactive" or row["SubState"] != "dead"
                    or row["ControlGroup"] or row["FragmentPath"] or row["Job"] not in ("", "0")
                    or Path("/sys/fs/cgroup/system.slice", path.name).exists()):
                raise AssertionError("cleanup slice not stopped and empty")
        elif state != b"not-found":
            raise AssertionError("owned runtime fixture still loadable")
        print(json.dumps({"cleanup_unit": path.name, "load_state": state.decode(),
                          "fragment_removed": True, "mask_removed": True}), flush=True)


class QueuedLaunchWitness(ManagerJobSession):
    """Test-only observer; arbitrary start/cancel calls NEVER enter the broker API."""
    def __init__(self, *, target, **kwargs):
        self.target, self.observed = target, {}
        super().__init__(**kwargs)

    def _job_removed(self, message):
        connection = self._connection
        if (_text(connection.lib.sd_bus_message_get_sender(message)) != self.owner
                or _text(connection.lib.sd_bus_message_get_path(message)) != MANAGER_PATH
                or _text(connection.lib.sd_bus_message_get_interface(message)) != MANAGER + ".Manager"
                or _text(connection.lib.sd_bus_message_get_member(message)) != "JobRemoved"):
            raise AssertionError("fixture completion sender unconfirmed")
        number, path, unit, result = connection.fields(message, "uoss")
        cookie = C.c_uint64()
        _ok(connection.lib.sd_bus_message_get_cookie(message, C.byref(cookie)))
        self._event_count += 1
        if (self._event_count > MAX_EVENTS or cookie.value <= self._last_cookie
                or number != job_path(path) or result not in RESULTS):
            raise AssertionError("fixture completion identity unconfirmed")
        self._last_cookie = cookie.value
        if unit == self.target:
            if path in self.observed:
                raise AssertionError("duplicate fixture completion")
            self.observed[path] = {"job_id": number, "job_path": path, "unit": unit,
                                   "result": result, "sender_cookie": cookie.value}

    def completed(self, path, expected):
        while path not in self.observed:
            self.pump()
            if path not in self.observed:
                self._current()
                self._connection.wait(min(10000, max(1, int((self.deadline - self.clock()) * 1000000))))
        self.identity()
        event = self.observed[path]
        if event["result"] != expected or event["job_id"] in self.jobs():
            raise AssertionError("fixture completion result unconfirmed")
        print(json.dumps({"manager_bus": self.bus_id, "manager_owner": self.owner,
                          "queued_launch_completion": event}), flush=True)


@unittest.skipUnless(ENABLED, "real system-manager matrix requires its disposable Actions step")
class SystemManagerTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertEqual(Path("/proc/1/comm").read_text().strip(), "systemd")
        self.assertTrue(Path("/sys/fs/cgroup/cgroup.controllers").is_file())
        self.assertTrue(hasattr(os, "pidfd_open"))
        self.systemctl = shutil.which("systemctl", path=os.defpath)
        self.systemd_run = shutil.which("systemd-run", path=os.defpath)
        self.assertIsNotNone(self.systemctl)
        self.assertIsNotNone(self.systemd_run)
        self.deadline = time.monotonic() + 30.
        self.directory = tempfile.TemporaryDirectory(prefix="cpa-manager-native-", dir="/")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(self.listener.close)
        self.listener.bind(str(self.root / "ready.sock"))
        self.listener.listen(1)
        self.listener.settimeout(10.)
        library = Path("/usr/lib/x86_64-linux-gnu/libsystemd.so.0").resolve(strict=True)
        # Copy only the runner's installed library into a private owned directory.
        # This exercises real ProtectedFile checks, not administrative approval.
        raw = library.read_bytes()
        self.library_sha256 = hashlib.sha256(raw).hexdigest()
        (self.root / "libsystemd.so").write_bytes(raw)
        (self.root / "libsystemd.so").chmod(0o400)
        info = self.root.stat()
        approval = DirectoryApproval(str(self.root), info.st_dev, info.st_ino, 0, 0,
                                     stat.S_IMODE(info.st_mode))
        self.handle_context = open_approved_directory(approval)
        self.handle = self.handle_context.__enter__()
        self.addCleanup(self.handle_context.__exit__, None, None, None)
        self.library = ProtectedFile(self.handle, "libsystemd.so", uid=0, gid=0,
                                     limit=16 * 1024 * 1024, current=self.current)
        self.addCleanup(self.library.close)
        print(json.dumps({"systemd_version": command(self.systemctl, "--version").decode().splitlines()[0],
                          "kernel": os.uname().release, "library_sha256": self.library_sha256,
                          "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}), flush=True)

    def current(self):
        if time.monotonic() >= self.deadline:
            raise AssertionError("original fixture deadline exhausted")

    def observe(self, unit):
        return properties(command(self.systemctl, "--no-pager", "show",
                                  "--property=" + ",".join(sorted(PROPERTIES)), "--", unit))

    def fixture(self, suffix):
        unit = unit_name(suffix)
        # Register cleanup BEFORE a possibly ambiguous submission. Targets are
        # fixed by this Actions run; no inventory-based kill or broad prefix stop.
        self.addCleanup(cleanup_units, suffix)
        command(self.systemd_run, "--quiet", "--unit=" + unit,
                "--property=Type=exec", "--property=Restart=no", "--property=KillMode=control-group",
                "--property=SendSIGKILL=yes", "--property=TimeoutStopSec=1s",
                "--property=RuntimeMaxSec=60s", "--property=User=0", "--property=Group=0",
                "--property=LimitCORE=0", "--", sys.executable, "-I",
                str(ROOT / "tests/manager_system_fixture.py"), str(self.root / "ready.sock"))
        return self.running_binding(unit)

    def running_binding(self, unit):
        with self.listener.accept()[0] as peer:
            peer.settimeout(5.)
            pid, uid, gid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            self.assertEqual((uid, gid), (0, 0))
            raw, _, flags, _ = peer.recvmsg(1024)
            self.assertFalse(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
            value = json.loads(raw)
            self.assertEqual(set(value), {"parent", "child"})
            self.assertEqual(value["parent"], pid)
            self.assertTrue(type(value["child"]) is int and value["child"] > 1)
        row = self.observe(unit)
        self.assertEqual(int(row["MainPID"]), pid)
        self.assertEqual(row["ActiveState"], "active")
        self.assertTrue(row["ControlGroup"].startswith("/system.slice/"))
        for process in list(value.values()):
            self.assertEqual(Path("/proc/%d/cgroup" % process).read_text(), "0::" + row["ControlGroup"] + "\n")
            pidfd = os.pidfd_open(process, 0)
            self.addCleanup(os.close, pidfd)
            value["parent_fd" if process == pid else "child_fd"] = pidfd
        fragment = Path(row["FragmentPath"])
        self.assertTrue(fragment.is_absolute())
        binding = UnitBinding(unit, row["InvocationID"], row["ControlGroup"], str(fragment),
                              digest(fragment.read_bytes()), digest(canonical(static_properties(row))))
        print(json.dumps({"fixture_unit": unit, "invocation": binding.invocation_id,
                          "cgroup": binding.cgroup, "parent": pid, "child": value["child"]}), flush=True)
        return binding, value

    def session(self, binding):
        session = ManagerJobSession(library=self.library, library_sha256=self.library_sha256,
            units={"forward": binding}, deadline=self.deadline, clock=time.monotonic, check=self.current)
        self.addCleanup(session.close)
        return session

    def masked_observation(self, unit):
        fields = {"Id", "LoadState", "ActiveState", "SubState", "MainPID", "Job", "InvocationID"}
        raw = command(self.systemctl, "--no-pager", "show", "--property=" + ",".join(sorted(fields)), "--", unit)
        print(json.dumps({"masked_observation_raw": raw.decode()}), flush=True)
        row = {}
        for line in raw.decode().splitlines():
            key, sep, value = line.partition("=")
            self.assertTrue(sep)
            self.assertIn(key, fields)
            self.assertNotIn(key, row)
            row[key] = value
        self.assertEqual(set(row), fields)
        self.assertEqual(row["Id"], unit)
        # Only explicit systemctl idle Job display is normalized in this test
        # projection. Do not synthesize missing service properties or change the
        # production loaded-unit configuration reader to accept masked units.
        if row["Job"] == "":
            row["Job"] = "0"
        return row

    def stopped(self, binding, pids, *, observe=None):
        for key in ("parent_fd", "child_fd"):
            poller = select.poll()
            poller.register(pids[key], select.POLLIN)
            self.assertTrue(poller.poll(max(1, int((self.deadline - time.monotonic()) * 1000))))
        row = (observe or self.observe)(binding.unit)
        self.assertIn(row["ActiveState"], ("inactive", "failed"))
        self.assertEqual(row["MainPID"], "0")
        self.assertEqual(row["Job"], "0")
        group = Path("/sys/fs/cgroup" + binding.cgroup)
        # The real completed stop plus pidfd deaths disambiguate disappearance in
        # this owned fixture. Absence is never exported as a general fence proof.
        present = group.exists()
        populated = None
        if present:
            events = dict(line.split() for line in (group / "cgroup.events").read_text().splitlines())
            self.assertEqual(events["populated"], "0")
            populated = 0
        print(json.dumps({"stopped_unit": binding.unit, "pidfds_dead": True,
                          "active_state": row["ActiveState"], "job": row["Job"],
                          "cgroup_present": present, "populated": populated,
                          "monotonic": time.monotonic()}), flush=True)
        return row

    def stop_and_witness(self, binding, *, kill=False):
        session = self.session(binding)
        job = session.stop("forward")
        if kill:
            command(self.systemctl, "kill", "--kill-whom=all", "--signal=SIGKILL", "--", binding.unit)
        while True:
            completions = session.completions()
            if "forward" in completions:
                break
            # Pump the same non-reconnecting native bus. No quiet-time heuristic,
            # extra deadline or repeated StopUnit submission is used.
            self.current()
            session._connection.wait(min(10000, max(1, int((self.deadline - time.monotonic()) * 1000000))))
            self.current()
        event = completions["forward"]
        self.assertEqual(event["job_path"], job)
        self.assertEqual(event["unit"], binding.unit)
        self.assertEqual(event["result"], "done")
        self.assertGreater(event["sender_cookie"], 0)
        self.assertNotIn(event["job_id"], session.jobs())
        print(json.dumps({"manager_bus": session.bus_id, "manager_owner": session.owner,
                          "completion": event}), flush=True)

    def publish_mask(self, binding, *, publish=True):
        from host_recovery.unit_masks import PersistentUnitMasks
        path = Path("/etc/systemd/system")
        st = path.stat()
        self.assertEqual((st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)), (0, 0, 0o755))
        approval = DirectoryApproval(str(path), st.st_dev, st.st_ino, 0, 0, 0o755)
        context = open_approved_directory(approval)
        directory = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        masks = PersistentUnitMasks(directory=directory, units={"forward": binding})
        if not publish:
            return masks
        receipt = masks.publish(current=self.current)
        self.assertTrue(receipt["persistent_masks_published"])
        self.assertFalse(receipt["activation_exclusion_proven"])
        self.assertFalse(receipt["manager_reload_performed"])
        print(json.dumps({"source_mask_publication": receipt}), flush=True)
        return masks

    def test_persistent_mask_blocks_fresh_launches_but_does_not_quiesce(self):
        self.masked_fixture(composed=False)

    def test_original_pending_sequence_masks_stops_and_kills_on_one_connection(self):
        self.masked_fixture(composed=True)

    def masked_fixture(self, *, composed):
        paths = activation_paths()
        mask = Path("/etc/systemd/system") / unit_name("masked")
        self.assertFalse(os.path.lexists(mask))
        self.assertTrue(all(not os.path.lexists(path) for path in paths.values()))
        self.addCleanup(cleanup_activation)
        fragments = {
            "masked": ("[Service]\nType=exec\nRestart=no\nKillMode=control-group\n"
                "SendSIGKILL=yes\nTimeoutStopSec=" + ("5s" if composed else "1s")
                + "\nRuntimeMaxSec=60s\nUser=0\nGroup=0\nLimitCORE=0\n"
                "ExecStart=" + sys.executable + " -I " + str(ROOT / "tests/manager_system_fixture.py")
                + " " + str(self.root / "ready.sock") + "\n"),
            "dependent": ("[Unit]\nRequires=" + unit_name("masked") + "\nAfter=" + unit_name("masked")
                + "\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\nRemainAfterExit=yes\n")}
        for suffix, path in paths.items():
            raw = ("# cpa-owned-fixture=" + path.name + "\n" + fragments[suffix]).encode()
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                self.assertEqual(os.write(fd, raw), len(raw))
                os.fsync(fd)
            finally:
                os.close(fd)
            self.assertEqual(owned_fragment(path), raw)
        command(self.systemctl, "daemon-reload")
        command(self.systemctl, "start", "--", unit_name("masked"))
        binding, pids = self.running_binding(unit_name("masked"))
        self.assertEqual(binding.fragment_path, str(paths["masked"]))
        from host_recovery.broker_operations import OperationJournal
        from host_recovery.mask_reload import ManagerMaskReload
        state = self.root / "reload-state"
        state.mkdir(mode=0o700)
        fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        now = time.monotonic()
        original = dict(installation_id="synthetic", attempt_id="11111111-1111-4111-8111-111111111111",
            intent_sha256="a" * 64, request_sha256="b" * 64, topology_sha256="c" * 64,
            original_boot_id="boot-original", original_arm=now, failure_monotonic=now,
            recovery_deadline=self.deadline)
        generation = dict(boot_id="boot-original", broker_invocation_id="22222222-2222-4222-8222-222222222222",
                          runtime_epoch="33333333-3333-4333-8333-333333333333")
        # Synthetic original request/authority, but real durable files, pinned
        # library, root PID1 connection, Reload reply and typed properties.
        journal = OperationJournal(fd, binding=original, epoch=generation, clock=time.monotonic,
                                   boot_id=lambda: "boot-original")
        masks = self.publish_mask(binding, publish=False)
        session = self.session(binding)
        if composed:
            from host_recovery.manager_jobs import ForwardStopJobs, completion_name
            from host_recovery.masked_forward_stop import MaskedForwardStop
            busctl = shutil.which("busctl", path=os.defpath)
            self.assertIsNotNone(busctl)
            checksum = digest(Path(busctl).read_bytes())
            jobs = ForwardStopJobs(journal=journal, units={"forward": binding}, busctl=busctl,
                busctl_sha256=checksum, commands=None, read_helper_hash=lambda path:digest(Path(path).read_bytes()),
                session=session)
            sequence = MaskedForwardStop(journal=journal, masks=masks, jobs=jobs)
            operation = journal.pending("contain_forward", target_sha256=sequence.target_sha256, deadline=self.deadline)
            witness = QueuedLaunchWitness(target=binding.unit, library=self.library,
                library_sha256=self.library_sha256, units={"forward": binding}, deadline=self.deadline,
                clock=time.monotonic, check=self.current)
            self.addCleanup(witness.close)
            receipt = sequence.stop(operation=operation)
            self.assertTrue(receipt["whole_unit_kill_returned"])
            self.assertTrue(receipt["fixed_stop_completion_observed"])
            self.assertTrue(receipt["masked_inactive_observed"])
            self.assertFalse(receipt["complete_fence_proven"])
            self.assertFalse(receipt["pending_drained"])
            self.assertFalse(receipt["start_allowed"])
            self.assertNotIn("contain_forward", journal._returned)
            completion = json.loads((state / completion_name(1, "forward")).read_bytes())
            witness.completed(completion["job_path"], "done")
            self.assertEqual(witness.observed[completion["job_path"]]["job_id"], completion["job_id"])
            print(json.dumps({"source_masked_forward_sequence": receipt, "completion": completion}), flush=True)
        else:
            operation = journal.pending("contain_forward", target_sha256="d" * 64, deadline=self.deadline)
            masks.publish(current=self.current)
            reload = ManagerMaskReload(journal=journal, masks=masks, session=session)
            receipt = reload.reload(operation=operation)
            self.assertTrue(receipt["effective_masks_observed"])
            self.assertEqual(receipt["active_unit_count"], 1)
            self.assertFalse(receipt["activation_exclusion_proven"])
            self.assertEqual(receipt, reload.observe())
            print(json.dumps({"source_mask_reload": receipt}), flush=True)
            masked = self.masked_observation(binding.unit)
            self.assertEqual(masked["LoadState"], "masked")
            self.assertEqual(masked["ActiveState"], "active")
            self.assertEqual(masked["InvocationID"], binding.invocation_id)
            self.assertEqual(masked["MainPID"], str(pids["parent"]))
            for key in ("parent_fd", "child_fd"):
                poller = select.poll()
                poller.register(pids[key], select.POLLIN)
                self.assertFalse(poller.poll(0), "mask alone killed a fixture process")
            print(json.dumps({"masked_active_unit": binding.unit, "mask_path": str(mask),
                              "load_state": masked["LoadState"], "active_state": masked["ActiveState"],
                              "same_invocation": True, "both_pidfds_live": True,
                              "mask_is_quiescence": False}), flush=True)
            # Mask presence cannot replace independent stop/completion, whole-unit
            # kill and pidfd deaths. This original qualification remains separate.
            self.stop_and_witness(binding, kill=True)
        self.stopped(binding, pids, observe=self.masked_observation)
        for suffix in ("masked", "dependent"):
            result = subprocess.run((self.systemctl, "start", "--", unit_name(suffix)),
                env={"PATH": os.defpath, "LANG": "C"}, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=15.)
            self.assertNotEqual(result.returncode, 0, "masked fixture was startable")
            print(json.dumps({"refused_start_unit": unit_name(suffix), "returncode": result.returncode,
                              "stdout": result.stdout.decode(), "stderr": result.stderr.decode()}), flush=True)
        final = self.masked_observation(binding.unit)
        self.assertEqual(final["LoadState"], "masked")
        self.assertEqual(final["MainPID"], "0")
        self.assertEqual(final["Job"], "0")
        self.assertEqual(os.readlink(mask), "/dev/null")
        dependent = self.observe(unit_name("dependent"))
        self.assertEqual(dependent["MainPID"], "0")
        self.assertEqual(dependent["Job"], "0")
        executed = command(self.systemctl, "show", "--property=ExecMainStartTimestampMonotonic",
                           "--value", "--", unit_name("dependent")).strip()
        self.assertEqual(executed, b"0", "dependent payload actually executed")
        poller = select.poll()
        poller.register(self.listener, select.POLLIN)
        self.assertFalse(poller.poll(0), "a replacement payload reached readiness")
        print(json.dumps({"direct_and_dependency_starts_refused": True,
                          "dependent_payload_executed": False, "pending_drained": False,
                          "boot_exclusion_qualified": False, "complete_fence_proven": False}), flush=True)

    def test_waiting_start_is_canceled_before_dependency_release(self):
        paths = activation_paths(queued=True)
        mask = Path("/etc/systemd/system") / unit_name("queue-fenced")
        self.assertFalse(os.path.lexists(mask))
        self.assertTrue(all(not os.path.lexists(path) for path in paths.values()))
        self.addCleanup(cleanup_activation, queued=True)
        for variant in ("control", "fenced"):
            gate, target = unit_name("gate-" + variant), unit_name("queue-" + variant)
            fragments = {
                "gate-" + variant: ("[Service]\nType=oneshot\nRemainAfterExit=yes\nRestart=no\n"
                    "KillMode=control-group\nTimeoutStartSec=30s\nTimeoutStopSec=1s\nUser=0\nGroup=0\nLimitCORE=0\n"
                    "ExecStart=" + sys.executable + " -I " + str(ROOT / "tests/manager_queue_gate.py")
                    + " " + str(self.root / "ready.sock") + "\n"),
                "queue-" + variant: ("[Unit]\nRequires=" + gate + "\nAfter=" + gate
                    + "\n[Service]\nType=oneshot\nRemainAfterExit=yes\nRestart=no\n"
                    "TimeoutStartSec=30s\nTimeoutStopSec=1s\nExecStart=/usr/bin/true\n")}
            for suffix, fragment in fragments.items():
                path = paths[suffix]
                raw = ("# cpa-owned-fixture=" + path.name + "\n" + fragment).encode()
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                try:
                    self.assertEqual(os.write(fd, raw), len(raw))
                    os.fsync(fd)
                finally:
                    os.close(fd)
                self.assertEqual(owned_fragment(path), raw)
            command(self.systemctl, "daemon-reload")
            command(self.systemctl, "start", "--no-block", "--", gate)
            with self.listener.accept()[0] as peer:
                peer.settimeout(5.)
                pid, uid, gid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                self.assertEqual((uid, gid), (0, 0))
                raw, _, flags, _ = peer.recvmsg(1024)
                self.assertFalse(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                self.assertEqual(json.loads(raw), {"gate": pid})
                gate_row = self.observe(gate)
                self.assertEqual(gate_row["ActiveState"], "activating")
                # ExecStart is the main process even while a oneshot is activating.
                self.assertEqual(gate_row["MainPID"], str(pid))
                self.assertEqual(Path("/proc/%d/cgroup" % pid).read_text(), "0::" + gate_row["ControlGroup"] + "\n")
                pidfd = os.pidfd_open(pid, 0)
                self.addCleanup(os.close, pidfd)
                fragment = paths["gate-" + variant]
                binding = UnitBinding(gate, gate_row["InvocationID"], gate_row["ControlGroup"], str(fragment),
                                      digest(fragment.read_bytes()), digest(canonical(static_properties(gate_row))))
                witness = QueuedLaunchWitness(target=target, library=self.library,
                    library_sha256=self.library_sha256, units={"forward": binding},
                    deadline=self.deadline, clock=time.monotonic, check=self.current)
                self.addCleanup(witness.close)
                start = witness._call(witness.owner, MANAGER + ".Manager", "StartUnit", "ss", (target, "fail"), "o")[0]
                number = job_path(start)
                waiting = witness.jobs()[number]
                self.assertEqual(waiting[1:5], (target, "start", "waiting", start))
                executed = command(self.systemctl, "show", "--property=ExecMainStartTimestampMonotonic",
                                   "--value", "--", target).strip()
                self.assertEqual(executed, b"0")
                print(json.dumps({"queued_variant": variant, "waiting_job": waiting,
                                  "gate_main_pid": pid, "payload_executed_before_release": False}), flush=True)
                if variant == "fenced":
                    from host_recovery.broker_operations import OperationJournal
                    from host_recovery.job_cancellation import WaitingStartCancellation, record_names
                    target_row = self.observe(target)
                    target_binding = UnitBinding(target, "a" * 32, "/system.slice/" + target, str(paths["queue-fenced"]),
                        digest(paths["queue-fenced"].read_bytes()), digest(canonical(static_properties(target_row))))
                    # The queued target has not run. Its nonzero invocation pin
                    # here is synthetic, never a claim that one was observed.
                    cancel_session = self.session(target_binding)
                    state = self.root / "cancel-state"
                    state.mkdir(mode=0o700)
                    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                    self.addCleanup(os.close, fd)
                    now = time.monotonic()
                    original = dict(installation_id="synthetic", attempt_id="11111111-1111-4111-8111-111111111111",
                        intent_sha256="a" * 64, request_sha256="b" * 64, topology_sha256="c" * 64,
                        original_boot_id="boot-original", original_arm=now, failure_monotonic=now,
                        recovery_deadline=self.deadline)
                    generation = dict(boot_id="boot-original", broker_invocation_id="22222222-2222-4222-8222-222222222222",
                                      runtime_epoch="33333333-3333-4333-8333-333333333333")
                    journal = OperationJournal(fd, binding=original, epoch=generation, clock=time.monotonic,
                                               boot_id=lambda: "boot-original")
                    operation = journal.pending("contain_forward", target_sha256="d" * 64, deadline=self.deadline)
                    masks = self.publish_mask(target_binding)
                    canceler = WaitingStartCancellation(journal=journal, masks=masks, session=cancel_session)
                    # Real source cancellation/journal/transport; original request
                    # and authority remain synthetic. The independent fixture
                    # witness still requires the exact accepted start completion.
                    self.assertEqual(witness.jobs()[number], waiting)
                    receipt = canceler.cancel(operation=operation)
                    self.assertEqual(receipt["canceled_waiting_start_count"], 1)
                    self.assertFalse(receipt["manager_jobs_retired"])
                    completion = json.loads((state / record_names(operation["sequence"], "forward")[2]).read_bytes())
                    self.assertEqual((completion["job_id"], completion["job_path"], completion["result"]),
                                     (number, start, "canceled"))
                    print(json.dumps({"source_waiting_start_cancellation": receipt, "completion": completion}), flush=True)
                    cancel_session.close()
                    witness.completed(start, "canceled")
                    command(self.systemctl, "daemon-reload")
                    self.assertEqual(self.masked_observation(target)["LoadState"], "masked")
                    stop = witness._call(witness.owner, MANAGER + ".Manager", "StopUnit", "ss", (target, "fail"), "o")[0]
                    self.assertNotEqual(stop, start)
                    witness.completed(stop, "done")
                poller = select.poll()
                poller.register(pidfd, select.POLLIN)
                self.assertFalse(poller.poll(0), "dependency gate escaped before explicit release")
                peer.sendall(b"release")
                self.assertTrue(poller.poll(max(1, int((self.deadline - time.monotonic()) * 1000))))
                if variant == "control":
                    witness.completed(start, "done")
                else:
                    # Join only the gate's existing job. Never resubmit the target.
                    command(self.systemctl, "start", "--", gate)
                    gate_done = self.observe(gate)
                    self.assertEqual((gate_done["ActiveState"], gate_done["SubState"]), ("active", "exited"))
                    self.assertEqual(command(self.systemctl, "show", "--property=ExecMainStatus", "--value", "--", gate).strip(), b"0")
                self.current()
                executed = command(self.systemctl, "show", "--property=ExecMainStartTimestampMonotonic",
                                   "--value", "--", target).strip()
                if variant == "control":
                    self.assertGreater(int(executed), 0, "positive-control payload did not execute")
                else:
                    self.assertEqual(executed, b"0", "canceled payload executed after gate release")
                    final = self.masked_observation(target)
                    self.assertEqual((final["MainPID"], final["Job"], final["ActiveState"]), ("0", "0", "inactive"))
                self.assertNotIn(number, witness.jobs())
                print(json.dumps({"queued_variant": variant, "dependency_released": True,
                                  "payload_executed_after_release": int(executed) > 0,
                                  "complete_fence_proven": False, "pending_drained": False}), flush=True)
                witness.close()

    def test_masked_runtime_pair_then_recursive_slice_kill(self):
        from host_recovery.broker_operations import OperationJournal
        from host_recovery.broker_runtime import RuntimeDomain
        from host_recovery.manager_jobs import RuntimeStopJobs, completion_name
        from host_recovery.masked_runtime_stop import MaskedRuntimeStop
        from host_recovery.unit_masks import PersistentUnitMasks
        paths = runtime_paths()
        masks_paths = {role:Path("/etc/systemd/system") / paths[role].name for role in ("dockerd", "containerd")}
        self.assertTrue(all(not os.path.lexists(path) for path in (*paths.values(), *masks_paths.values())))
        self.addCleanup(cleanup_runtime)
        for role,path in paths.items():
            body = ("[Slice]\n" if role == "slice" else
                "[Service]\nType=exec\nRestart=no\nKillMode=control-group\nSendSIGKILL=yes\n"
                "TimeoutStopSec=5s\nRuntimeMaxSec=60s\nUser=0\nGroup=0\nLimitCORE=0\nSlice=" + paths["slice"].name
                + "\nExecStart=" + sys.executable + " -I " + str(ROOT / "tests/manager_system_fixture.py")
                + " " + str(self.root / "ready.sock") + "\n")
            raw = ("# cpa-owned-fixture=" + path.name + "\n" + body).encode()
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                self.assertEqual(os.write(fd, raw), len(raw))
                os.fsync(fd)
            finally:
                os.close(fd)
            self.assertEqual(owned_fragment(path), raw)
        command(self.systemctl, "daemon-reload")
        command(self.systemctl, "start", "--", paths["slice"].name)
        units, processes = {}, {}
        for role in ("dockerd", "containerd", "task"):
            command(self.systemctl, "start", "--", paths[role].name)
            unit,pids = self.running_binding(paths[role].name)
            processes[role] = pids
            if role != "task": units[role] = unit
        # The third inert fixture models a separate runtime-domain task. Neither
        # fixed StopUnit/KillUnit targets it: only the recursive slice write does.
        cgroup = command(self.systemctl, "show", "--property=ControlGroup", "--value", "--", paths["slice"].name).decode().strip()
        self.assertEqual(cgroup, "/system.slice/" + paths["slice"].name)
        fd = os.open("/sys/fs/cgroup" + cgroup, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        info = os.fstat(fd)
        domain = RuntimeDomain(fd=fd, mount_root="/sys/fs/cgroup", cgroup=cgroup, device=info.st_dev, inode=info.st_ino)
        self.assertTrue(domain.populated())
        state = self.root / "runtime-state"
        state.mkdir(mode=0o700)
        state_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, state_fd)
        now = time.monotonic()
        original = dict(installation_id="synthetic", attempt_id="11111111-1111-4111-8111-111111111111",
            intent_sha256="a"*64, request_sha256="b"*64, topology_sha256="c"*64,
            original_boot_id="boot-original", original_arm=now, failure_monotonic=now, recovery_deadline=self.deadline)
        generation = dict(boot_id="boot-original", broker_invocation_id="22222222-2222-4222-8222-222222222222",
                          runtime_epoch="33333333-3333-4333-8333-333333333333")
        # Original request, forward return, epoch and authority are synthetic.
        journal = OperationJournal(state_fd, binding=original, epoch=generation, clock=time.monotonic,
                                   boot_id=lambda:"boot-original")
        forward = journal.pending("contain_forward", target_sha256="e"*64, deadline=self.deadline)
        journal.returned(forward, result="returned")
        path = Path("/etc/systemd/system")
        info = path.stat()
        context = open_approved_directory(DirectoryApproval(str(path), info.st_dev, info.st_ino, 0, 0, 0o755))
        directory = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        masks = PersistentUnitMasks(directory=directory, units=units)
        def current():
            self.current()
            # Before the source recursive write, both third-fixture pidfds must
            # remain live, even after both fixed units have actually completed.
            if not sequence._domain_killed:
                for key in ("parent_fd", "child_fd"):
                    poller = select.poll()
                    poller.register(processes["task"][key], select.POLLIN)
                    self.assertFalse(poller.poll(0), "unaddressed task died before recursive slice kill")
        session = ManagerJobSession(library=self.library, library_sha256=self.library_sha256, units=units,
            deadline=self.deadline, clock=time.monotonic, check=self.current)
        self.addCleanup(session.close)
        busctl = shutil.which("busctl", path=os.defpath)
        self.assertIsNotNone(busctl)
        jobs = RuntimeStopJobs(journal=journal, units=units, busctl=busctl, busctl_sha256=digest(Path(busctl).read_bytes()),
            commands=None, read_helper_hash=lambda path:digest(Path(path).read_bytes()), session=session)
        sequence = MaskedRuntimeStop(journal=journal, masks=masks, jobs=jobs, domain=domain)
        # No manager/library boundary is mocked. Only the fixture's original
        # authority barrier additionally asserts the independent live-task witness.
        session.check = current
        operation = journal.pending("cold_quiesce_runtime", target_sha256=sequence.target_sha256, deadline=self.deadline)
        receipt = sequence.stop(operation=operation)
        self.assertTrue(receipt["recursive_domain_kill_returned"] and receipt["domain_empty_observed"])
        self.assertEqual(receipt["runtime_stop_completion_count"], 2)
        self.assertFalse(receipt["runtime_containment_coverage_proven"])
        self.assertFalse(receipt["pending_drained"] or receipt["complete_fence_proven"] or receipt["start_allowed"])
        self.assertNotIn("cold_quiesce_runtime", journal._returned)
        self.assertFalse(domain.populated())
        for role in ("dockerd", "containerd"):
            saved = json.loads((state/completion_name(2,role)).read_bytes())
            self.assertEqual((saved["unit"],saved["result"]), (units[role].unit,"done"))
            self.stopped(units[role], processes[role], observe=self.masked_observation)
            refused = subprocess.run((self.systemctl,"start","--",units[role].unit),
                env={"PATH":os.defpath,"LANG":"C"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15.)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(os.readlink(masks_paths[role]), "/dev/null")
        for key in ("parent_fd", "child_fd"):
            poller = select.poll()
            poller.register(processes["task"][key], select.POLLIN)
            self.assertTrue(poller.poll(max(1,int((self.deadline-time.monotonic())*1000))))
        print(json.dumps({"source_masked_runtime_sequence":receipt, "inert_task_pidfds_dead":True,
                          "populated":False, "actual_daemon_or_shim_coverage":False}), flush=True)

    def test_actual_stop_kills_term_ignoring_parent_and_descendant(self):
        binding, pids = self.fixture("active")
        self.stop_and_witness(binding)
        self.stopped(binding, pids)

    def test_actual_inactive_stop_still_requires_its_own_completion(self):
        binding, pids = self.fixture("inactive")
        command(self.systemctl, "stop", "--", binding.unit)
        self.stopped(binding, pids)
        self.stop_and_witness(binding)
        self.stopped(binding, pids)


if __name__ == "__main__":
    if not ENABLED:
        raise SystemExit("system-manager tests require explicit disposable GitHub-hosted Actions context")
    if sys.argv[1:] == ["--cleanup"]:
        if os.geteuid() != 0 or Path("/proc/1/comm").read_text().strip() != "systemd":
            raise SystemExit("disposable root system-manager required")
        cleanup_units("active", "inactive")
        cleanup_activation()
        cleanup_activation(queued=True)
        cleanup_runtime()
    else:
        unittest.main(verbosity=2)
