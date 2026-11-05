"""Actions-only real system-manager stop/completion and descendant evidence.

Unlike the private-bus matrix, neither the bus address, manager credentials nor
native transport is patched. Test-local library pins and owned fixture units
are NOT independently approved production provisioning, complete activation
exclusion, daemon/shim containment, a cold runtime barrier or recovery acceptance.
"""
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
from host_recovery.manager_bus import ManagerJobSession
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
    if suffix not in ("active", "inactive", "masked", "dependent"):
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


def activation_paths():
    return {suffix: Path("/run/systemd/system") / unit_name(suffix)
            for suffix in ("masked", "dependent")}


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


def cleanup_activation():
    systemctl = shutil.which("systemctl", path=os.defpath)
    paths = activation_paths()
    mask = Path("/etc/systemd/system") / unit_name("masked")
    if os.path.lexists(mask):
        info = mask.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or os.readlink(mask) != "/dev/null":
            raise AssertionError("owned activation mask unconfirmed")
    for path in paths.values():
        if os.path.lexists(path):
            owned_fragment(path)
    for suffix in ("dependent", "masked"):
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

    def test_persistent_mask_blocks_fresh_launches_but_does_not_quiesce(self):
        paths = activation_paths()
        mask = Path("/etc/systemd/system") / unit_name("masked")
        self.assertFalse(os.path.lexists(mask))
        self.assertTrue(all(not os.path.lexists(path) for path in paths.values()))
        self.addCleanup(cleanup_activation)
        fragments = {
            "masked": ("[Service]\nType=exec\nRestart=no\nKillMode=control-group\n"
                "SendSIGKILL=yes\nTimeoutStopSec=1s\nRuntimeMaxSec=60s\nUser=0\nGroup=0\nLimitCORE=0\n"
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
        # The /etc mask has higher load-path precedence than this /run fragment.
        # O_EXCL symlink creation (without force/overwrite) preserves collisions.
        os.symlink("/dev/null", mask)
        fd = os.open(mask.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        command(self.systemctl, "daemon-reload")
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
        # A separate authenticated stop/completion, explicit whole-unit kill and
        # pidfd deaths are required. Mask presence cannot supply any of them.
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
    else:
        unittest.main(verbosity=2)
