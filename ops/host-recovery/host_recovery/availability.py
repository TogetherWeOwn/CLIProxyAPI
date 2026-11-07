"""Durable raw availability observations, not continuous uptime/downtime proof.

The caller supplies an approved probe and private evidence directory. No network,
credentials, schedule, live endpoint or timeout is supplied here. A probe must be
bounded by its independently enforced execution boundary. Point samples cannot
prove uninterrupted availability or a continuous outage between observations.
"""
import copy
import os
import stat

from .budget import positive
from .durable import Rejected, atomic_write, canonical, decode, digest, read_file
from .journal import identity
from .loading import pin

NAME = "availability.json"
MAX_SAMPLES = 4096
OUTCOMES = frozenset(("available", "unavailable", "unknown"))


def validate_trace(value):
    fields = {"schema", "attempt_id", "probe_revision", "target_sha256", "boot_id",
              "window_start", "window_end", "samples", "production_acceptance"}
    if (type(value) is not dict or set(value) != fields
            or value["schema"] != "host-recovery-availability-v1"
            or not identity(value["attempt_id"]) or not identity(value["boot_id"])
            or value["production_acceptance"] is not False
            or not positive(value["window_start"])
            or type(value["samples"]) is not list or len(value["samples"]) > MAX_SAMPLES):
        raise Rejected("availability-trace-schema")
    pin(value["probe_revision"])
    pin(value["target_sha256"])
    previous = value["window_start"]
    for sequence, sample in enumerate(value["samples"], 1):
        if (type(sample) is not dict or set(sample) != {"sequence", "start", "end", "outcome"}
                or type(sample["sequence"]) is not int or sample["sequence"] != sequence
                or not positive(sample["start"]) or not positive(sample["end"])
                or sample["start"] < previous or sample["end"] < sample["start"]
                or type(sample["outcome"]) is not str or sample["outcome"] not in OUTCOMES):
            raise Rejected("availability-sample-schema")
        previous = sample["end"]
    end = value["window_end"]
    if end is not None and (not positive(end) or end < previous):
        raise Rejected("availability-window-schema")


def summarize(raw):
    """Describe samples, never promote a streak into measured continuous downtime.

    Brackets are observation windows, not outage-duration confidence bounds. Even
    two available samples may hide an outage. Unknown observations break negative
    streaks; they are not silently counted as healthy or as observed failures.
    A persisted closed file alone is not proof that its final fsync succeeded.
    """
    value = decode(raw)
    validate_trace(value)
    samples = value["samples"]
    runs, active, previous_available = [], None, None
    for sample in samples:
        if sample["outcome"] == "unavailable":
            if active is None:
                active = {"first_sequence": sample["sequence"], "last_sequence": sample["sequence"],
                          "first_failed_observation": sample["end"], "last_failed_observation": sample["end"],
                          "preceding_available_observation": previous_available,
                          "following_available_observation": None,
                          "left_censored": previous_available is None, "right_censored": True,
                          "outage_seconds_lower_bound": 0, "outage_seconds_upper_bound": None}
                runs.append(active)
            active["last_sequence"] = sample["sequence"]
            active["last_failed_observation"] = sample["end"]
        elif sample["outcome"] == "available":
            if active is not None:
                active["following_available_observation"] = sample["end"]
                active["right_censored"] = False
                active = None
            previous_available = sample["end"]
        else:
            # An unknown probe cannot bridge two independently observed streaks.
            active, previous_available = None, None
    gaps, previous = [], value["window_start"]
    for sample in samples:
        gaps.append(sample["start"] - previous)
        previous = sample["end"]
    if value["window_end"] is not None:
        gaps.append(value["window_end"] - previous)
    counts = {outcome: sum(sample["outcome"] == outcome for sample in samples) for outcome in sorted(OUTCOMES)}
    return {"schema": "host-recovery-availability-summary-v1", "trace_sha256": digest(raw),
            "attempt_id": value["attempt_id"], "boot_id": value["boot_id"],
            "window_start": value["window_start"], "window_end": value["window_end"],
            "counts": counts, "unavailable_sample_runs": runs,
            "maximum_probe_seconds": max((row["end"] - row["start"] for row in samples), default=None),
            "maximum_unsampled_gap_seconds": max(gaps, default=None),
            "sampling_window_closed": value["window_end"] is not None,
            "unsampled_tail_unbounded": value["window_end"] is None,
            "continuous_coverage_proven": False, "continuous_downtime_seconds": None,
            "production_acceptance": False}


class AvailabilityRecorder:
    """One explicitly owned evidence directory; never the installation journal.

    Callers retain the fd and exclude competing writers through their independent
    evidence-ownership boundary. The same descriptor must remain open throughout.
    Failed/ambiguous persistence or clock/boot continuity permanently revokes this
    instance. A visible completed file is not a successful completion receipt.
    This component does not meter recovery or enforce a wedged probe's deadline.
    """
    def __init__(self, fd, *, attempt_id, probe_revision, target_sha256, clock, boot_id, fault=None):
        self.fd, self.clock, self.boot_id, self.fault = fd, clock, boot_id, fault
        self.failed, self.closed, self.busy = False, False, False
        self.saved, self.last = None, None
        st = os.fstat(fd)
        if (not stat.S_ISDIR(st.st_mode) or (st.st_uid, st.st_gid) != (os.geteuid(), os.getegid())
                or stat.S_IMODE(st.st_mode) != 0o700 or os.listxattr(fd) or os.listdir(fd)
                or not callable(clock) or not callable(boot_id)):
            raise Rejected("availability-empty-private-root-required")
        self.root = (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode))
        self.boot = boot_id()
        self.value = {"schema": "host-recovery-availability-v1", "attempt_id": attempt_id,
                      "probe_revision": probe_revision, "target_sha256": target_sha256,
                      "boot_id": self.boot, "window_start": self._now(), "window_end": None,
                      "samples": [], "production_acceptance": False}
        validate_trace(self.value)
        self._save()

    def _now(self):
        now = self.clock()
        if (not positive(now) or self.last is not None and now < self.last or self.boot_id() != self.boot):
            raise Rejected("availability-clock-continuity-lost")
        self.last = now
        return now

    def _current(self):
        st = os.fstat(self.fd)
        if ((st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != self.root
                or os.listxattr(self.fd) or set(os.listdir(self.fd)) != {NAME}):
            raise Rejected("availability-root-changed")
        raw, info = read_file(self.fd, NAME)
        if ((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (self.root[2], self.root[3], 0o600)
                or info.st_dev != self.root[0] or raw != self.saved or canonical(self.value) != self.saved):
            raise Rejected("availability-saved-trace-changed")

    def _save(self):
        validate_trace(self.value)
        raw = canonical(self.value)
        atomic_write(self.fd, NAME, raw, fault=self.fault)
        self.saved = raw
        self._current()
        # A successful filesystem readback cannot hide a reboot or clock loss
        # during persistence. Recheck bytes after the external clock/boot reads.
        self._now()
        self._current()

    def _available(self):
        if self.failed or self.closed or self.busy:
            raise Rejected("availability-recorder-unavailable")
        self._current()

    def observe(self, probe):
        """Capture one strict True/False/None observation; exceptions mean unknown.

        Probe exception strings and return payloads are never retained. Invalid
        non-boolean results are unknown, not truthy successes. Reentrant use is
        refused and invalidates the outer observation rather than recording it.
        """
        try:
            self._available()
            if not callable(probe) or len(self.value["samples"]) >= MAX_SAMPLES:
                raise Rejected("availability-probe-or-sample-limit")
            self.busy = True
            start = self._now()
            self._current()
            try:
                result = probe()
            except Exception:
                result = None
            end = self._now()
            if self.failed:
                raise Rejected("availability-recorder-unavailable")
            self._current()
            outcome = "available" if result is True else "unavailable" if result is False else "unknown"
            sample = {"sequence": len(self.value["samples"]) + 1, "start": start, "end": end, "outcome": outcome}
            self.value["samples"].append(sample)
            self._save()
            return copy.deepcopy(sample)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def finish(self):
        try:
            self._available()
            end = self._now()
            self._current()
            self.value["window_end"] = end
            self._save()
            self.closed = True
            return {"schema": "host-recovery-availability-receipt-v1", "trace_sha256": digest(self.saved),
                    "sampling_window_closed": True, "production_acceptance": False}
        except BaseException:
            self.failed = True
            raise
