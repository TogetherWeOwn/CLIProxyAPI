"""Protected worker-report readback around an independent result oracle.

The supervisor authenticates the original request/claim and retains its lock.
This reader corroborates only the report's exact bytes and linkage, not the
reported filesystem, runtime, readiness, timings or durability. Those facts must
still be independently observed. No runner, start or settlement is enabled here.
"""
import copy
from contextlib import contextmanager
import math
import os
import stat

from .commands import Deadline
from .coordinator import validate_baseline_receipt
from .durable import Rejected, canonical, decode, digest, signature
from .installation import DirectoryApproval, open_approved_directory
from .journal import validate_intent
from .loading import pin
from .outcomes import expected_oracle
from .protected_file import ProtectedFile


class WorkerEvidenceOracle:
    """Retain an approved report inode through supervisor observation persistence.

    directory is independently provisioned for the worker's private evidence,
    with explicit verifier read access. It is never learned from a worker path.
    check must revalidate the live original owner, lock, inputs and complete fence.
    oracle must independently inspect current baseline/image/replay/plugin/fence/
    readiness, not reuse this report's stopped receipt or timing assertions.

    RecoverySupervisor uses observe as a context so final byte/identity checks
    follow its own observation-record fsync. A visible record after failed final
    checks is not verified and cannot be reused on restart. Direct calls provide
    only a point observation. Either mode is once-only, including on uncertainty.
    """
    def __init__(self, *, directory, oracle, check, clock):
        if (not isinstance(directory, DirectoryApproval) or directory.mode != 0o700
                or not all(callable(value) for value in (oracle, check, clock))):
            raise Rejected("result-report-explicit-boundaries-required")
        self.directory, self.oracle, self.check, self.clock = directory, oracle, check, clock
        self.attempted, self.failed = False, False

    @staticmethod
    def _report(raw, intent, result):
        report = decode(raw)
        fields = {"schema", "request_id", "intent_sha256", "claim_sha256", "status", "stopped_receipt",
                  "timing_events", "worker_report_only", "start_permission", "recovery_completed", "installation_settled"}
        if (set(report) != fields or report["schema"] != "host-recovery-worker-evidence-v1"
                or any(report[key] != result[key] for key in ("request_id", "intent_sha256", "claim_sha256"))
                or report["worker_report_only"] is not True
                or any(report[key] is not False for key in ("start_permission", "recovery_completed", "installation_settled"))
                or canonical(report) != raw or digest(raw) != result["evidence_sha256"]):
            raise Rejected("result-report-linkage-unconfirmed")
        status = report["status"]
        if (type(status) is not dict or set(status) != {"outcome", "recovery_error", "alert_error", "evidence_error",
                "start_fenced", "installation_settled", "production_acceptance", "alert"}
                or status["outcome"] != "baseline_restored"
                or any(status[key] is not None for key in ("recovery_error", "alert_error", "evidence_error"))
                or status["start_fenced"] is not True or status["installation_settled"] is not False
                or status["production_acceptance"] is not False):
            raise Rejected("result-report-outcome-unconfirmed")
        alert = status["alert"]
        if (type(alert) is not dict or set(alert) != {"receipt_persisted", "transport_delivered", "human_acknowledged",
                "receipt_error", "transport_error"}
                or type(alert["receipt_persisted"]) is not bool or alert["transport_delivered"] is not True
                or alert["human_acknowledged"] is not False or alert["transport_error"] is not None
                or alert["receipt_error"] != (None if alert["receipt_persisted"] else "alert-persistence-failed")):
            raise Rejected("result-report-alert-unconfirmed")
        # These are historical worker assertions, never fresh oracle inputs.
        validate_baseline_receipt(intent, report["stopped_receipt"])
        if type(report["timing_events"]) is not list or not 1 <= len(report["timing_events"]) <= 64:
            raise Rejected("result-report-timing-bounds")

    @contextmanager
    def observe(self, intent, result, *, deadline):
        if self.attempted:
            self.failed = True
            raise Rejected("result-report-once-only")
        self.attempted = True
        directory, oracle, check, clock = self.directory, self.oracle, self.check, self.clock
        value, saved = copy.deepcopy(intent), copy.deepcopy(result)
        original_intent, original_result = canonical(value), canonical(saved)
        last = None
        file = None
        try:
            validate_intent(value)
            fields = {"schema", "request_id", "intent_sha256", "claim_sha256", "outcome", "evidence_sha256"}
            if (type(saved) is not dict or set(saved) != fields or saved["schema"] != "host-recovery-worker-result-v1"
                    or saved["outcome"] != "baseline_restored" or saved["intent_sha256"] != digest(original_intent)):
                raise Rejected("result-report-original-result-required")
            for key in ("request_id", "intent_sha256", "claim_sha256", "evidence_sha256"):
                pin(saved[key])

            def bound():
                if (self.failed or self.directory != directory or self.oracle is not oracle
                        or self.check is not check or self.clock is not clock
                        or canonical(intent) != original_intent or canonical(result) != original_result):
                    raise Rejected("result-report-boundary-changed")

            def now():
                nonlocal last
                bound()
                instant = clock()
                bound()
                if (type(instant) not in (int, float) or not math.isfinite(instant)
                        or last is not None and instant < last):
                    raise Rejected("result-report-clock-discontinuity")
                last = instant
                return instant

            timer = Deadline(now, deadline)

            def current():
                try:
                    timer.remaining()
                    if check(deadline=deadline) is not True:
                        raise Rejected("result-report-live-boundary-unconfirmed")
                    bound()
                    timer.remaining()
                except BaseException:
                    self.failed = True
                    raise

            current()
            with open_approved_directory(directory) as root:
                name = "worker-evidence-" + saved["request_id"] + ".json"
                if ".stage-" + name in os.listdir(root.fd):
                    raise Rejected("result-report-staged-evidence")
                file = ProtectedFile(root, name, uid=directory.uid, gid=directory.gid,
                                     limit=65536, current=current)
                if stat.S_IMODE(file.info.st_mode) != 0o600:
                    raise Rejected("result-report-private-file-required")
                raw = b"".join(file.blocks())
                self._report(raw, value, saved)

                def revalidate():
                    file.validate()
                    current()
                    # No caller callback follows the final raw read. Even the last
                    # clock/fence callback may mutate an already-hashed inode.
                    root.validate()
                    if (".stage-" + name in os.listdir(root.fd)
                            or signature(os.fstat(file.fd)) != signature(file.info)
                            or os.pread(file.fd, file.info.st_size, 0) != raw
                            or signature(os.fstat(file.fd)) != signature(file.info)
                            or signature(os.stat(name, dir_fd=root.fd, follow_symlinks=False)) != signature(file.info)):
                        raise Rejected("result-report-bytes-or-identity-changed")
                    root.validate()

                revalidate()
                observed_intent, observed_result = copy.deepcopy(value), copy.deepcopy(saved)
                receipt = copy.deepcopy(oracle(observed_intent, observed_result, deadline=deadline))
                if (canonical(observed_intent) != original_intent or canonical(observed_result) != original_result
                        or canonical(receipt) != canonical(expected_oracle(value, saved))):
                    raise Rejected("result-report-independent-oracle-unconfirmed")
                revalidate()
                yield copy.deepcopy(receipt)
                revalidate()
        except BaseException:
            self.failed = True
            raise Rejected("result-report-observation-unconfirmed") from None
        finally:
            if file is not None:
                file.close()

    def __call__(self, intent, result, *, deadline):
        with self.observe(intent, result, deadline=deadline) as receipt:
            return receipt
