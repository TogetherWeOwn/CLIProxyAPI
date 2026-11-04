"""Strict producer-prefix inspection, deliberately NOT replay-evidence acceptance.

Aligned with the inspected producer startup/decision v1 shapes. A failure marker
is always rejected; its pending schema need not be guessed to reject it. This
standalone-NDJSON component has no log demultiplexer, HTTP probe, container binding
or producer completion oracle. No amount of green input can set replay_accepted.
"""
from dataclasses import dataclass
from datetime import datetime
import copy
import os
import re
import stat
import uuid

from .durable import MAX_FILE_BYTES, Rejected, decode, digest, read_file
from .journal import identity

PARSER_VERSION = "replay-prefix-parser-v1"
MAX_RECORD_BYTES = 4095
MAX_RECORDS = 1024
MAX_SOURCES = 16
UINT64_MAX = (1 << 64) - 1
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/()+-]{0,255}\Z")
STAMP = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d{1,9})?Z\Z", re.ASCII)
COMMON = frozenset(("schema", "producer_instance_id", "event_id", "timestamp"))
STARTUP = COMMON | {"producer_version", "source_revision", "source_modified", "sources", "file_logging"}
CORRELATION = frozenset(("attempt_id", "probe_id", "request_id", "parent_request_id", "turn"))
DECISION = COMMON | CORRELATION | {"requested_model", "resolved_model", "replay_attempt", "replay_enabled",
                                   "kept", "dropped_foreign", "dropped_untagged"}
OBLIGATIONS = ("producer-drain-boundary", "real-container-source-binding", "all-required-source-coverage",
               "successful-tool-linked-http-turns", "source-artifact-binding")


def instance(value):
    try:
        parsed = uuid.UUID(value)
        return parsed.version == 4 and str(parsed) == value
    except (ValueError, TypeError, AttributeError):
        return False


def model(value):
    return type(value) is str and MODEL.fullmatch(value) is not None


def integer(value, allowed=None):
    return type(value) is int and 0 <= value <= UINT64_MAX and (allowed is None or value in allowed)


def record(raw):
    """Validate actual JSON tokens and cross-field identity; never regex counters."""
    if (type(raw) is not bytes or not raw or len(raw) > MAX_RECORD_BYTES
            or not raw.isascii() or b"\r" in raw or b"\n" in raw):
        raise Rejected("replay-record-size-or-encoding")
    value = decode(raw)
    schema = value.get("schema")
    if schema == "replay-producer-failure-v1":
        raise Rejected("replay-producer-failure-marker")
    if schema not in ("replay-producer-startup-v1", "replay-event-v1"):
        raise Rejected("replay-unknown-schema")
    if set(value) != (STARTUP if schema == "replay-producer-startup-v1" else DECISION):
        raise Rejected("replay-record-fields")
    producer = value["producer_instance_id"]
    if not instance(producer) or type(value["event_id"]) is not str:
        raise Rejected("replay-record-identity")
    prefix, sep, sequence = value["event_id"].rpartition(":")
    if (prefix != producer or not sep or re.fullmatch(r"[1-9][0-9]{0,19}", sequence) is None
            or int(sequence) > UINT64_MAX):
        raise Rejected("replay-record-sequence")
    stamp = value["timestamp"]
    match = STAMP.fullmatch(stamp) if type(stamp) is str and len(stamp) <= 30 else None
    if match is None:
        raise Rejected("replay-record-timestamp")
    try:
        datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise Rejected("replay-record-timestamp") from None
    if schema == "replay-producer-startup-v1":
        if (int(sequence) != 1 or type(value["producer_version"]) is not str
                or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["producer_version"]) is None
                or type(value["source_revision"]) is not str
                or re.fullmatch(r"(?:[0-9a-fA-F]{40})?", value["source_revision"]) is None
                or type(value["source_modified"]) is not bool
                or value["sources"] != ["stdout"] or value["file_logging"] != "not_configured"):
            raise Rejected("replay-startup-schema")
    else:
        if (not all(identity(value[k]) for k in ("attempt_id", "probe_id", "request_id"))
                or not integer(value["turn"], (1, 2))
                or (value["turn"] == 1 and value["parent_request_id"] != "")
                or (value["turn"] == 2 and (not identity(value["parent_request_id"])
                                           or value["parent_request_id"] == value["request_id"]))):
            raise Rejected("replay-correlation-schema")
        if (not all(model(value[k]) for k in ("requested_model", "resolved_model"))
                or not integer(value["replay_attempt"], (0, 1))
                or type(value["replay_enabled"]) is not bool
                or not all(integer(value[k]) for k in ("kept", "dropped_foreign", "dropped_untagged"))
                or (value["replay_attempt"] == 1 and (value["kept"] != 0 or value["replay_enabled"] is not True))):
            raise Rejected("replay-decision-schema")
    return value, int(sequence)


@dataclass(frozen=True)
class ProbeExpectation:
    """Comparison input, not proof that a probe/request/container really exists."""
    producer_instance_id: str
    attempt_id: str
    probe_id: str
    request1: str
    request2: str
    requested_model: str
    resolved_model: str

    def __post_init__(self):
        if (not instance(self.producer_instance_id)
                or not all(identity(v) for v in (self.attempt_id, self.probe_id, self.request1, self.request2))
                or self.request1 == self.request2 or not model(self.requested_model) or not model(self.resolved_model)):
            raise Rejected("replay-probe-expectation")


def inspect_prefix(sources, expectation):
    """Inspect bounded full NDJSON prefixes, including explicitly empty mirrors.

    Sources is an exact source-id -> raw-bytes map supplied by a collector, not
    a claim that all required sources were opened. Each nonempty source must start
    with startup and contain an ordered contiguous prefix. Identical mirrored
    records deduplicate; conflicts, partial records and all failure markers reject.
    A contiguous sequence proves only the admitted/emitted prefix, never drain.
    """
    if (type(sources) is not dict or not 1 <= len(sources) <= MAX_SOURCES
            or not isinstance(expectation, ProbeExpectation)):
        raise Rejected("replay-prefix-input")
    seen, receipts = {}, []
    total_bytes, total_records = 0, 0
    for source_id, raw in sources.items():
        if not identity(source_id) or type(raw) is not bytes:
            raise Rejected("replay-source-shape")
        total_bytes += len(raw)
        if total_bytes > MAX_FILE_BYTES:
            raise Rejected("replay-collection-overflow")
        if raw and not raw.endswith(b"\n"):
            raise Rejected("replay-partial-record")
        offset, next_sequence = 0, 1
        for line in raw.split(b"\n")[:-1]:
            total_records += 1
            if total_records > MAX_RECORDS:
                raise Rejected("replay-record-overflow")
            value, sequence = record(line)
            if value["producer_instance_id"] != expectation.producer_instance_id:
                raise Rejected("replay-wrong-producer")
            if sequence != next_sequence or (sequence == 1) != (value["schema"] == "replay-producer-startup-v1"):
                raise Rejected("replay-source-gap-or-order")
            next_sequence += 1
            event_id = value["event_id"]
            if event_id in seen and seen[event_id][0] != line:
                raise Rejected("replay-conflicting-duplicate")
            if event_id not in seen:
                seen[event_id] = (line, value)
            offset += len(line) + 1
        receipts.append({"source_id": source_id, "start_offset": 0, "end_offset": offset,
                         "raw_sha256": digest(raw), "empty": not raw, "coverage": "prefix_only"})
    matching = []
    initial = set()
    retries = set()
    for _, value in sorted(seen.values(), key=lambda item: int(item[1]["event_id"].rpartition(":")[2])):
        if value["schema"] != "replay-event-v1":
            continue
        if (value["attempt_id"], value["probe_id"]) != (expectation.attempt_id, expectation.probe_id):
            continue  # Unrelated events stay in raw evidence, never get relabeled.
        if value["dropped_foreign"] != 0:
            raise Rejected("replay-correlated-foreign-drop")
        expected_request = expectation.request1 if value["turn"] == 1 else expectation.request2
        expected_parent = "" if value["turn"] == 1 else expectation.request1
        if (value["request_id"] != expected_request or value["parent_request_id"] != expected_parent
                or value["requested_model"] != expectation.requested_model
                or value["resolved_model"] != expectation.resolved_model):
            raise Rejected("replay-correlated-mapping-conflict")
        turn = value["turn"]
        if value["replay_attempt"] == 0:
            if turn in initial:
                raise Rejected("replay-ambiguous-initial-decision")
            initial.add(turn)
        else:
            if turn not in initial or turn in retries:
                raise Rejected("replay-unexpected-retry")
            retries.add(turn)
        matching.append(value)
    if initial != {1, 2}:
        raise Rejected("replay-missing-initial-decisions")
    if not any(v["turn"] == 2 and v["kept"] >= 1 and v["replay_enabled"] for v in matching):
        raise Rejected("replay-kept-evidence-missing")
    return {"schema": "replay-prefix-report-v1", "parser_version": PARSER_VERSION,
            "unique_records": len(seen), "matching_decisions": len(matching), "sources": receipts,
            "observed_retry_turns": sorted(retries), "collection_complete": False,
            "producer_drained": False, "replay_accepted": False, "production_acceptance": False,
            "missing_obligations": list(OBLIGATIONS)}


def inspect_spooled_prefix(spool_fd, receipts, expected_sources, expectation):
    """Verify restricted raw artifacts against capture receipts, then inspect.

    expected_sources must come from the eventual authenticated manifest; merely
    supplying this list is not its authentication or complete source coverage.
    Raw file handles/offsets are observed by FileCapture, not producer fields.
    This function cannot promote a prefix receipt to complete replay evidence.
    """
    private = os.fstat(spool_fd)
    if (not stat.S_ISDIR(private.st_mode) or private.st_uid != os.geteuid()
            or stat.S_IMODE(private.st_mode) != 0o700):
        raise Rejected("private-collection-spool-required")
    if (type(expected_sources) is not list or not 1 <= len(expected_sources) <= MAX_SOURCES
            or any(not identity(v) for v in expected_sources) or len(set(expected_sources)) != len(expected_sources)
            or type(receipts) is not list or len(receipts) != len(expected_sources)):
        raise Rejected("replay-required-sources")
    fields = {"schema", "source_id", "device", "inode", "start_offset", "end_offset", "previous_end_offset",
              "raw_sha256", "raw_handle", "empty", "coverage", "producer_drained"}
    sources, total = {}, 0
    for item in receipts:
        if type(item) is not dict or set(item) != fields:
            raise Rejected("replay-capture-receipt-schema")
        source_id = item["source_id"]
        if (not identity(source_id) or source_id not in expected_sources or source_id in sources
                or item["schema"] != "replay-source-prefix-v1" or item["coverage"] != "prefix_only"
                or item["producer_drained"] is not False or type(item["empty"]) is not bool
                or any(not integer(item[k]) for k in ("device", "inode", "start_offset", "end_offset", "previous_end_offset"))
                or item["inode"] == 0 or item["start_offset"] != 0
                or not 0 <= item["previous_end_offset"] <= item["end_offset"] <= MAX_FILE_BYTES
                or type(item["raw_handle"]) is not str
                or re.fullmatch(r"prefix-[0-9a-f]{32}\.raw", item["raw_handle"]) is None):
            raise Rejected("replay-capture-receipt-values")
        try:
            raw, st = read_file(spool_fd, item["raw_handle"])
        except OSError:
            raise Rejected("replay-capture-raw-unavailable") from None
        total += len(raw)
        if (total > MAX_FILE_BYTES or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600
                or digest(raw) != item["raw_sha256"] or len(raw) != item["end_offset"]
                or (not raw) != item["empty"]):
            raise Rejected("replay-capture-raw-mismatch")
        sources[source_id] = raw
    report = inspect_prefix(sources, expectation)
    report["capture_receipts"] = copy.deepcopy(receipts)
    return report
