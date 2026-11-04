import copy
import hashlib
import json
from pathlib import Path
import unittest

from host_recovery.durable import Rejected
from host_recovery.replay import ProbeExpectation, inspect_prefix, record

PRODUCER = "f55c9c69-323a-406f-bd1c-eeb68474d092"
FIXTURE = Path(__file__).parent / "fixtures" / "producer-prefix-b6f95237.ndjson"
EXPECT = ProbeExpectation(PRODUCER, "attempt-1", "probe-1", "request-1", "request-2",
                          "public-model-alias(high)", "muse-spark-1.3")


def records():
    return [json.loads(line) for line in FIXTURE.read_bytes().splitlines()]


def wire(values):
    return b"".join(json.dumps(v, separators=(",", ":")).encode("ascii") + b"\n" for v in values)


def inspect(values):
    return inspect_prefix({"stdout": wire(values)}, EXPECT)


def retry(values):
    value = copy.deepcopy(values[-1])
    value.update(event_id=PRODUCER + ":4", replay_attempt=1, kept=0)
    return value


class ReplayPrefixTests(unittest.TestCase):
    def test_actual_producer_fixture_is_immutable_and_never_accepted(self):
        raw = FIXTURE.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "065998f1e02cdc4b0bf8dadfedd4afacd496d43037ac5f807f1f6a0450c47af2")
        result = inspect_prefix({"stdout": raw}, EXPECT)
        self.assertEqual(result["matching_decisions"], 2)
        self.assertFalse(result["replay_accepted"])
        self.assertFalse(result["collection_complete"])
        self.assertFalse(result["producer_drained"])
        self.assertFalse(result["production_acceptance"])
        self.assertIn("producer-drain-boundary", result["missing_obligations"])
        self.assertIn("source-artifact-binding", result["missing_obligations"])

    def test_identical_mirror_deduplicates_with_raw_hashes_and_offsets(self):
        raw = FIXTURE.read_bytes()
        result = inspect_prefix({"stdout": raw, "external-mirror": raw, "empty-mirror": b""}, EXPECT)
        self.assertEqual(result["unique_records"], 3)
        self.assertEqual(result["matching_decisions"], 2)
        self.assertEqual(len(result["sources"]), 3)
        self.assertEqual(result["sources"][0]["end_offset"], len(raw))
        self.assertEqual(result["sources"][0]["raw_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertTrue(result["sources"][2]["empty"])
        self.assertEqual(result["sources"][2]["end_offset"], 0)
        self.assertEqual(result["sources"][2]["coverage"], "prefix_only")

    def test_shorter_mirror_is_still_only_a_prefix(self):
        values = records()
        result = inspect_prefix({"stdout": wire(values), "mirror": wire(values[:2])}, EXPECT)
        self.assertFalse(result["collection_complete"])
        self.assertEqual(result["unique_records"], 3)

    def test_failure_marker_after_good_turns_always_rejects(self):
        values = records() + [{"schema": "replay-producer-failure-v1", "reason": "queue_overflow"}]
        with self.assertRaisesRegex(Rejected, "producer-failure-marker"):
            inspect(values)

    def test_failure_marker_in_another_source_always_rejects(self):
        values = records()
        with self.assertRaises(Rejected):
            inspect_prefix({"stdout": wire(values), "mirror": wire(values + [
                {"schema": "replay-producer-failure-v1"}])}, EXPECT)

    def test_missing_failure_marker_cannot_prove_drain(self):
        result = inspect(records() + [retry(records())])
        self.assertEqual(result["observed_retry_turns"], [2])
        self.assertFalse(result["producer_drained"])
        self.assertFalse(result["replay_accepted"])

    def test_foreign_drop_cannot_be_overridden_by_retry(self):
        values = records()
        values[2]["dropped_foreign"] = 1
        values.append(retry(records()))
        with self.assertRaisesRegex(Rejected, "correlated-foreign-drop"):
            inspect(values)

    def test_foreign_drop_in_first_turn_also_rejects(self):
        values = records()
        values[1]["dropped_foreign"] = 1
        with self.assertRaisesRegex(Rejected, "correlated-foreign-drop"):
            inspect(values)

    def test_conflicting_duplicates_reject_even_when_one_source_is_green(self):
        values = records()
        bad = copy.deepcopy(values)
        bad[2]["dropped_foreign"] = 1
        with self.assertRaisesRegex(Rejected, "conflicting-duplicate"):
            inspect_prefix({"stdout": wire(values), "mirror": wire(bad)}, EXPECT)

    def test_byte_different_duplicate_is_not_silently_canonicalized(self):
        raw = wire(records())
        spaced = b"".join(json.dumps(v).encode() + b"\n" for v in records())
        with self.assertRaisesRegex(Rejected, "conflicting-duplicate"):
            inspect_prefix({"stdout": raw, "mirror": spaced}, EXPECT)

    def test_partial_last_line_rejects(self):
        with self.assertRaisesRegex(Rejected, "partial-record"):
            inspect_prefix({"stdout": wire(records())[:-1]}, EXPECT)

    def test_prefix_without_startup_or_with_gap_rejects(self):
        for values in (records()[1:], [records()[0], records()[2]], list(reversed(records()))):
            with self.subTest(values=values), self.assertRaisesRegex(Rejected, "gap-or-order"):
                inspect(values)

    def test_unknown_schema_or_fields_reject(self):
        for key, value in (("schema", "replay-event-v2"), ("extra", "not-allowed")):
            values = records()
            values[2][key] = value
            with self.subTest(key=key), self.assertRaises(Rejected):
                inspect(values)

    def test_strict_nonnegative_counter_tokens(self):
        for bad in (True, False, 0.0, "0", "01", -1, None, 1 << 64):
            for field in ("kept", "dropped_foreign", "dropped_untagged"):
                values = records()
                values[2][field] = bad
                with self.subTest(bad=bad, field=field), self.assertRaises(Rejected):
                    inspect(values)

    def test_zero_one_text_false_green_and_duplicate_keys_reject(self):
        raw = wire(records())
        for replacement in (b'"dropped_foreign":01', b'"dropped_foreign":1,"dropped_foreign":0'):
            bad = raw.replace(b'"dropped_foreign":0', replacement)
            with self.subTest(replacement=replacement), self.assertRaises(Rejected):
                inspect_prefix({"stdout": bad}, EXPECT)

    def test_missing_initial_turn_or_zero_kept_reject(self):
        values = records()
        values[2]["kept"] = 0
        for bad in (records()[:2], values, []):
            with self.subTest(bad=bad), self.assertRaises(Rejected):
                inspect(bad)

    def test_wrong_producer_or_model_or_request_mapping_reject(self):
        for key, bad in (("producer_instance_id", "deae1734-3ff9-445b-9cba-2ac885e1663d"),
                         ("requested_model", "other-model"), ("resolved_model", "other-model"),
                         ("request_id", "concurrent"), ("parent_request_id", "unrelated"), ("turn", 1)):
            values = records()
            values[2][key] = bad
            with self.subTest(key=key), self.assertRaises(Rejected):
                inspect(values)

    def test_stale_attempt_or_probe_does_not_get_current_ids(self):
        for key in ("attempt_id", "probe_id"):
            values = records()
            for v in values[1:]:
                v[key] = "stale"
            with self.subTest(key=key), self.assertRaisesRegex(Rejected, "missing-initial"):
                inspect(values)

    def test_unrelated_green_event_never_replaces_bad_correlated_event(self):
        values = records()
        values[2]["dropped_foreign"] = 3
        unrelated = retry(records())
        unrelated.update(probe_id="other-probe", replay_attempt=0, kept=1)
        with self.assertRaisesRegex(Rejected, "correlated-foreign-drop"):
            inspect(values + [unrelated])

    def test_unrelated_event_preserved_without_fabricated_mapping(self):
        values = records()
        unrelated = retry(values)
        unrelated.update(probe_id="other-probe", replay_attempt=0, kept=1, dropped_foreign=4)
        result = inspect(values + [unrelated])
        self.assertEqual(result["unique_records"], 4)
        self.assertEqual(result["matching_decisions"], 2)
        self.assertFalse(result["replay_accepted"])

    def test_retry_before_initial_or_duplicate_initial_reject(self):
        values = records()
        early = retry(values)
        early["event_id"] = PRODUCER + ":2"
        for bad in (values[:1] + [early], values + [{**values[2], "event_id": PRODUCER + ":4"}]):
            with self.subTest(bad=bad), self.assertRaisesRegex(Rejected, "retry|ambiguous-initial"):
                inspect(bad)

    def test_retry_schema_is_strict(self):
        for key, bad in (("kept", 1), ("replay_enabled", False), ("replay_attempt", True), ("replay_attempt", "1")):
            value = retry(records())
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(Rejected):
                record(wire([value])[:-1])

    def test_ids_models_turns_and_parent_are_not_coerced(self):
        for key, bad in (("attempt_id", "a\n"), ("probe_id", "x" * 129), ("request_id", True),
                         ("requested_model", "model with space"), ("resolved_model", "méta"),
                         ("turn", True), ("turn", 2.0), ("parent_request_id", "request-2")):
            value = records()[2]
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(Rejected):
                record(wire([value])[:-1])

    def test_event_identity_timestamp_and_sequence_are_strict(self):
        for key, bad in (("event_id", PRODUCER + ":03"), ("event_id", PRODUCER + ":0"),
                         ("event_id", PRODUCER + ":18446744073709551616"),
                         ("event_id", "deae1734-3ff9-445b-9cba-2ac885e1663d:3"),
                         ("timestamp", "2026-02-30T01:02:03Z"), ("timestamp", "2026-11-04T01:02:03+00:00"),
                         ("timestamp", "2026-11-04T01:02:03.1234567890Z")):
            value = records()[2]
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(Rejected):
                record(wire([value])[:-1])

    def test_startup_source_declaration_is_exact_not_missing_file_fallback(self):
        for key, bad in (("sources", []), ("file_logging", "enabled"), ("source_modified", "false"),
                         ("source_revision", "tag-not-sha"), ("producer_version", "0.2.4\n"),
                         ("event_id", PRODUCER + ":2")):
            value = records()[0]
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(Rejected):
                record(wire([value])[:-1])

    def test_empty_or_invalid_source_sets_reject(self):
        for sources in ({}, {"stdout": b""}, {"../source": wire(records())}, {"stdout": "not bytes"}):
            with self.subTest(sources=sources), self.assertRaises(Rejected):
                inspect_prefix(sources, EXPECT)

    def test_record_source_byte_and_record_count_limits(self):
        for sources in ({"stdout": b"x" * (4 * 1024 * 1024 + 1)},
                        {str(n): b"" for n in range(17)},
                        {"stdout": b"{}\n" + b" " * 4096 + b"\n"}):
            with self.subTest(count=len(sources)), self.assertRaises(Rejected):
                inspect_prefix(sources, EXPECT)
        values = records()
        for n in range(4, 1026):
            value = copy.deepcopy(values[2])
            value.update(event_id=PRODUCER + ":" + str(n), probe_id="other-probe")
            values.append(value)
        with self.assertRaisesRegex(Rejected, "record-overflow"):
            inspect(values)

    def test_non_ndjson_host_logs_are_explicitly_unsupported_not_swallowed(self):
        for suffix in (b"host log\n", b"\n", b'{"schema":"unrelated-host-json"}\n'):
            with self.subTest(suffix=suffix), self.assertRaises(Rejected):
                inspect_prefix({"stdout": wire(records()) + suffix}, EXPECT)

    def test_expectations_are_strict_not_provenance(self):
        for field, bad in (("request2", "request-1"), ("attempt_id", "x" * 129),
                           ("producer_instance_id", "short-id"), ("resolved_model", "")):
            values = dict(EXPECT.__dict__)
            values[field] = bad
            with self.subTest(field=field), self.assertRaises(Rejected):
                ProbeExpectation(**values)
