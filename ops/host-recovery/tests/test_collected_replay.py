import copy
import os
from pathlib import Path
import tempfile
import unittest

from host_recovery.collection import FileCapture
from host_recovery.durable import Rejected, directory
from host_recovery.replay import ProbeExpectation, inspect_spooled_prefix


class CollectedReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spool = self.root / "spool"
        self.spool.mkdir(mode=0o700)
        raw = (Path(__file__).parent / "fixtures" / "producer-prefix-b6f95237.ndjson").read_bytes()
        self.expect = ProbeExpectation("f55c9c69-323a-406f-bd1c-eeb68474d092", "attempt-1", "probe-1",
                                       "request-1", "request-2", "public-model-alias(high)", "muse-spark-1.3")
        self.receipts = []
        self.sources = ["stdout", "mirror", "empty-mirror"]
        for source_id in self.sources:
            source = self.root / source_id
            source.write_bytes(b"" if source_id == "empty-mirror" else raw)
            source.chmod(0o600)
            with FileCapture(source_id=source_id, path=str(source), uid=os.geteuid(), gid=os.getegid(),
                             mode=0o600) as capture, directory(str(self.spool), private=True) as spool:
                self.receipts.append(capture.snapshot(spool))

    def inspect(self, receipts=None, sources=None):
        with directory(str(self.spool), private=True) as spool:
            return inspect_spooled_prefix(spool, self.receipts if receipts is None else receipts,
                                          self.sources if sources is None else sources, self.expect)

    def test_capture_raw_readback_parser_handoff_never_issues_acceptance(self):
        result = self.inspect()
        self.assertEqual(result["unique_records"], 3)
        self.assertEqual(result["matching_decisions"], 2)
        self.assertEqual(result["capture_receipts"], self.receipts)
        self.assertFalse(result["replay_accepted"])
        self.assertFalse(result["collection_complete"])
        self.assertIn("all-required-source-coverage", result["missing_obligations"])
        result["capture_receipts"][0]["inode"] = 0
        self.assertNotEqual(result["capture_receipts"], self.receipts)

    def test_missing_duplicate_extra_and_unknown_required_sources_reject(self):
        for receipts, sources in ((self.receipts[:-1], self.sources),
                                  (self.receipts + [self.receipts[0]], self.sources),
                                  ([self.receipts[0]] * 3, self.sources),
                                  (self.receipts, ["stdout", "mirror", "missing"]),
                                  (self.receipts, self.sources + ["absent"]),
                                  (self.receipts, ["stdout"] * 3), ([], [])):
            with self.subTest(count=len(receipts)), self.assertRaises(Rejected):
                self.inspect(receipts, sources)

    def test_tampered_raw_bytes_size_hash_and_empty_state_reject(self):
        for key, bad in (("raw_sha256", "0" * 64), ("end_offset", 0), ("empty", True),
                         ("previous_end_offset", 1 << 63)):
            receipts = copy.deepcopy(self.receipts)
            receipts[0][key] = bad
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.inspect(receipts)
        raw_path = self.spool / self.receipts[0]["raw_handle"]
        raw_path.write_bytes(raw_path.read_bytes().replace(b'"kept":1', b'"kept":0'))
        with self.assertRaises(Rejected):
            self.inspect()

    def test_missing_unreadable_unsafe_or_traversal_raw_handles_reject(self):
        for handle in ("../elsewhere", "prefix-" + "0" * 32 + ".raw", True):
            receipts = copy.deepcopy(self.receipts)
            receipts[0]["raw_handle"] = handle
            with self.subTest(handle=handle), self.assertRaises(Rejected):
                self.inspect(receipts)
        raw_path = self.spool / self.receipts[0]["raw_handle"]
        raw_path.chmod(0o644)
        with self.assertRaises(Rejected):
            self.inspect()
        raw_path.unlink()
        raw_path.symlink_to(self.root / "stdout")
        with self.assertRaises(Rejected):
            self.inspect()

    def test_receipts_cannot_claim_complete_drained_or_gapped_coverage(self):
        for key, bad in (("coverage", "complete"), ("producer_drained", True), ("start_offset", 1),
                         ("device", False), ("inode", 0), ("end_offset", 4 * 1024 * 1024 + 1),
                         ("source_id", "foreign"), ("schema", "unknown"), ("extra", "not-allowed")):
            receipts = copy.deepcopy(self.receipts)
            receipts[0][key] = bad
            with self.subTest(key=key), self.assertRaises(Rejected):
                self.inspect(receipts)
