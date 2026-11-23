import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, call
import zipfile

import staging


def spec(image, meta):
    return {"image": "sha256:" + image * 64, "docker_config": "sha256:" + "0" * 64,
            "executable": "1" * 64, "meta": meta}


class StagingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bundle = self.root / "bundle.zip"
        self.release = {"baseline": spec("a", "0.2.7"), "candidate": spec("a", "0.2.9")}

    def write_bundle(self, extra=None):
        with zipfile.ZipFile(self.bundle, "w") as archive:
            archive.writestr("release.json", json.dumps(self.release))
            archive.writestr("baseline/meta-v0.2.7.so", b"baseline fixture")
            archive.writestr("candidate/meta-v0.2.9.so", b"candidate fixture")
            archive.writestr("baseline.oci.tar.zst", b"fake archive")
            if extra:
                archive.writestr(extra, b"unexpected")

    def test_accept_meta_only_with_one_image(self):
        self.write_bundle()
        self.assertEqual(staging.unpack(self.bundle, self.root, preloaded=False), self.release)
        self.assertEqual((self.root / "candidate/meta-v0.2.9.so").read_bytes(), b"candidate fixture")

    def test_host_upgrade_requires_candidate_image(self):
        self.release["candidate"] = spec("b", "0.2.9")
        self.write_bundle()
        with self.assertRaisesRegex(staging.StagingError, "archive set"):
            staging.unpack(self.bundle, self.root, preloaded=False)
        self.assertFalse((self.root / "baseline.oci.tar.zst").exists())

    def test_traversal_fails_before_extracting(self):
        self.write_bundle("candidate/../unexpected.so")
        with self.assertRaisesRegex(staging.StagingError, "unexpected staging bundle member"):
            staging.unpack(self.bundle, self.root, preloaded=False)
        self.assertFalse((self.root / "baseline").exists())

    def test_candidate_failure_still_restarts_same_baseline_and_fails(self):
        gateway = Mock()
        gateway.config.read_bytes.return_value = b"original bytes after baseline startup"
        gateway.switch.side_effect = [None, staging.StagingError("candidate refused"), None]
        with self.assertRaisesRegex(staging.StagingError, "candidate refused"):
            staging.rehearse(gateway, self.release)
        snapshot = gateway.config.read_bytes.return_value
        self.assertEqual(gateway.switch.call_args_list, [
            call("baseline", self.release["baseline"], staging.CONFIG),
            call("candidate", self.release["candidate"], snapshot),
            call("baseline", self.release["baseline"], snapshot),
        ])
        gateway.stop.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
