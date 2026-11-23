import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, call
import zipfile

import staging
from staging_probe import completed


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
            archive.writestr("baseline.oci.tar", b"fake archive")
            if extra:
                archive.writestr(extra, b"unexpected")

    def test_accept_meta_only_with_one_image(self):
        self.write_bundle()
        self.assertEqual(staging.unpack(self.bundle, self.root), self.release)
        self.assertEqual((self.root / "candidate/meta-v0.2.9.so").read_bytes(), b"candidate fixture")

    def test_host_upgrade_requires_candidate_image(self):
        self.release["candidate"] = spec("b", "0.2.9")
        self.write_bundle()
        with self.assertRaisesRegex(staging.StagingError, "archive set"):
            staging.unpack(self.bundle, self.root)
        self.assertFalse((self.root / "baseline.oci.tar").exists())

    def test_traversal_fails_before_extracting(self):
        self.write_bundle("candidate/../unexpected.so")
        with self.assertRaisesRegex(staging.StagingError, "unexpected staging bundle member"):
            staging.unpack(self.bundle, self.root)
        self.assertFalse((self.root / "baseline").exists())

    def test_oci_only_change_cannot_rehearse_same_runtime(self):
        self.release["candidate"] = spec("b", "0.2.7")
        with zipfile.ZipFile(self.bundle, "w") as archive:
            archive.writestr("release.json", json.dumps(self.release))
            for phase in self.release:
                archive.writestr(f"{phase}/meta-v0.2.7.so", b"same library")
                archive.writestr(f"{phase}.oci.tar", b"fake archive")
        with self.assertRaisesRegex(staging.StagingError, "identical identities"):
            staging.unpack(self.bundle, self.root)

    def test_oci_and_docker_archive_must_describe_same_image(self):
        empty = io.BytesIO()
        with tarfile.open(fileobj=empty, mode="w"):
            pass
        layer = empty.getvalue()
        layer_digest = "sha256:" + hashlib.sha256(layer).hexdigest()
        config = json.dumps({
            "os": "linux", "architecture": "amd64", "config": {"Cmd": ["/unused-fixture"]},
            "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
        }).encode()
        config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
        manifest = json.dumps({
            "schemaVersion": 2, "mediaType": staging.OCI_MANIFEST,
            "config": {"digest": config_digest, "size": len(config), "mediaType": "application/vnd.oci.image.config.v1+json"},
            "layers": [{"digest": layer_digest, "size": len(layer), "mediaType": "application/vnd.oci.image.layer.v1.tar"}],
        }).encode()
        image = "sha256:" + hashlib.sha256(manifest).hexdigest()
        descriptor = {"mediaType": staging.OCI_MANIFEST, "digest": image, "size": len(manifest)}
        image_archive = self.root / "image.tar"
        compat = [{"Config": staging.blob_path(config_digest), "Layers": [staging.blob_path(layer_digest)]}]
        files = {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": json.dumps({"schemaVersion": 2, "manifests": [descriptor]}).encode(),
            "manifest.json": json.dumps(compat).encode(),
            staging.blob_path(image): manifest,
            staging.blob_path(config_digest): config,
            staging.blob_path(layer_digest): layer,
        }
        with tarfile.open(image_archive, "w") as archive:
            for path, data in files.items():
                entry = tarfile.TarInfo(path)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        staging.verify_image(image_archive, {"image": image, "docker_config": config_digest})
        with self.assertRaisesRegex(staging.StagingError, "Docker config digest mismatch"):
            staging.verify_image(image_archive, {"image": image, "docker_config": "sha256:" + "0" * 64})
        if os.environ.get("CI") == "true" and os.environ.get("GITHUB_ACTIONS") == "true":
            staging.command("docker", "image", "load", "--quiet", "--input", str(image_archive))
            classic = staging.command("docker", "info", "--format", "{{.Driver}}") == "overlay2"
            reference = config_digest if classic else image
            self.assertEqual(staging.command("docker", "image", "inspect", "--format", "{{.Id}}", reference), reference)

    def test_text_then_done_needs_finish_reason(self):
        text = b'{"choices":[{"index":0,"delta":{"content":"stage-complete"},"finish_reason":null}]}'
        finish = b'{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}'
        self.assertFalse(completed([text, b"[DONE]"]))
        self.assertTrue(completed([text, finish, b"[DONE]"]))

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
