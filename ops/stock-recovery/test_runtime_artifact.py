#!/usr/bin/env python3
"""Synthetic archive controls, not stock-runtime recovery qualification."""

import gzip
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("runtime_artifact", Path(__file__).with_name("runtime_artifact.py"))
artifact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact)


def archive(*entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as stream:
        for name, data, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(data) if kind == tarfile.REGTYPE else 0
            member.linkname = "elsewhere" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
            stream.addfile(member, io.BytesIO(data) if member.isfile() else None)
    return output.getvalue()


class RuntimeArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.destination = Path(self.temporary.name) / "download"

    def image(self, *layers):
        blobs = {}
        descriptors = []
        for layer in layers:
            compressed = gzip.compress(layer, mtime=0)
            key = artifact.digest(compressed)
            blobs[key] = compressed
            descriptors.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                                "digest": key, "size": len(compressed)})
        config = json.dumps({"os": "linux", "architecture": "amd64",
                             "rootfs": {"type": "layers", "diff_ids": [artifact.digest(x) for x in layers]}}).encode()
        manifest = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "layers": descriptors,
                    "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                               "digest": artifact.digest(config), "size": len(config)}}
        return manifest, config, blobs

    def materialize(self, image, fetch=None):
        manifest, config, blobs = image
        return artifact.materialize(json.dumps(manifest).encode(), config,
                                    fetch or (lambda key, size: blobs[key]), self.destination)

    def binary_layer(self, data=b"synthetic-not-an-executable"):
        entries = [("CLIProxyAPI", b"", tarfile.DIRTYPE),
                   ("./CLIProxyAPI/CLIProxyAPI", data, tarfile.REGTYPE)]
        entries.extend((name, ("synthetic-" + name).encode(), tarfile.REGTYPE)
                       for name in artifact.FROZEN_LIBS)
        return archive(*entries)

    def libs_layer(self, data=b"synthetic-lib"):
        return archive(*[("./" + name, data, tarfile.REGTYPE) for name in artifact.FROZEN_LIBS])

    def test_complete_chain_selects_last_regular_binary_without_extracting_tree(self):
        image = self.image(self.binary_layer(b"old"), archive(("other", b"ignored", tarfile.REGTYPE)),
                           self.binary_layer(b"new"))
        result = self.materialize(image)
        self.assertEqual(result["binary_digest"], artifact.digest(b"new"))
        self.assertEqual(result["qualification"], "HOLD")
        self.assertEqual(result["service_recovery"], "NOT_TESTED")
        self.assertEqual((self.destination / "runtime/CLIProxyAPI").read_bytes(), b"new")
        self.assertFalse((self.destination / "other").exists())
        self.assertEqual(len(list((self.destination / "inputs").iterdir())), 3)

    def test_late_layer_digest_failure_never_publishes_binary(self):
        image = self.image(self.binary_layer(), archive(("other", b"x", tarfile.REGTYPE)))
        image[0]["layers"][-1]["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(artifact.ArtifactError):
            self.materialize(image, lambda key, size: next(iter(image[2].values())))
        self.assertFalse((self.destination / "runtime").exists())

    def test_config_identity_is_verified_before_creating_destination(self):
        image = self.image(self.binary_layer())
        image[0]["config"]["size"] += 1
        with self.assertRaises(artifact.ArtifactError):
            self.materialize(image)
        self.assertFalse(self.destination.exists())

    def test_uncompressed_diff_identity_is_verified(self):
        image = self.image(self.binary_layer())
        config = json.loads(image[1])
        config["rootfs"]["diff_ids"][0] = "sha256:" + "1" * 64
        raw = json.dumps(config).encode()
        image[0]["config"].update(digest=artifact.digest(raw), size=len(raw))
        with self.assertRaises(artifact.ArtifactError):
            self.materialize((image[0], raw, image[2]))
        self.assertFalse((self.destination / "runtime").exists())

    def test_target_links_and_nonregular_entries_fail_closed(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind), self.assertRaises(artifact.ArtifactError):
                artifact.layer_binary(archive((artifact.TARGET, b"", kind)), None)

    def test_ancestor_links_fail_closed(self):
        with self.assertRaises(artifact.ArtifactError):
            artifact.layer_binary(archive(("CLIProxyAPI", b"", tarfile.SYMTYPE)), b"old")

    def test_target_cannot_be_used_as_a_directory(self):
        with self.assertRaises(artifact.ArtifactError):
            artifact.layer_binary(archive((artifact.TARGET + "/child", b"x", tarfile.REGTYPE)), b"old")

    def test_whiteouts_cannot_resurrect_stale_binary(self):
        for path in (".wh.CLIProxyAPI", ".wh..wh..opq", "CLIProxyAPI/.wh.CLIProxyAPI",
                     "CLIProxyAPI/.wh..wh..opq"):
            with self.subTest(path=path), self.assertRaises(artifact.ArtifactError):
                artifact.layer_binary(archive((path, b"", tarfile.REGTYPE)), b"old")

    def test_unsafe_archive_paths_are_never_written(self):
        for path in ("../outside", "/absolute", "CLIProxyAPI/../outside", "a//b"):
            with self.subTest(path=path), self.assertRaises(artifact.ArtifactError):
                artifact.layer_binary(archive((path, b"x", tarfile.REGTYPE)), None)
        self.assertFalse((Path(self.temporary.name) / "outside").exists())

    def test_existing_download_directory_is_not_overwritten(self):
        self.destination.mkdir()
        sentinel = self.destination / "sentinel"
        sentinel.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            self.materialize(self.image(self.binary_layer()))
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_unpacked_layer_limit(self):
        with patch.object(artifact, "MAX_UNPACKED", 32), self.assertRaises(artifact.ArtifactError):
            self.materialize(self.image(self.binary_layer()))
        self.assertFalse((self.destination / "runtime").exists())

    def test_missing_runtime_is_failure(self):
        with self.assertRaises(artifact.ArtifactError):
            self.materialize(self.image(archive(("other", b"x", tarfile.REGTYPE))))
        self.assertFalse((self.destination / "runtime").exists())

    def test_frozen_libs_are_materialized_without_tree_extraction(self):
        image = self.image(self.binary_layer())
        result = self.materialize(image)
        for name in artifact.FROZEN_LIBS:
            published = self.destination / "runtime/libs" / name
            self.assertTrue(published.is_file())
            self.assertEqual(published.read_bytes(), ("synthetic-" + name).encode())
            self.assertEqual(result["libs"][name], artifact.digest(published.read_bytes()))
        self.assertFalse((self.destination / "other").exists())

    def test_missing_frozen_lib_fails_closed(self):
        layer = archive(("CLIProxyAPI", b"", tarfile.DIRTYPE),
                        ("CLIProxyAPI/CLIProxyAPI", b"synthetic", tarfile.REGTYPE),
                        ("etc/ld.so.cache", b"synthetic-cache", tarfile.REGTYPE))
        with self.assertRaises(artifact.ArtifactError):
            self.materialize(self.image(layer))
        self.assertFalse((self.destination / "runtime").exists())

    def test_frozen_lib_links_and_dirs_fail_closed(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind), self.assertRaises(artifact.ArtifactError):
                artifact.layer_libs(archive(("etc/ld.so.cache", b"", kind)), {})

    def test_frozen_lib_whiteout_fails_closed(self):
        for path in ("usr/lib/x86_64-linux-gnu/.wh.libc.so.6", "etc/.wh..wh..opq"):
            with self.subTest(path=path), self.assertRaises(artifact.ArtifactError):
                artifact.layer_libs(archive((path, b"", tarfile.REGTYPE)), {})

    def test_frozen_libs_use_last_layer_wins(self):
        image = self.image(self.binary_layer(b"old"), self.libs_layer(b"overridden"))
        result = self.materialize(image)
        for name in artifact.FROZEN_LIBS:
            self.assertEqual(result["libs"][name], artifact.digest(b"overridden"))

    def test_compressed_size_and_limit(self):
        image = self.image(self.binary_layer())
        image[0]["layers"][0]["size"] += 1
        with self.assertRaises(artifact.ArtifactError):
            self.materialize(image)
        with patch.object(artifact, "MAX_COMPRESSED", 1), self.assertRaises(artifact.ArtifactError):
            # A fresh directory is needed for each attempt, including failed attempts.
            self.destination = Path(self.temporary.name) / "second"
            self.materialize(self.image(self.binary_layer()))

    def test_layer_chain_shape(self):
        image = self.image(self.binary_layer())
        image[0]["layers"] = []
        with self.assertRaises(artifact.ArtifactError):
            self.materialize(image)
        self.assertFalse(self.destination.exists())

    def test_bounded_reader_accepts_exact_limit_but_not_more(self):
        self.assertEqual(artifact.bounded_read(io.BytesIO(b"abc"), 3), b"abc")
        with self.assertRaises(artifact.ArtifactError):
            artifact.bounded_read(io.BytesIO(b"abcd"), 3)


if __name__ == "__main__":
    unittest.main()
