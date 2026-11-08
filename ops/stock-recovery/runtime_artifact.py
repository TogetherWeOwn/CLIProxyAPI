#!/usr/bin/env python3
"""Materialize the frozen public OCI runtime for disposable Actions tests only.

Never extracts an archive tree or executes downloaded content. The binary is
published only after every layer and its uncompressed diff ID have been checked.
This proves registry-artifact lineage, not binary/source attestation or recovery.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile
import urllib.request


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_COMPRESSED = 128 * 1024 * 1024
MAX_UNPACKED = 256 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024
TARGET = "CLIProxyAPI/CLIProxyAPI"
ANCESTORS = frozenset(("CLIProxyAPI",))


class ArtifactError(ValueError):
    """The frozen runtime cannot be established."""


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def bounded_read(stream, limit):
    chunks = []
    remaining = limit + 1
    while remaining:
        chunk = stream.read(min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    if remaining == 0:
        raise ArtifactError("artifact exceeds size limit")
    return b"".join(chunks)


def checked_descriptor(descriptor, raw):
    if (not isinstance(descriptor, dict)
            or not isinstance(descriptor.get("digest"), str)
            or not DIGEST.fullmatch(descriptor["digest"])
            or type(descriptor.get("size")) is not int
            or descriptor["size"] != len(raw)
            or descriptor["digest"] != digest(raw)):
        raise ArtifactError("artifact descriptor mismatch")


def layer_binary(raw, current):
    """Interpret only the target path; never use extract/extractall."""
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for number, member in enumerate(archive):
            if number >= 100000:
                raise ArtifactError("too many archive entries")
            name = member.name
            # A leading ./ and a trailing directory slash are standard tar forms.
            while name.startswith("./"):
                name = name[2:]
            name = name.rstrip("/")
            if name in ("", ".") and member.isdir():
                continue
            if name.startswith("/") or any(part in ("", ".", "..") for part in name.split("/")):
                raise ArtifactError("unsafe archive member path")
            # Reject whiteout effects on the target instead of guessing overlay semantics.
            if name in (".wh.CLIProxyAPI", ".wh..wh..opq",
                        "CLIProxyAPI/.wh.CLIProxyAPI", "CLIProxyAPI/.wh..wh..opq"):
                raise ArtifactError("runtime path affected by whiteout")
            if name in ANCESTORS and not member.isdir():
                raise ArtifactError("runtime ancestor is not a directory")
            if name.startswith(TARGET + "/"):
                raise ArtifactError("runtime path used as a directory")
            if name != TARGET:
                continue
            if not member.isfile() or not 0 < member.size <= MAX_BINARY:
                raise ArtifactError("runtime is not a bounded regular file")
            with archive.extractfile(member) as stream:
                current = bounded_read(stream, MAX_BINARY)
            if len(current) != member.size:
                raise ArtifactError("truncated runtime member")
    return current


def materialize(manifest_raw, config_raw, fetch_blob, destination):
    manifest, config = map(json.loads, (manifest_raw, config_raw))
    checked_descriptor(manifest["config"], config_raw)
    if (manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
            or manifest["config"].get("mediaType") != "application/vnd.oci.image.config.v1+json"
            or config.get("os") != "linux" or config.get("architecture") != "amd64"
            or config.get("rootfs", {}).get("type") != "layers"):
        raise ArtifactError("unsupported image format or platform")
    layers, diff_ids = manifest["layers"], config["rootfs"]["diff_ids"]
    if not isinstance(layers, list) or not 0 < len(layers) <= 32 or len(layers) != len(diff_ids):
        raise ArtifactError("invalid layer chain")
    # The caller must allocate a new, empty download directory for each image.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    inputs = destination / "inputs"
    inputs.mkdir(mode=0o700)
    binary = None
    for index, (descriptor, diff_id) in enumerate(zip(layers, diff_ids)):
        if (descriptor.get("mediaType") != "application/vnd.oci.image.layer.v1.tar+gzip"
                or type(descriptor.get("size")) is not int
                or not 0 < descriptor["size"] <= MAX_COMPRESSED
                or not isinstance(descriptor.get("digest"), str)
                or not DIGEST.fullmatch(descriptor["digest"])
                or not isinstance(diff_id, str) or not DIGEST.fullmatch(diff_id)):
            raise ArtifactError("unsupported layer descriptor")
        compressed = fetch_blob(descriptor["digest"], descriptor["size"])
        checked_descriptor(descriptor, compressed)
        (inputs / (str(index) + ".tar.gz")).write_bytes(compressed)
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            unpacked = bounded_read(stream, MAX_UNPACKED)
        if digest(unpacked) != diff_id:
            raise ArtifactError("uncompressed layer identity mismatch")
        binary = layer_binary(unpacked, binary)
    if binary is None:
        raise ArtifactError("frozen runtime path absent")
    output = destination / "runtime"
    output.mkdir(mode=0o700)
    executable = output / "CLIProxyAPI"
    with executable.open("xb") as stream:
        stream.write(binary)
    os.chmod(executable, 0o700)
    return {"manifest_digest": digest(manifest_raw), "config_digest": digest(config_raw),
            "binary_digest": digest(binary), "binary_size": len(binary),
            "platform": "linux/amd64", "qualification": "HOLD", "service_recovery": "NOT_TESTED"}


class PublicRegistry:
    """Public pull token only; no workspace or production credentials."""

    def __init__(self):
        url = ("https://auth.docker.io/token?service=registry.docker.io"
               "&scope=repository:eceasy/cli-proxy-api:pull")
        with urllib.request.urlopen(url) as response:
            token = json.loads(bounded_read(response, 65536))["token"]
        if not isinstance(token, str) or not token:
            raise ArtifactError("public registry token missing")
        self.token = token

    def __call__(self, blob_digest, size):
        # Strip the registry token on cross-origin CDN redirects.
        class Redirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, msg, headers, newurl):
                if not newurl.startswith("https://"):
                    raise ArtifactError("insecure registry redirect")
                redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
                if redirected is not None:
                    redirected.remove_header("Authorization")
                return redirected

        request = urllib.request.Request(
            "https://registry-1.docker.io/v2/eceasy/cli-proxy-api/blobs/" + blob_digest,
            headers={"Authorization": "Bearer " + self.token})
        with urllib.request.build_opener(Redirect()).open(request) as response:
            return bounded_read(response, min(size, MAX_COMPRESSED))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    # Registry download is an Actions preparation step, never an installed wrapper path.
    if os.environ.get("GITHUB_ACTIONS") != "true":
        parser.error("runtime materialization is limited to GitHub Actions")
    import importlib.util
    spec = importlib.util.spec_from_file_location("source_packet", Path(__file__).with_name("packet.py"))
    packet = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(packet)
    try:
        raw = args.packet.read_bytes()
        value = json.loads(raw)
        root = args.packet.resolve().parent
        packet.verify(value, root)
        candidate = value["candidate"]
        result = materialize(packet.checked_file(root, candidate["manifest_file"]),
                             packet.checked_file(root, candidate["config_file"]),
                             PublicRegistry(), args.destination)
        result["packet_digest"] = digest(raw)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, EOFError) as error:
        print(json.dumps({"qualification": "HOLD", "error_type": type(error).__name__}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
