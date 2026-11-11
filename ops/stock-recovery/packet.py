#!/usr/bin/env python3
"""Inspect a source packet without executing its contents or touching a runtime."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
REQUIRED_BINDINGS = (
    "binary_source_attestation",
    "host_platform",
    "compose_config",
    "provider_artifacts",
    "authoritative_store",
    "quiescence_mechanism",
    "watchdog_armed",
    "terminal_persistence",
    "journal_fault_matrix",
    "functional_recovery",
    "security_review",
    "qa_review",
    "release_acceptance",
    "operator_execution_authorization",
)


class PacketError(ValueError):
    """The source packet is inconsistent, not merely unqualified."""


def refusal_report(*, possibly_submitted, observation_available, service_unavailable):
    """Classify a refusal; this source-only contract cannot admit any writes.

    Inputs represent observations supplied by a caller, not verified runtime facts.
    This function provides no independent reporting channel or execution authority.
    """
    if any(type(value) is not bool for value in
           (possibly_submitted, observation_available, service_unavailable)):
        raise PacketError("refusal observations must be booleans")
    if service_unavailable and observation_available:
        outcome = "FUNCTIONAL_FAIL"
    elif not observation_available:
        outcome = "UNKNOWN"
    elif possibly_submitted:
        outcome = "RECOVERY_NOT_PROVEN"
    else:
        outcome = "ABORT_UNCHANGED"
    return {"outcome": outcome, "recovery_write_admitted": False,
            "execution_authorized": False, "recovery_success": False}


def checked_file(root, name):
    if not isinstance(name, str) or not name:
        raise PacketError("invalid packet path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in name.split("/")):
        raise PacketError("packet path escapes its root")
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise PacketError("symlinks are not packet inputs")
    if not stat.S_ISREG(current.stat().st_mode):
        raise PacketError("packet input is not a regular file")
    if current.stat().st_size > 1024 * 1024:
        raise PacketError("packet input exceeds one MiB")
    return current.read_bytes()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def verify(packet, root):
    if not isinstance(packet, dict) or packet.get("schema") != "stock-recovery-source/v1":
        raise PacketError("unsupported source packet schema")
    files = packet.get("files")
    if not isinstance(files, dict) or not files or len(files) > 64:
        raise PacketError("missing or excessive source inputs")
    for name, expected in files.items():
        if not isinstance(expected, str) or not DIGEST.fullmatch(expected):
            raise PacketError("invalid source digest")
        if digest(checked_file(root, name)) != expected:
            raise PacketError("source input hash mismatch: " + name)

    artifact = packet["candidate"]
    index_bytes = checked_file(root, artifact["index_file"])
    manifest_bytes = checked_file(root, artifact["manifest_file"])
    config_bytes = checked_file(root, artifact["config_file"])
    for kind, data in (("index", index_bytes), ("manifest", manifest_bytes), ("config", config_bytes)):
        if artifact[kind + "_digest"] != digest(data):
            raise PacketError("OCI " + kind + " digest mismatch")
        if artifact[kind + "_file"] not in files:
            raise PacketError("OCI input is not source-bound")
    index, manifest, config = map(json.loads, (index_bytes, manifest_bytes, config_bytes))
    if index.get("mediaType") != "application/vnd.oci.image.index.v1+json":
        raise PacketError("expected OCI index")
    matches = [item for item in index["manifests"] if item.get("platform") == artifact["platform"]]
    if len(matches) != 1 or matches[0]["digest"] != artifact["manifest_digest"]:
        raise PacketError("platform does not select the frozen manifest")
    if manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        raise PacketError("expected platform image manifest")
    if manifest.get("config", {}).get("digest") != artifact["config_digest"]:
        raise PacketError("platform manifest does not bind the config ID")
    if manifest["config"].get("mediaType") != "application/vnd.oci.image.config.v1+json":
        raise PacketError("expected image config")
    if any(config.get(key) != value for key, value in artifact["platform"].items()):
        raise PacketError("image config platform mismatch")
    if artifact["docker_image_id"] != artifact["config_digest"]:
        raise PacketError("Docker image ID must be the config digest, not the registry index")
    if artifact["recovery_manifest_digest"] != artifact["manifest_digest"]:
        raise PacketError("an alternative recovery target needs separate qualification")

    # A source freeze is deliberately incapable of granting execution acceptance.
    # Future qualification receipts need their own reviewed, exact-artifact verifier.
    bindings = packet.get("unresolved_bindings")
    if bindings != list(REQUIRED_BINDINGS):
        raise PacketError("source-only packet must retain every unresolved acceptance gate")
    return {
        "source_binding": "BOUND",
        "qualification": "HOLD",
        "service_recovery": "NOT_TESTED",
        "execution_authorized": False,
        "recovery_write_admitted": False,
        "recovery_success": False,
        "unresolved_bindings": list(REQUIRED_BINDINGS),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    args = parser.parse_args()
    try:
        raw = args.packet.read_bytes()
        if len(raw) > 1024 * 1024:
            raise PacketError("packet exceeds one MiB")
        result = verify(json.loads(raw), args.packet.resolve().parent)
        result["packet_digest"] = digest(raw)
    except (OSError, ValueError, KeyError, TypeError) as error:
        # Do not print untrusted input or configuration values into CI logs.
        print(json.dumps({"source_binding": "FAIL", "qualification": "HOLD", "error_type": type(error).__name__}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
