#!/usr/bin/env python3
"""Prevalidate frozen identities before any stop or recovery write.

Standard-library-only, offline, no execution. This is wrapper-adaptation
item 1 ("prevalidate identities without secrets"): it compares an
observed identity bundle against the source packet's frozen candidate
and fails closed on mismatch, malformed or missing identities. It
never invents host-only values, never falls back to a tag or a mutable
default, and rejects secret-shaped keys.

The result is always qualification=HOLD, service_recovery=NOT_TESTED
and execution_authorized=false, mirroring packet.py. A match binds
identity only; unknown host-only values stay named gates, not invented.
"""

import argparse
import json
import re
import sys
from pathlib import Path


MAX_OBSERVED_BYTES = 262144
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

# Mirrors packet.REQUIRED_BINDINGS; keep in sync (test asserts equality).
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

REQUIRED_OBSERVED_KEYS = (
    "repository",
    "platform",
    "index_digest",
    "manifest_digest",
    "config_digest",
    "docker_image_id",
    "recovery_manifest_digest",
)

SECRET_SUBSTRINGS = ("secret", "token", "password", "credential", "auth", "apikey", "api_key", "private")


class PrevalidationError(ValueError):
    """An observed identity cannot be prevalidated against the packet."""


def _require_digest(value, label):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise PrevalidationError(label + " must be a sha256 digest")


def _checked_manifest_candidate(manifest):
    if not isinstance(manifest, dict) or manifest.get("schema") != "stock-recovery-source/v1":
        raise PrevalidationError("unsupported source packet schema")
    candidate = manifest.get("candidate")
    if not isinstance(candidate, dict):
        raise PrevalidationError("missing packet candidate")
    for kind in ("index", "manifest", "config"):
        _require_digest(candidate.get(kind + "_digest"), "packet " + kind + " digest")
    _require_digest(candidate.get("docker_image_id"), "packet image ID")
    _require_digest(candidate.get("recovery_manifest_digest"), "packet recovery digest")
    platform = candidate.get("platform")
    if not isinstance(platform, dict) or not platform:
        raise PrevalidationError("packet platform is missing")
    for key, value in platform.items():
        if not isinstance(key, str) or not isinstance(value, str) or not value:
            raise PrevalidationError("packet platform is malformed")
    repository = candidate.get("repository")
    if not isinstance(repository, str) or not repository:
        raise PrevalidationError("packet repository is missing")
    bindings = manifest.get("unresolved_bindings")
    if bindings != list(REQUIRED_BINDINGS):
        raise PrevalidationError("source-only packet must retain every unresolved acceptance gate")
    return candidate


def _check_secret_key(key, label):
    if not isinstance(key, str) or not key or len(key) > 128:
        raise PrevalidationError(label + " key is malformed")
    lowered = key.lower()
    if any(part in lowered for part in SECRET_SUBSTRINGS):
        raise PrevalidationError(label + " must not carry secrets")


def _checked_manifest_files(manifest):
    files = manifest.get("files")
    if not isinstance(files, dict) or not files or len(files) > 64:
        raise PrevalidationError("packet source inputs are missing")
    for name, expected in files.items():
        # File names are fixed packet identities (e.g. retained/authcount
        # legitimately contains a secret-shaped substring); only the
        # digest shape is enforced here.
        if not isinstance(name, str) or not name:
            raise PrevalidationError("packet source input key is malformed")
        _require_digest(expected, "packet source digest for " + name)
    return files


def _checked_source_digests(files, bundle):
    """Compare an optional observed source bundle against the packet by name.

    Source/helper/runbook identities are frozen in the packet, so any
    observed digest supplied under source_digests must match exactly.
    Absence leaves the named gate unresolved rather than defaulting.
    """
    if "source_digests" not in bundle:
        return
    supplied = bundle["source_digests"]
    if not isinstance(supplied, dict) or not supplied or len(supplied) > 64:
        raise PrevalidationError("observed source digests must be a non-empty object")
    for name, expected in supplied.items():
        # Unknown names fail closed — including secret-shaped names,
        # which cannot be frozen packet files.
        if not isinstance(name, str) or not name:
            raise PrevalidationError("observed source digest key is malformed")
        if name not in files:
            raise PrevalidationError("observed source digest is not in the frozen packet: " + name)
        _require_digest(expected, "observed source digest for " + name)
        if expected != files[name]:
            raise PrevalidationError("observed source digest does not match the frozen packet: " + name)


def _checked_observed(observed):
    if not isinstance(observed, dict):
        raise PrevalidationError("observed identities must be an object")
    if len(observed) > 32:
        raise PrevalidationError("observed identities exceed key limit")
    for key, value in observed.items():
        _check_secret_key(key, "observed identity")
        if value is None or isinstance(value, (bool, int, float)):
            raise PrevalidationError("observed identity value is malformed")
    for required in REQUIRED_OBSERVED_KEYS:
        if required not in observed:
            raise PrevalidationError("observed identity is missing: " + required)
    return observed


def prevalidate(manifest, observed):
    candidate = _checked_manifest_candidate(manifest)
    files = _checked_manifest_files(manifest)
    bundle = _checked_observed(observed)

    if bundle["repository"] != candidate["repository"]:
        raise PrevalidationError("repository does not match the frozen candidate")
    platform = bundle["platform"]
    if not isinstance(platform, dict) or platform != candidate["platform"]:
        raise PrevalidationError("platform does not match the frozen candidate")

    # OCI identities must be compared by role, never by tag or by swap.
    for kind, label in (
        ("index_digest", "index digest"),
        ("manifest_digest", "manifest digest"),
        ("config_digest", "config digest"),
    ):
        _require_digest(bundle.get(kind), "observed " + label)
        if bundle[kind] != candidate[kind]:
            raise PrevalidationError("observed " + label + " does not match the frozen candidate")
    _require_digest(bundle.get("docker_image_id"), "observed image ID")
    if bundle["docker_image_id"] != candidate["config_digest"]:
        raise PrevalidationError("image ID must be the config digest, not the registry index")
    _require_digest(bundle.get("recovery_manifest_digest"), "observed recovery digest")
    if bundle["recovery_manifest_digest"] != candidate["manifest_digest"]:
        raise PrevalidationError("an alternative recovery target needs separate qualification")

    # Frozen source/helper/runbook identities, where supplied, must match
    # the packet by name; absence leaves the named gate unresolved.
    _checked_source_digests(files, bundle)

    # Optional host-only identities are validated only where supplied;
    # absence leaves the named gate unresolved rather than defaulting.
    for key, value in bundle.items():
        if key in REQUIRED_OBSERVED_KEYS or key == "source_digests":
            continue
        if isinstance(value, str):
            _require_digest(value, "host-only identity " + key)
        elif isinstance(value, list) and value:
            for item in value:
                _require_digest(item, "host-only identity " + key)
        elif isinstance(value, dict) and value:
            for item in value.values():
                _require_digest(item, "host-only identity " + key)
        else:
            raise PrevalidationError("host-only identity is malformed: " + key)

    return {
        "identity_match": True,
        "source_binding": "BOUND",
        "qualification": "HOLD",
        "service_recovery": "NOT_TESTED",
        "execution_authorized": False,
        "unresolved_bindings": list(REQUIRED_BINDINGS),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, help="source packet manifest")
    parser.add_argument("--observed", required=True, help="observed identity bundle JSON")
    args = parser.parse_args(argv)
    try:
        manifest_raw = Path(args.manifest).read_bytes()
        observed_raw = Path(args.observed).read_bytes()
        if len(manifest_raw) > 1024 * 1024 or len(observed_raw) > MAX_OBSERVED_BYTES:
            raise PrevalidationError("identity input exceeds size limit")
        result = prevalidate(json.loads(manifest_raw), json.loads(observed_raw))
    except PrevalidationError:
        print(json.dumps({"identity_match": False, "qualification": "HOLD", "error_type": "PrevalidationError"}))
        return 1
    except (OSError, ValueError, TypeError):
        print(json.dumps({"identity_match": False, "qualification": "HOLD", "error_type": "InputError"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
