"""Offline fixture verdicts for CLIProxy release evidence."""

import hashlib
import hmac
import json
import re

MAX_BYTES = 16 * 1024
FIXTURE_NOW = 200
MAX_LIFETIME = 300
STAGING_ISSUER = "fixture-staging-issuer"
ACCEPTANCE_ISSUER = "fixture-acceptance-issuer"
# Public fixture keys, deliberately distinct for the two issuer roles.
STAGING_KEY = b"public fixture staging key v1"
ACCEPTANCE_KEY = b"public fixture acceptance key v1"
DIGEST = re.compile(r"fixture-sha256:[0-9a-f]{64}")
TAG = re.compile(r"[0-9a-f]{64}")
LABEL = re.compile(r"fixture-[a-z0-9-]{1,24}")
LIBRARY = re.compile(LABEL.pattern + r"\.so")
CHECKS = (
    "source_checks", "source_reviews", "readiness", "registrations",
    "disabled_providers", "write_cohort_a", "write_cohort_b",
    "zero_internal_499s", "fresh_routes", "rollback_rehearsal",
)


class InvalidFixture(Exception):
    pass


def require(condition):
    if not condition:
        raise InvalidFixture


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(value):
    return "fixture-sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def seal(key, claims):
    return hmac.digest(key, canonical(claims), "sha256").hex()


def unique_object(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs))
    return result


def bounded_int(token):
    require(len(token) <= 10)
    return int(token)


def reject_number(_):
    raise InvalidFixture


def fields(value, *names):
    require(type(value) is dict and value.keys() == set(names))


def matches(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def sorted_unique(values):
    require(values == sorted(set(values)))


def verify_bundle(bundle):
    digests = ("source", "build", "oci", "image", "binary", "compose", "config", "runtime_config")
    fields(bundle, *digests, "platform", "plugins")
    require(bundle["platform"] == "linux/amd64")
    require(all(matches(bundle[field], DIGEST) for field in digests))
    plugins = bundle["plugins"]
    require(type(plugins) is list and len(plugins) <= 16)
    for plugin in plugins:
        fields(plugin, "filename", "abi", "library", "registrations", "disabled_providers")
        require(matches(plugin["filename"], LIBRARY))
        require(plugin["abi"] in ("fixture-abi-1", "fixture-abi-2"))
        require(matches(plugin["library"], DIGEST))
        for field in ("registrations", "disabled_providers"):
            labels = plugin[field]
            require(type(labels) is list and len(labels) <= 16)
            require(all(matches(label, LABEL) for label in labels))
            sorted_unique(labels)
    sorted_unique([plugin["filename"] for plugin in plugins])


def verify_record(claims, tag, key):
    issued, expires = claims["issued"], claims["expires"]
    require(type(issued) is int and type(expires) is int)
    require(0 <= issued <= FIXTURE_NOW < expires <= issued + MAX_LIFETIME)
    require(matches(tag, TAG) and hmac.compare_digest(tag, seal(key, claims)))


def verify(raw, expected_attempt):
    """Compare an envelope against a separately supplied synthetic attempt digest."""
    try:
        require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES)
        envelope = json.loads(
            raw.decode("ascii"), object_pairs_hook=unique_object,
            parse_int=bounded_int, parse_float=reject_number, parse_constant=reject_number,
        )
        fields(envelope, "manifest", "staging_receipt", "release_approval")
    except (InvalidFixture, ValueError, RecursionError):
        return "fixture-envelope-rejected"

    manifest = envelope["manifest"]
    try:
        fields(manifest, "version", "workflow", "candidate", "rollback")
        require(type(manifest["version"]) is int and manifest["version"] == 1)
        require(manifest["workflow"] == digest("fixture-preflight-workflow-v1"))
        verify_bundle(manifest["candidate"])
        verify_bundle(manifest["rollback"])
        require(manifest["candidate"] != manifest["rollback"])
        manifest_digest = digest(manifest)
    except InvalidFixture:
        return "fixture-manifest-rejected"

    receipt = envelope["staging_receipt"]
    try:
        fields(receipt, "claims", "seal")
        claims = receipt["claims"]
        evidence = ("artifact", "qualification", "config_compatibility")
        fields(claims, "issuer", "workflow", "manifest", "attempt", "issued", "expires", "checks", *evidence)
        fields(claims["checks"], *CHECKS)
        require(all(result is True for result in claims["checks"].values()))
        require(all(matches(claims[field], DIGEST) for field in evidence))
        require(claims["issuer"] == STAGING_ISSUER)
        require(claims["workflow"] == digest("fixture-staging-workflow-v1"))
        require(claims["manifest"] == manifest_digest)
        require(matches(expected_attempt, DIGEST) and claims["attempt"] == expected_attempt)
        verify_record(claims, receipt["seal"], STAGING_KEY)
        receipt_digest = digest(receipt)
    except InvalidFixture:
        return "fixture-staging-rejected"

    approval = envelope["release_approval"]
    try:
        fields(approval, "claims", "seal")
        acceptance = approval["claims"]
        fields(acceptance, "issuer", "decision", "manifest", "receipt", "attempt", "issued", "expires")
        require(acceptance["issuer"] == ACCEPTANCE_ISSUER and acceptance["decision"] == "APPROVE")
        require(acceptance["manifest"] == manifest_digest and acceptance["receipt"] == receipt_digest)
        require(acceptance["attempt"] == expected_attempt)
        verify_record(acceptance, approval["seal"], ACCEPTANCE_KEY)
        require(acceptance["issued"] >= claims["issued"])
    except InvalidFixture:
        return "fixture-acceptance-rejected"

    return "fixture-match"
