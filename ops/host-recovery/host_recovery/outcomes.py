"""Strict worker result envelopes; reports and digests are not recovery authority.

Only an independently provisioned oracle can corroborate the referenced evidence
and current baseline/readiness. This module neither implements that oracle nor
settles the installation latch. No paths, exception text or credentials occur in
the bounded worker envelope.
"""
from .durable import Rejected, canonical, digest
from .inventory import HASH


def validate_result(value, request, claim):
    expected = {"schema", "request_id", "intent_sha256", "claim_sha256", "outcome", "evidence_sha256"}
    if (type(value) is not dict or set(value) != expected
            or value["schema"] != "host-recovery-worker-result-v1"
            or value["request_id"] != request["request_id"]
            or value["intent_sha256"] != request["intent_sha256"]
            or value["claim_sha256"] != digest(canonical(claim))
            or type(value["outcome"]) is not str
            or value["outcome"] not in ("baseline_restored", "recovery_unresolved")
            or type(value["evidence_sha256"]) is not str or HASH.fullmatch(value["evidence_sha256"]) is None):
        raise Rejected("supervisor-worker-result-unconfirmed")


def expected_oracle(intent, result):
    """Exact independent verification receipt, never a worker-supplied assertion.

    The oracle must inspect original bytes/metadata/all roots, original image,
    replay/no-plugin state, writer/start fence and old readiness, and authenticate
    the referenced evidence and source/role bindings. Matching dictionaries in
    tests are only scripted boundary evidence, not implementation of those checks.
    """
    return {"schema": "host-recovery-result-oracle-v1", "result_sha256": digest(canonical(result)),
            "evidence_sha256": result["evidence_sha256"], "baseline_sha256": intent["baseline_sha256"],
            "object_id": intent["old_object_id"], "original_image": True, "original_replay": True,
            "new_plugin_absent": True, "complete_write_set": True, "metadata_verified": True,
            "all_writers_stopped": True, "start_fence_retained": True, "old_ready": True}
