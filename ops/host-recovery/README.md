# host-recovery-v1 — source implementation in progress

**Component source only. Not an installable recovery supervisor, a live run
instruction, a release artifact, or production acceptance.** There are no live
path defaults, service installation commands, management API calls, or credentials
in this subtree. Do not execute the received launchers or use this partial source
as a substitute for the accepted production binaries.

## Implemented so far

- `host_recovery/durable.py`: no-follow fd-relative filesystem access, one
  installation-directory lock, bounded regular-file reads, restricted atomic
  writes with file fsync → rename → directory fsync → readback acknowledgment.
  Failed/ambiguous writes raise even if destination bytes are visible. Staging
  evidence is retained, not silently cleaned or treated as a terminal record.
- `host_recovery/inventory.py`: complete bounded directory/tree inventory,
  original bytes/uid/gid/mode, a separately supplied exact-nine auth selection,
  strict seven-disabled/two-enabled validation, and immutable restricted baseline
  blobs/manifests. Mixed directories retain unrelated providers. No hardcoded
  synthetic filenames are used by the implementation. Unsafe links, hardlinks,
  special files, xattrs/ACLs, cross-device entries, unsupported modes and observed
  concurrent inventory changes fail closed. These are **not restore operations**.
- `host_recovery/budget.py`: explicit 120/180/300-second policy validation,
  positive phase caps and safety margins, monotonic same-boot accounting,
  detection charged from the actual trigger/work deadline, non-resetting phase
  deadlines, and forward-promotion refusal after a recovery trigger. This is an
  accounting primitive, **not yet a manager-enforced watchdog**. A measurement
  digest is structurally required; verifying/authenticating the accepted drill
  and policy belongs to supervisor admission. Test caps are synthetic, not a
  measured operating policy. There is intentionally no default allocation.
- Diagnostic HTTP ingress → executor → plugin metadata bridge, using the
  existing metadata ABI without a provider-kit change. See the carrier below.

The filesystem and lock operations assume an explicitly accepted ownership
contract and exclusion of cooperating writers. They do not defend against hostile
root/same-uid actors. A lock-owner structure is not proof of a real manager
invocation; the supervisor still has to verify that identity at admission.

## Diagnostic carrier

The server consumes these HTTP headers before engine-configured middleware,
request logging, credential selection and request building:

| Header | `cpa_recovery_v1` metadata field |
| --- | --- |
| `X-CPA-Recovery-Attempt-Id` | `attempt_id` |
| `X-CPA-Recovery-Probe-Id` | `probe_id` |
| `X-CPA-Recovery-Request-Id` | `request_id` |
| `X-CPA-Recovery-Parent-Request-Id` | `parent_request_id` |
| `X-CPA-Recovery-Turn` | integer `turn` |

IDs are 1–64 ASCII bytes, starting with an alphanumeric character and containing
only alphanumerics, `-`, `_`, `.`, `:`. Turn is exactly `1` or `2`; turn 1 has no
parent, turn 2 requires a distinct parent request ID. No trimming, comma folding,
duplicate headers, unknown diagnostic fields, or partial envelopes are accepted.
An invalid envelope has **no diagnostic metadata**, but does not change normal
HTTP authentication/error semantics. Every `X-CPA-Recovery-*` header is removed,
even if invalid/unknown; explicit SDK headers and plugin executor headers are
also filtered. Authorization and session headers are untouched. IDs are untrusted
diagnostic data, never credentials, auth-selection hints, or proof of replay.
Requested model stays in existing `requested_model` metadata; resolved model stays
in the executor request's model field.

Ingress/handler/plugin-seam tests are component evidence, not actual Meta replay
decision evidence. The canonical Meta producer, producer startup markers,
container/source-handle provenance, collector, two-turn probe and verifier still
have to be integrated. No timestamp grep or diagnostic/container label substitutes
for those missing links.

## Safe component verification

From this repository's verified isolated worktree:

```sh
python3 -I ops/host-recovery/tests/run.py
go test -timeout 180s ./internal/recoverycorrelation ./internal/api/middleware ./internal/api ./sdk/api/handlers ./internal/pluginhost
go build -o test-output ./cmd/server && rm test-output
```

The Python runner explicitly adds only this repository-owned package to isolated
Python's path. It creates fresh synthetic temporary roots. No unit is installed,
no daemon is contacted and no real auth/config/backup is read. Tests use fake
clocks and deterministic fault injection, not wall-clock sleeps. Filesystem fault
injection includes EIO/ENOSPC, write/fsync/rename/directory-fsync/readback, partial
writes and terminal-looking destination bytes after uncertain durability.

The independent alert helper attempts its injected transport even if receipt
persistence raises. It distinguishes disk receipt, strict transport receipt and
human acknowledgment. It is **not yet an alert listener or preflight handshake**.

## Remaining acceptance work (not implemented or not proved)

1. Persistent systemd supervisor with admission, durable active-attempt latch,
   separate manager-owned forward/recovery cgroups, all six semantic operations,
   boot fence and reconciliation after manager/worker loss. No second Bash
   rollback owner.
2. Narrow daemon boundary, immutable object IDs registered durably before start,
   ambiguous-create reconciliation, daemon/reboot restart prevention and complete
   cgroup **plus daemon-object** quiescence before restore.
3. Full write-set conversion, partial/idempotent restoration, complete independent
   bytes/metadata/config/Compose/image/replay/no-plugin oracle before old start,
   durable terminal state handling and independent listener challenge/receipt.
4. Actual strict source YAML/Compose + frozen-rendered Compose, schema/policy,
   authenticated approval, interpolation/tool identity, artifact dual hashes and
   preflight/stopped revalidation. The historical r3 comparator is not that
   integration and is not imported as if it were.
5. Source-bound probe/producer/collector/verifier with cursors/rotation/raw hashes,
   correlated drop/conflicting duplicate negatives and both tool-linked turns.
6. Actual pinned package disposable systemd/cgroup/daemon matrix, measured phase
   caps/safety margins, independent restoration/start oracle and raw availability
   samples/censoring. No systemd/daemon capability is asserted by a component test.
7. Complete normal PR checks/reviews, a narrow authorized publication base, and
   exact reviewed-head merge. No release pin or production action is authorized.

See [the versioned runbook](RUNBOOK-v1.md) for retained invariants and blocked
operational gates. Reference archives remain provenance/negative material, not
production defaults; [provenance](provenance.json) identifies the inspected bytes.
Prior reference test counts are historical evidence, not tests rerun here.
