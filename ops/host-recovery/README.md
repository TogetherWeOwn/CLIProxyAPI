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
- `host_recovery/journal.py`: immutable restricted attempt intent and separately
  durable arm point; exact stopped/no-restart daemon-object registration before
  candidate-start eligibility. Registration/terminal uncertainty never replaces
  the original intent or grants a start. Recovery revokes forward eligibility.
  Reopening a journal always fences forward work, including when a terminal file
  is visible. **Settlement/archival and new admission after supervisor restart are
  not implemented**; this intentionally conservative latch is not yet a complete
  usable supervisor lifecycle.
- `host_recovery/restore.py`: bounded whole-root restoration of original bytes,
  uid/gid/modes, with an explicit accepted list of candidate-only additions.
  Unknown entries, type changes, unsafe links/metadata and tampered baselines
  refuse restoration before mutation. Reserved deterministic staging names allow
  retry after partial writes/fsync/rename failures. A final independent rescan
  checks the complete tree. One ownership domain and owner-accessible directories
  per root are supported; unsupported access is refused, never relaxed. This
  does **not** verify image/replay/plugin semantics or stop any writers.
- `host_recovery/coordinator.py`: component forward/recovery ordering, injected
  manager/daemon boundaries, registration-before-start, strict post-check and
  restoration-oracle acknowledgment shapes, original versus recovery errors,
  inclusive deadline accounting and independent alert attempts. Calls receive
  phase deadlines and are checked afterwards; the concrete manager must enforce
  them while calls are running. An observed manager failure timestamp is charged
  from that event, not from delayed detection. No blocking-call watchdog,
  persistent service loop, resume/continuation, actual manager, listener or
  executable post-check implementation exists here yet. Mock acknowledgments
  are **not** complete host/package/start-fence evidence.
- `host_recovery/commands.py`: bounded local subprocess output and same-clock
  deadlines, a fixed minimal environment and no shell/session escape. Helper
  failure, output overflow or lost reply is an uncertain operation, not a daemon
  cancellation. Deadline cleanup kills only the helper; the owning supervisor
  must reap it and independently quiesce the complete manager/daemon boundary.
  This is **not a privilege boundary or a hard-real-time watchdog**.
- `host_recovery/manager.py`: explicit systemctl command generation, strict unit
  property/fragment pins, distinct non-nested forward/recovery unit bindings,
  whole-control-group SIGKILL and repeated manager/cgroup-v2 observations.
  Non-root, non-delegated, no-capability mutator properties are required. The
  recursive kernel populated bit, no pending job and inactive state are all
  checked; PID exit alone is insufficient. Missing/reused groups or changed
  invocation/configuration refuse or remain pending. No units are installed or
  started. Tests use **scripted manager/fake-mount fixtures**, not actual systemd.
- `host_recovery/daemon.py`: explicit local Docker endpoint, projected inspection
  without environment/mount/credential output, full immutable old/candidate IDs,
  exact installation/attempt ownership, no-restart/no-auto-remove checks and
  reinspection of every stopped object. Multiple attempt-owned objects are all
  considered for recovery; short/foreign/changed IDs fail closed. It exposes no
  create/start/update/restart/remove operation. Tests use **scripted CLI replies**,
  not an actual daemon or installed authorization boundary.

The manager and daemon adapters both require an independent, currently enforced
start/pending-operation fence. Their injected Boolean acknowledgment is an
interface requirement, **not an implementation or proof of that fence**. Source
property pins alone do not authenticate policy approval. The persistent supervisor,
privilege broker, boot/restart/start authorization and integration of these
adapters with the coordinator remain missing. An empty cgroup, `restart=no`, stable
inspection snapshots or a killed helper cannot substitute for those prerequisites.
No broad Docker/root permission is provided or requested by this source.

- `host_recovery/collection.py`: explicit no-follow regular-file handles and
  restricted durable full-prefix snapshots with observed identity, offsets,
  raw hashes and genuine empty-source accounting. Observed rotation/truncation/
  rewrite, read failure and persistence uncertainty poison the capture. This is
  **not** a daemon/stdout opener, rotation follower or container provenance proof.
- `host_recovery/replay.py`: bounded strict startup/decision NDJSON inspection,
  byte-identical mirror deduplication, exact request/model/turn matching and
  correlated foreign-drop/conflicting-duplicate negatives. Any producer failure
  marker, partial/unknown record, gap or malformed integer rejects. Spool-receipt
  readback wires actual raw hashes/offsets/source-set checks to this parser.
  **Every report remains prefix-only and non-accepting.** HTTP completion, EOF,
  silence, contiguous sequences and no failure marker cannot establish an
  asynchronous producer's complete drain. There is no accepting mode, flush
  implementation, actual HTTP probe or real container/source mapping here.
  See [collection status and immutable fixture provenance](REPLAY-COLLECTION-v1.md).
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

IDs are 1–128 ASCII bytes, matching the producer carrier contract, starting with an alphanumeric character and containing
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
decision evidence. A retained actual producer-output fixture now exercises the
prefix parser, without changing its unstamped identity or claiming current
producer execution. The canonical producer, startup/container/source-handle
binding, daemon collector, asynchronous completeness boundary, two-turn HTTP
probe and accepting verifier still have to be integrated. No timestamp grep,
quiet prefix or diagnostic/container label substitutes for those missing links.

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
2. Integrate the new manager/daemon observation/quiescence adapters with an actual
   independently enforced narrow start/pending-operation fence and persistent
   supervisor. Complete create/start authorization, immutable IDs registered
   durably before start, ambiguous-create reconciliation and daemon/reboot restart
   prevention. Scripted adapter tests do not prove complete cgroup **plus daemon**
   quiescence or install a privileged authorization boundary.
3. Full write-set conversion and integration of the tree-restoration component
   across every approved root; complete independent config/Compose/image/replay/
   no-plugin oracle before old start; safe journal settlement, supervisor resume
   and separately identified bounded recovery continuations; actual independent
   listener challenge/receipt. Strict mock receipt shapes do not prove semantics.
4. Actual strict source YAML/Compose + frozen-rendered Compose, schema/policy,
   authenticated approval, interpolation/tool identity, artifact dual hashes and
   preflight/stopped revalidation. The historical r3 comparator is not that
   integration and is not imported as if it were.
5. Integrate the prefix-capture/parser components with real source-bound HTTP
   probe/producer/RPC/container evidence, all required sources, cursors/rotation,
   mixed-log framing and both tool-linked turns. Establish a genuine source-reviewed
   asynchronous completeness boundary; prefix inspection cannot issue acceptance.
   Recheck the corrected producer's immutable source/schema/artifact delivery.
6. Actual pinned package disposable systemd/cgroup/daemon matrix, measured phase
   caps/safety margins, independent restoration/start oracle and raw availability
   samples/censoring. No systemd/daemon capability is asserted by a component test.
7. Complete normal PR checks/reviews, a narrow authorized publication base, and
   exact reviewed-head merge. No release pin or production action is authorized.

See [the versioned runbook](RUNBOOK-v1.md) for retained invariants and blocked
operational gates. Reference archives remain provenance/negative material, not
production defaults; [provenance](provenance.json) identifies the inspected bytes.
Prior reference test counts are historical evidence, not tests rerun here.
