# Replay collection v1 — prefix components, acceptance unavailable

This is source/component documentation, **not an operational probe, a complete
collector/verifier, or production acceptance**. No source or release pin changes.
There is no live path, daemon access, credential/config scrape or network call.

## Asynchronous transport is not request completion

The producer transport correction specifies a bounded asynchronous 128-record
FIFO and one writer. Startup precedes decisions. Inference and shutdown do not
wait for sink I/O. Saturation disables admission and preserves the admitted prefix;
a terminal `replay-producer-failure-v1` is only best-effort when the sink resumes.
Partial/error writes stop output. The corrected immutable handoff reports source
`c54c8c86989032f269ebfb49e95c6fb16fb9f2db`, source tree
`11dbe1a400a5c834c42aec651699fcd4fb29df3d`, package ZIP SHA256
`eaa9cf0281e979e26cc2d72a7a32a238bb133c4d0681ecb1b216cb5a45c52439`,
extracted library SHA256
`bb306f57220b1906713766597b57041b0be68a9db51b63b8c33c45f06827c281`,
and schema SHA256
`a7a0a411df5cc4e28d693936f8f2dafd15a5853bc9e6d7c38997af322d60efd7`.
These are producer-reported integration references, not independently verified
artifacts, accepted release pins, merged/review approval or a drain boundary.
No corrected package was installed or executed by this checkpoint. Reverify exact
source/schema/package correspondence during integration; never mix generations
of chunked artifacts. The historical fixture below is not that build.

This QA-corrected producer is reported to use raw syscall writes so EPIPE reaches
sticky failure handling rather than process-terminating SIGPIPE, and to check both
pre/post-build Git status exits before publishing a package. These are reported
component/packaging fixes, not independent reruns here. The bounded metadata/event
contract and schema are unchanged; no flush RPC/health attestation was added.
Version 0.2.4 remains unreleased development output, not a replacement production
pin. Integration use remains gated on producer review/merge and separate artifact,
integration and release checks. Surviving a broken pipe never validates evidence.

Consequently, none of these establish complete evidence:

- successful HTTP completion, observed initial decisions or a green retry;
- no failure marker, an empty read, EOF, a stable file stat or contiguous event IDs;
- stopping/killing the producer and then observing EOF (queued records may be lost);
- an arbitrary quiet interval, a timeout, or a snapshot labelled "complete".

An apparently healthy prefix can precede a stalled writer, an unadmitted decision,
a retry, a correlated foreign drop, overflow, or ambiguous partial bytes. The
currently described producer has no flush RPC or health/drain attestation.
**Runtime replay acceptance remains unavailable without a separately implemented,
source-reviewed completeness boundary.** The collector cannot invent that boundary
or compensate by attaching current request IDs to logs.

The future boundary must independently establish that all decisions for the probe's
actual HTTP executions/retries were accounted, writer admission remained healthy,
and all admitted relevant records reached the independently bound opened sources,
with complete cursors/rotation/drain coverage. It must remain fail-closed under
worker/controller loss and queue/write/transport failure, and fit the inclusive
post-check deadline. A Boolean supplied by a caller is not its implementation.
This document records an integration requirement, not a speculative new ABI,
producer change, finalized handshake or an approved flush implementation.

## Implemented components and limits

### `host_recovery/collection.py`

`FileCapture` opens an explicit regular-file source through no-follow directory
handles. The caller supplies source identity and exact uid/gid/mode; group/world
writable sources, symlinks, hardlinks, special files and xattrs are refused. The
handle is retained across snapshots. Every full prefix starts at offset zero and
is bounded to 4 MiB. Observed leaf rotation, truncation, rewrite, unsupported
metadata and changes during a read fail closed. Previous prefix bytes must remain
identical; previous raw snapshots are never overwritten. Undetected changes
between observations are not claimed impossible.

Each acknowledged snapshot is first persisted to a unique 0600 raw file in an
explicit same-owner 0700 spool, with fsync/rename/directory-fsync/readback. Receipts
record actual opened device/inode, offsets, previous end, raw handle/digest and
empty-source accounting. A read or persistence failure poisons the capture; a
later healthy read cannot repair the gap. Even directory-fsync failure after
visible rename returns no acknowledgment. Filesystem calls cannot interrupt a
wedged kernel; real supervisor deadlines/watchdog integration remain required.

Every receipt says `coverage: prefix_only`, `producer_drained: false`. The source
path is not printed. This is only a regular-file adapter, not a Docker log-stream
opener, rotation follower or proof that a file really mirrors container stdout.
A file-source name/label never proves container provenance.

### `host_recovery/replay.py`

The parser requires bounded standalone ASCII NDJSON, exact startup/decision field
sets, real JSON integer tokens, valid parent/turn/model/UUID/sequence constraints
and contiguous startup-first records per nonempty source. Partial lines, duplicate
JSON keys, unknown schemas/fields, invalid counters and any producer failure
marker reject. A failure marker is rejected without guessing its pending field
shape. The bounded uint64 counter restriction is conservative; it does not broaden
the producer's strict nonnegative-integer contract.

Identical mirrored bytes deduplicate by event identity; conflicting copies reject.
Comparison inputs preserve the actual attempt/probe/request/parent/turn and exact
requested/resolved model mapping. No stale/concurrent/wrong-producer event is
relabeled. Both initial turns must be visible and second-turn kept evidence must
exist. Any correlated foreign drop rejects, including the first turn or an initial
decision before a green retry. An observed retry must follow its initial decision;
a missing/unobserved retry still cannot be excluded by this prefix analysis.

`inspect_spooled_prefix` wires capture receipts to restricted raw readback, hash,
size, offset and source-set checks before parsing. An omitted source cannot be
silently treated as empty. The supplied expected-source list still needs the
future manifest's independent authentication; reading that list is not proof of
all required producer/container sources. Neither digest syntax nor startup's
source/version strings authenticate approved package artifacts.

All report paths explicitly return `collection_complete: false`,
`producer_drained: false`, `replay_accepted: false`, `production_acceptance: false`
and list the unresolved obligations. There is no accepting mode or complete flag
that a caller may enable. Component shape/counter matches are not HTTP/tool proof,
container binding, source artifact proof or drain coverage. The coordinator is
not changed to accept these reports as its replay post-check.

The current parser conservatively refuses mixed non-NDJSON/host log lines instead
of swallowing possible producer errors. An actual daemon collector/demultiplexer
must retain and account the complete raw stream with a reviewed framing policy.
A missing source is an error, not `file_logging: not_configured`; that source-bound
startup declaration is checked only as data, pending artifact/manifest binding.

## Retained actual producer fixture

`tests/fixtures/producer-prefix-b6f95237.ndjson` is the **unchanged** delivered
`final-delivery/replay-events.ndjson` from producer source
`b6f95237f5f0e2f4576dc7b3a15e2e362fd22104`, not collector-generated linkage.

- Fixture SHA256: `065998f1e02cdc4b0bf8dadfedd4afacd496d43037ac5f807f1f6a0450c47af2`.
- Inspected source archive SHA256:
  `275fcd00189e4cf4672161f401e28ceff0966f4067e5e8077a0f036ab3280124`.
- Inspected producer schema SHA256:
  `a01cde1fa0a4e05cddbc7ad36f19eddb7df0de8429664f5a9e0f36fabde23f9f`.
- Delivery bundle SHA256:
  `d5dbc69439c9f8874251a5e7b12abb0da122ca84890aae092fd47c46bcb31daa`.

The fixture was captured by the producer's own synthetic two-turn component test.
It is deliberately unstamped (`source_revision` empty, `source_modified` true).
Those values remain unchanged and cannot be accepted as clean source provenance.
The newer asynchronous correction is not represented by these historical bytes.
Tests derived from this fixture mutate copies to exercise parser negatives; they
are explicitly synthetic, not actual new producer executions or container/RPC
integration. Failure-marker tests check fail-closed handling, not new-schema
conformance or a genuine queue-overflow drill.

## Still required

Real source-bound probe/HTTP tool linkage, ingress/RPC-to-producer execution,
container/source-handle/artifact binding, all configured source opening and
rotation, reviewed mixed-log framing, a genuine asynchronous completeness boundary,
bounded collector process/watchdog integration, final corrected producer schema
alignment, and the actual integrated negative/full-package matrix remain due.
No current test is a production timing result, an installed supervisor/fence or a
substitute for integrated Security/QA and Release Manager gates.

REA angle: use the inspected producer source/schema and actual output, existing
metadata ABI, Unix opened-file identity and durable raw artifacts. Do not infer
producer completion from transport quietness or invent a log linkage.
