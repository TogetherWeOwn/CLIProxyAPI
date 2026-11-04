# Strict YAML exact-delta guard v1

**Read-only comparison and opt-in coordinator barrier composition only. Not a
runnable host supervisor, Compose renderer, application/plugin schema validator,
authenticated policy loader or complete recovery/start oracle.** Existing recovery
and replay acceptance remain unavailable. Tests execute the built guard with
synthetic inputs; no live config, credentials, containers or service-manager
operations are used.

## Purpose and interface

`inputguard/guard.go` reuses the repository's existing pinned `gopkg.in/yaml.v3`
parser to compare actual YAML bytes rather than treating a synthetic JSON fixture
as YAML validation. The library has no filesystem or network access. The separate
`inputguard/cmd` helper uses stdin/stdout only, with no arguments or environment
configuration. Test builds are disposable development output, not installed helpers
or new accepted release identities.

- `SemanticHash` computes a typed, deterministic semantic SHA256 for one supported
  YAML value. This is a provisioning aid, not approval or attestation.
- `Verify` compares two mapping-root documents against exact changes. Every change
  names a literal mapping-key path, an exact old semantic hash and an exact new
  semantic hash. An empty hash denotes absence, distinct from explicit null.
- `VerifyBundle` requires three separate pairs: config, Compose source and frozen
  rendered Compose. Each pair must supply approved old/new **raw-byte** SHA256
  pins and its own exact semantic changes. Omission of any pair refuses validation.

The caller must independently authenticate the policy and pins, acquire immutable
input snapshots through the protected boundary and retain the installation lock
and writer/start fence. Do not derive an accepted policy from the candidate under
test. A self-consistent digest or successful comparison does not prove approval.

## No wildcard exclusions

A change replaces exactly one value, with both its original and resulting content
bound to hashes. An addition/removal may address one exact subtree, such as the
approved plugin stanza or original replay stanza. A replacement is **not** an
ignored region: unexpected content inside it still fails its exact hash check.
Other subtrees must match after applying the changes to the original tree.

Paths must be nonempty, nonoverlapping, unique and bounded. There is no whole-
document path, prefix exclusion, regular expression, array index or wildcard
interpretation. Keys containing dots or `*` are literal keys, not traversal syntax.
Sequence changes require an exact hash of the complete sequence and retain order.

The guard does not decide which paths the installation is allowed to change. The
policy admission layer must constrain the exact approved Meta stanza, exactly nine
alias paths, original replay and selected Compose service image while preserving
unrelated maps/images. In particular, do not approve whole plugin/alias/service-map
replacements as a shortcut. The tests exercise nine individual alias paths and
one plugin entry, not a whole-map exclusion.

Comments, mapping ordering and equivalent string quoting are not semantic changes;
raw-byte pins still bind those differences. Types, sequence order, absent versus
null, other services' images and unrelated plugin/alias values are significant.
Numbers retain their accepted lexical representation; numerically equivalent
spellings do not silently become an approved change.

## Conservative YAML subset

Each document is bounded to 4 MiB, 65,536 parsed value/key nodes and nesting depth
64. Comparison roots must be mappings. Supported nested values are mappings with
unique nonempty string keys, ordered sequences and explicit string/boolean/null/
int64/finite float64-compatible scalars. Integer/float spelling uses a restricted
JSON-number grammar; integers must fit int64. Strings may be quoted or block values.

Refuse duplicate keys (also nested or differently quoted duplicates), non-string
keys, anchors/aliases, merge keys, custom tags, binary/timestamp values, multiple
or trailing empty documents, malformed inputs, implicit empty nulls, legacy octal/
hex/underscored numbers, nonfinite values and overflow. An overflowing plain float
that the YAML parser falls back to a string is also refused; an intended numeric-
looking string must use quotes or explicit `!!str`. Unsupported input refuses
rather than being normalized by a more permissive second parser.

The node/depth bounds apply after the bounded YAML parse; they are not hard CPU,
memory or execution-time guarantees for the parser. Production helper containment
and inclusive deadline enforcement remain required. Errors contain fixed codes,
not parser diagnostics, keys, values, filenames, hashes or source contents.

## Restricted helper protocol and coordinator composition

Build the repository-owned development helper with
`go build -o <disposable-output> ./ops/host-recovery/inputguard/cmd`. There are no
installation commands or live defaults. The helper accepts exactly one bounded
JSON object on stdin:

- `schema`: `host-recovery-input-request-v1`.
- `config`, `compose_source`, `frozen_rendered_compose`: mandatory pair objects.
- Each pair requires `before`, `after` (canonical padded standard base64 of the
  captured YAML bytes), `before_sha256`, `after_sha256` (independently approved raw
  pins), and `changes` (an array, including an explicit empty array when unchanged).
- Each change requires `path` (literal string array), `before`, `after` (semantic
  hashes, or empty string for absence). The earlier nonoverlap/path limits apply.

Unknown, missing, duplicate, differently cased and null fields, trailing documents,
invalid/noncanonical base64 and over-limit requests refuse. Maximum request size is
36 MiB, covering six 4 MiB YAML documents and policy. Receipt stdout is a single
fixed `host-recovery-input-result-v1` object with `matched: true|false` and
`start_authorized: false`. Exit zero requires a matching bundle and a complete
receipt write; any other exit/output is not confirmation. Parser diagnostics,
input values, hashes and paths are never included. There is no provisioning or
semantic-hash command and no schema/rendering claim in this receipt.

`host_recovery/input_gate.py` supplies opt-in composition:

1. `InputApproval` binds the original intent, serialized request, executable digest
   and numeric helper owner. These pins must come from independently authenticated
   provisioning; the data class and hashes do not supply it.
2. `ExactInputGate` borrows an already-open protected helper descriptor. Every call
   checks regular/single-link metadata, protected mode, owner, size, digest and
   unchanged inode signature. Execution uses `/proc/self/fd/<fd>`, not a reopened
   path. The caller's required `check()` must revalidate the installation lock,
   supervisor ownership, original protected path/handle identities and writer
   fence. No root/same-uid-hostile defense or namespace attestation is claimed.
3. The required `snapshot(intent, deadline=...)` captures actual source and frozen
   render bytes through protected descriptors at each barrier. It must not return
   cached proposal bytes as proof of current input. The gate checks the approved
   request digest before dispatch and recaptures after the helper reply. The test
   implementation uses descriptor-relative synthetic files; an authenticated
   operational source/render snapshot implementation remains due.
4. Nonblocking full-duplex stdin/stdout avoids request/output pipe deadlocks.
   Request bytes never enter argv, the environment, logs or receipts. Only the
   helper descriptor is passed, environment is minimal and cwd is `/`. Output is
   capped at 4096 bytes and must match the exact positive receipt, exit zero and
   complete input delivery. Partial/extra/authorizing receipts, broken pipes,
   overflow, helper failure or deadline/clock uncertainty refuse with a fixed code.
5. `GuardedBoundary` first retains the existing underlying preflight or stopped
   revalidation check, then requires fresh exact-input comparison. Admission
   failure reaches no intent/arm/stop. A stopped failure follows the coordinator's
   existing recovery path without forward mutation/candidate start. Existing
   listener/schema checks cannot be replaced by a comparison result. Recovery
   methods delegate unchanged so bad candidate input does not prevent restoration;
   they still require the separate complete baseline/start oracle.

Preflight takes an explicit external deadline, before the durable arm. Stopped
validation receives the original forward revalidation phase deadline; capture,
helper hashing, I/O, post-reply recapture and revalidation share it. Failed helpers
are killed without an extra unmetered wait; pending children need `reap()` and
independent manager/group reconciliation. Helper death is not complete quiescence.
Callbacks/kernel operations can still wedge: checks before/after cannot implement
a hard-real-time manager watchdog or cancel daemon operations. Operational manager
containment, authenticated provisioning and complete host fencing remain required.

Real built-helper tests prove descriptor/pipe comparison and ordering against a
scripted host boundary only, not installed-systemd/daemon recovery. They include
source drift after arm, semantic mismatch despite valid raw pins, helper replacement,
source/helper changes during verification, actual stalled/overflowing/early-exit
helpers, malformed receipts, EIO/ENOSPC read injection and alert-receipt disk failure
with an independent transport attempt. No live input, actual Compose rendering,
application/plugin schema, archive/extracted-library check, producer or external
alert sink is exercised.

## Evidence and remaining integration

Repository-owned synthetic YAML tests cover exact additions/removals/replacements,
nine aliases, unrelated map/image preservation, strict type/sequence differences,
raw pin independence for all three roles, parser ambiguity/bounds, policy overlap,
wrong old/new hashes, source redaction and literal path keys. Race tests and bounded
fuzzing test this component only; they prove no live rendering or host recovery.
The first regression run exposed the YAML parser's overflowing-float-to-string
fallback; its red receipt and corrected refusal are retained.

Still required before this can become an operational barrier:

1. Authenticate restricted policy/pins and package/helper/interpreter identity.
2. Acquire all real source inputs and frozen render through protected handles;
   bind renderer/tool versions and interpolation-input identity. Actually render
   with those inputs, then independently compare and retain the captured bytes.
3. Validate the actual config, full approved plugin stanza, Compose and plugin
   schemas. The generic YAML subset and exact delta are not those schemas.
4. Bind artifact availability plus both plugin archive and extracted-library hashes.
5. Supply the operational boundary to the opt-in preflight **and** stopped
   revalidation composition and wire every other required guard, plus the separate
   complete restoration/start oracle, under original inclusive phase deadlines.
6. Exercise the pinned helper inside the approved disposable manager/daemon/full-
   recovery matrix, including persistence faults, source/renderer replacement and
   partial restoration. Current pure-Go tests are not that evidence.

Persistent supervisor/worker execution and complete boot/internal-restart/start/
writer/pending-operation fencing remain separate unfinished requirements. No claim
or YAML comparison alone may grant restoration, old start or a terminal outcome.
