# Strict YAML exact-delta guard v1

**Comparison component only. Not wired into admission, stopped revalidation or
recovery startup. Not a Compose renderer, application/plugin schema validator,
authenticated policy loader or complete start oracle.** Existing recovery and
replay acceptance remain unavailable. No host inputs, credentials, containers or
service-manager operations are used by these tests.

## Purpose and interface

`inputguard/guard.go` reuses the repository's existing pinned `gopkg.in/yaml.v3`
parser to compare actual YAML bytes rather than treating a synthetic JSON fixture
as YAML validation. It has no executable entrypoint, filesystem or network access.
This is a small source-level dependency for the eventual restricted guard helper;
no helper binary, installation default or release identity is created here.

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
5. Wire all checks into preflight **and** stopped revalidation and the independent
   complete restoration/start oracle, under original inclusive phase deadlines.
6. Exercise the pinned helper inside the approved disposable manager/daemon/full-
   recovery matrix, including persistence faults, source/renderer replacement and
   partial restoration. Current pure-Go tests are not that evidence.

Persistent supervisor/worker execution and complete boot/internal-restart/start/
writer/pending-operation fencing remain separate unfinished requirements. No claim
or YAML comparison alone may grant restoration, old start or a terminal outcome.
