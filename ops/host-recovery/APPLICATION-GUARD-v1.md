# Host application config validation v1

**Offline, read-only, opt-in component. Not complete preflight, plugin/Compose
schema validation, authenticated policy, an installed supervisor/fence, an old-start
oracle or recovery/replay acceptance.** No runtime config loader or management
endpoint was changed. Tests use synthetic private files and scripted host boundaries,
not an installed manager, daemon, real credential or producer package.

## Reuse the application's schema, not its normalization pipeline

`internal/config.ValidateRecoveryConfigBytes` reuses the actual `Config` field types,
v8 layout translation and selected pure intrinsic validators. It does not call
`ParseConfigBytes`/`LoadConfig`: those paths can hash management secrets, resolve
plugin paths, log normalizations and drop/sanitize entries. A successful runtime
normalization is not proof that the captured source passed a recovery guard.

The recovery validator:

- accepts a single mapping document, bounded to 4 MiB; callers must first apply the
  strict YAML subset/node/depth limits of the exact-input guard;
- supports legacy or v8 layouts, refusing mixed layouts instead of allowing a
  winning value to conceal a conflicting legacy subtree;
- checks declared host fields recursively using their actual YAML tags, including
  inline SDK fields, maps, lists and pointers; rejects unknown fields and implicit
  type coercions (such as a quoted port or numeric header string);
- refuses explicit null in host-typed positions, even where the runtime loader
  permits defaults/inheritance; this is an intentionally conservative subset;
- uses the existing strict custom image-generation-mode and web-search-cache
  decoders, including their supported boolean/string and duration/integer unions;
- checks API-key group/key source types **before** expansion, so empty groups,
  overridden group settings, skipped nulls or overwritten compatibility key lists
  cannot erase invalid source fields. Runtime-only `auth-index`/`auth_index`
  metadata is not accepted in these recovery inputs;
- invokes the existing model-catalog source syntax, trusted-proxy, credential
  weight, in-flight observation, intrinsic concurrency, live-media-relay and
  web-search-cache validators. Defaults are applied only in memory for the
  existing in-flight/concurrency validation contracts, not to captured bytes;
- returns a fixed `recovery-config-invalid` refusal, never parser details or
  credential/config values; does not modify input bytes, access configured paths,
  hash secrets, start background updaters, load plugins or contact a service.

This is not every operational constraint: there is no daemon/image availability,
credential usability, external lifecycle timing invariant, model readiness,
approved exact-nine alias/Meta policy or full plugin schema check here. Dynamic
payload maps are intentionally extensible. Each plugin instance must be a mapping;
only its host-owned `enabled` and `priority` fields are typed by this validator.
Other options remain opaque. In particular, a misspelled Meta option is **not**
validated merely because the host can carry its raw YAML. The complete separately
approved plugin stanza and the producer's actual schema still need validation.

## Stricter helper and coordinator composition

Build the development helper from this verified repository:

```sh
go build -o <disposable-output> ./ops/host-recovery/inputguard/applicationcmd
```

There are no arguments, paths, environment configuration, service operations or
live defaults. This is development output, not an installed or approved helper.
The helper accepts the same exact `host-recovery-input-request-v1` envelope as the
comparison-only helper. `VerifyApplicationBundle` first requires all raw pins,
strict YAML and exact changes for config, Compose source and frozen render, then
validates **both** config documents. A good candidate cannot conceal an invalid
original; a good original cannot conceal an invalid candidate. Full Compose
rendering/schema and plugin-specific schema checks are not added by this mode.

The stdout receipt has a distinct schema:

```json
{"schema":"host-recovery-application-input-result-v1","matched":true,"application_validated":true,"start_authorized":false}
```

Any validation failure emits the same fixed object with both result booleans
false and exits nonzero. Partial writes, malformed input or command arguments
cannot produce successful confirmation. No source/error text is emitted.

`ApplicationInputGate` inherits the existing descriptor-execution, executable pin,
protected fresh snapshot/recapture, deadline, transport and boundary checks from
`ExactInputGate`, but requires this exact application receipt. An independently
repinned comparison-only helper cannot downgrade the requirement. Use it with
`GuardedBoundary` and `ProtectedInputSnapshot` at admission and stopped validation;
no second installation lock, cached green receipt or relaxed input approval is
introduced. The existing comparison-only helper/API keep their old semantics.

Before-arm refusal creates no intent/stop. A stopped refusal skips candidate
mutation/start and delegates to the existing separate recovery path; candidate
schema validation is not a prerequisite for baseline restoration. Baseline
verification and service start still require the independent complete oracle.
The tests exercise real built helpers/private files with **scripted** manager,
fence, recovery oracle and alert transport. A test-only stopped fault updates
all byte/request pins to force a reached schema refusal; this is deliberate
fault injection, not permission or code to repin an armed operational attempt.

## Evidence limits and remaining work

Tests retain a reproduced initial false green: the first implementation validated
only expanded groups, allowing invalid source fields to disappear. Source-group
prevalidation fixes it. The unchanged runtime v8 validator remains intentionally
more permissive; no management endpoint or runtime parsing behavior is modified.
A separate first-red fixture assumed negative credential weights were invalid;
the actual contract normalizes them to zero. The test now uses the real upper
bound. That fixture correction is not a product bug fix or negative-weight policy
change.

Actual Compose rendering with pinned tool/interpolation inputs, Compose and
plugin-specific schema validation, authenticated policy/role/pin provisioning,
complete baseline/image/replay/no-plugin pre-start oracle and persistent
supervisor/worker/fence integration remain unfinished. A host-schema receipt
cannot release a startup fence or grant a terminal outcome. The approved full-
system disposable matrix, measured inclusive phase allocations, external alert
sink, genuine probe/container/source binding and asynchronous producer drain
remain required. No full-system/timing/downtime or production acceptance follows
from component tests or bounded fuzz execution counts.

REA angle: reuse the application's current exported types, layout implementation
and pure validators, with source-shape checks before lossy runtime expansion,
rather than a second hand-maintained config schema or a live parse/load operation.
