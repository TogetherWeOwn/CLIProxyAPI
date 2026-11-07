# Source-pinned Meta configuration shape guard v1

Development component only. No plugin loading, production operation, release-pin
replacement, migration approval, recovery or service-start authority. The existing
[runbook](RUNBOOK-v1.md) and all integrated acceptance gates remain required.

## Inspected source, not an invented plugin schema

Canonical repository: `https://github.com/TogetherWeOwn/cliproxy-provider-meta`.
Reviewed source `c54c8c86989032f269ebfb49e95c6fb16fb9f2db`, tree
`11dbe1a400a5c834c42aec651699fcd4fb29df3d`, later merged at
`30f0d6a285e42b98fbbcf5aeeb3549c550bd72b4`. These identities are distinct. This
profile binds the reviewed source, not the squash identity or historical v0.2.2.

Source archive SHA256:
`f23107911154481c1f593d4bf80d477d6708200f5a25086b1ecbe175ddf392b0`.
Transport evidence ZIP SHA256:
`05b825ef12eca6c63694ba82b7124dd1067e02473def5d5ddab983a37af47e1a`.
All 27 evidence-manifest entries were verified before reading the nested archive;
no extraction-cwd execution, producer build, library loading or package download
was needed. The initial attempt to open the evidence ZIP as tar failed; the format
was corrected before reading it. That was an inspection error, not a product test.

The exact `config.go` bytes and MIT license are retained as **inert text** under
`inputguard/testdata/meta-config/`. Config SHA256:
`4665020ba0b2688dda79578f3f8717878a50212c8fd092f856c728c563ddbfd8`.
The producer's `pluginConfig` has only `reasoning-replay`, whose fields are
`enabled` (bool) and `models` (string list). Missing values default off/empty.
Its parser discards `yaml.Unmarshal` errors. Calling that parser and observing a
zero config therefore would not prove that malformed input was valid.

`MetaConfigProfile` identifies a **conservative source-derived shape projection**.
This is not an upstream-published JSON schema or execution of the producer parser.
It refuses unsupported fields rather than guessing what a future plugin does.

## Scope and composition

`VerifyMetaRequest` / `metacmd` first require the entire existing
[restricted Compose input check](COMPOSE-GUARD-v1.md): exact deltas/raw pins, actual
host-owned config validators, real pinned compose-go schema/model rendering and
both frozen models. Both config sides additionally validate the Meta subtree.

- Baseline Meta plugin may be absent. If present, it must have a supported shape,
  even if disabled; disabled state cannot hide malformed options.
- Candidate must explicitly set `plugins.enabled: true` and
  `plugins.configs.meta.enabled: true`.
- Meta subtree supports host-owned `enabled` (bool), `priority` (integer), and
  `reasoning-replay` (mapping of optional bool `enabled` and string-list `models`).
- Duplicate/unknown/case-variant keys, nulls, coercible strings, numeric/bool model
  entries, aliases and unsupported YAML are refused. An explicit empty replay map
  or empty model list is a valid **shape**, not an approved replay policy.
- Unknown Meta options, including `store` metadata, refuse in this profile. Do not
  strip an accepted field or repin a policy to get a pass. Inspect its canonical
  semantics and extend the reviewed profile before using such a stanza.
- Other plugin-owned subtrees are opaque and untouched; their schemas are not
  validated here. Existing exact policy still protects all unrelated fields.

The bounded stdin-only envelope has exact keys `schema`, `producer_config`,
`inputs`. Schema is `host-recovery-meta-input-request-v1`; `producer_config` must
match `MetaConfigProfile`; `inputs` is the unchanged Compose request.
`ProtectedMetaSnapshot` specializes only serialization inside the same retained
nine-file descriptor/rehash boundary; no extra file or ambient lookup is added.
`MetaInputGate` requires the distinct fixed `host-recovery-meta-input-result-v1`
receipt with `meta_config_validated: true` and `start_authorized: false`.
A successful Compose-only receipt cannot downgrade the selected profile.

The same opt-in `GuardedBoundary` composes at admission and stopped forward
revalidation, with fresh post-helper capture. Recovery delegation stays unchanged:
invalid candidate config cannot block the separate baseline restoration path.
Original intent/request/helper pins, caller-held installation lock, protected
handles, writer fence and inclusive deadline checks remain mandatory.

## What a shape receipt does not prove

Authenticated policy and source-to-installed-artifact provisioning remain external
and unfinished. The profile identifier and digest are not approval signatures.
The guard does not prove the selected Meta subtree belongs to an actual installed
library, full accepted A+B stanza, exact replay/pattern migration, nine aliases,
coverage of retained replay patterns, artifact/image availability, actual Docker
CLI/runtime/path equivalence, or full recovery/pre-start oracle.

In particular, schema-valid `enabled: false`, blank patterns or empty models do
not establish the accepted replay policy. Enforce the exact approved values and
unrelated-field preservation through the authenticated delta policy, not schema
shape alone. Full original-fork configuration support and reversal semantics need
the separately source-bound baseline oracle. Do not remove original state merely
to satisfy the stock application schema.

No producer was executed and no archive/library release identity changed. Producer
behavior, genuine two-turn tool linkage, container/log-source provenance and
asynchronous drain/completeness remain unproven. HTTP completion, silence, EOF or
absence of a terminal failure marker cannot supply that boundary.

Tests use actual built helper/private files but scripted manager/fence/oracle/alert
boundaries. Synthetic candidate/recovery outcomes retain the start fence and
`production_acceptance: false`. They prove neither installed-systemd/daemon
recovery nor full package/timing/external-notification/downtime acceptance.
