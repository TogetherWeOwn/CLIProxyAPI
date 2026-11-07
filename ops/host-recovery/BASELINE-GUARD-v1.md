# Restored-input guard v1 — restricted component, not start authority

This opt-in guard checks **actual restored files**, separately from candidate
validation. It does not implement the persistent supervisor, complete host fence,
independent daemon/mount/readiness oracle or an installable recovery package.
Never run it against live credentials/config/backup paths to obtain test evidence.

## Inputs and provenance

The existing `WriteSetRecovery` context retains all independently approved root
handles under the caller's existing installation lock. `capture_files` requires
successful restoration, freshly verifies the complete aggregate baseline and
original intent, and captures role bytes from the **current root scans**, not its
backup blobs. The aggregate inventory still includes unrelated providers, exact
nine selected auths, original metadata and all other managed roots. Unsupported
links/metadata, unknown additions, root replacement or read uncertainty refuse.
Alternatively, a fresh `WriteSetVerifier` supplies independently reopened approved
handles and complete baseline observations without invoking restoration or trusting
its progress flag. This read-only API is not an OS sandbox or an authenticated
observer service; both handles and the external fence still need provisioning.

`RestoredInputSnapshot` requires four distinct approved `(root, relative-file)`
roles: `config`, `compose_source`, `frozen_rendered_compose`, and `environment`.
The latter is an explicit restricted JSON interpolation map, never ambient env or
an automatically loaded `.env`. Policy, role-map and original-intent pins must be
provided independently. Computing matching hashes is **not authentication**. The
role layout has no live defaults; an installation whose approved frozen model or
interpolation snapshot is not bound this way is unsupported, not permission to
create/copy/repin live material.

The snapshot performs all-root byte/metadata checks before capture and after
serialization. The existing `ExactInputGate` transport checks the independently
pinned executable descriptor, request digest, same-lock/fence callback and original
inclusive phase deadline before/after real helper execution and fresh recapture.
Raw bytes remain restricted stdin-only input. Errors and output are fixed codes;
no filenames, auth names, config values or helper diagnostics enter receipts.

## What the helper verifies

`inputguard/baselinecmd` accepts only `host-recovery-baseline-input-v1`:

- Strict bounded YAML and exact raw pins for config, Compose source and captured
  rendered model; strict JSON/base64, no duplicate/unknown/coerced protocol fields.
- Inspected rollback source `b4c6bf0e7a0b610983ad21d343aff6a7bef5fb24` defines
  `MetaConfig`/`MetaReasoningReplayConfig` in `internal/config/config_types.go`.
  `internal/config/meta_reasoning_replay_test.go` records the legacy top-level
  `meta.reasoning-replay` and canonical `upstream.meta.reasoning-replay` layouts.
  This projection requires exactly one layout, explicit Boolean `enabled`, bounded
  string `models` if present, and the independently pinned complete replay subtree.
  Both layouts at once, unknown replay fields or any `plugins` stanza refuse.
- Actual pinned `compose-go/v2@v2.16.2:single-file-model-v1` rendering with the closed
  environment must equal the entire frozen model, including unrelated services.
  The selected service must declare the exact approved immutable digest reference.
  Renderer restrictions in [COMPOSE-GUARD-v1.md](COMPOSE-GUARD-v1.md) still apply.

The inspected rollback source is **not executed/imported**, and this is **not its
full application schema/normalization/defaults validator**. A source layout pin is
not running-image provenance. A Compose image reference is not the daemon's image
ID, effective command/mount/config selection or readiness. A missing plugin stanza
is not proof of absent plugin binaries, runtime discovery, or unloaded code.
Those checks remain mandatory in the independent host oracle. Do not strip fields
from the accepted baseline or change pins to fit this deliberately narrow subset.

A success receipt is exactly:

```json
{"schema":"host-recovery-baseline-input-result-v1","baseline_inputs_validated":true,"start_authorized":false}
```

## Recovery composition and one-shot semantics

`RecoveredInputBoundary` retains the existing boundary's full stopped-state oracle.
The shared strict `validate_baseline_receipt` checks its original baseline/object
and every required Boolean fact; the guard cannot synthesize missing facts. Then
the restored-input guard runs. Before delegating old start, the same original
intent/receipt is required, the pending call is consumed and the guard runs again.
Changed files/fence, incomplete oracle, helper failure, deadline uncertainty or a
lost start response cannot reuse the call. The actual start boundary must still
revalidate manager/daemon/writer fence, effective mounts and all owned objects.
The wrapper snapshots the receipt immediately and retains the same oracle/gate
instances. It rejects caller-intent drift, mutation of a callback's intent copy,
receipt edits during the last gate, boundary replacement, or a caught reentrant
refusal. Verification is never rebound to changed inputs; only the original
snapshots can reach the one-shot delegation. These local identity checks do not
implement authentication, continuous writer exclusion or the independent oracle.

The coordinator's original arm/deadlines, independent alert attempt and durable
terminal-write rules are unchanged. Candidate guards are not required to restore
the baseline; invalid candidate inputs must not disable recovery. The new guard
never retires the latch or grants later startup/new admission.

## Evidence boundary

Tests use actual synthetic protected multi-root files and a built Go helper, with
**scripted manager/fence/daemon/readiness/alert boundaries**. Valid inputs cannot
replace an incomplete oracle. Byte-exact but semantically invalid synthetic
baselines refuse before old start; reached read-fault hooks and post-helper changes
refuse. None of this proves installed-systemd recovery, a complete operational
oracle, external notification, measured phase caps, availability or producer drain.
