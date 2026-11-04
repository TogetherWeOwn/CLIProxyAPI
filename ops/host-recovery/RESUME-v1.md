# Original-arm coordinator resume v1 — component boundary

**Not an installed supervisor, executable host recovery adapter, complete fence,
reboot continuation or acceptance result.** This source changes no host service,
daemon configuration, privilege, credential, live input or release pin.

## Implemented path

`AttemptCoordinator.resume()` now connects a reopened original journal to its
existing fence → quiescence → recovery validation → complete restoration → strict
stopped-baseline oracle → old start/readiness → terminal persistence sequence.
Previously that coordinator could recover only inside its forward invocation;
a reopened coordinator had no budget and could not enter recovery.

The caller must retain the same installation-directory lock and supply the
independently authenticated current recovery owner and trusted boundary. This
function does not acquire a second lock, discover/approve that owner, dispatch a
worker or attach itself to a running supervisor.

Before any mutating boundary call, resume:

1. Requires a reopened, non-uncertain journal and exhausts the invocation's resume
   path. Live admission cannot use it. Forward eligibility is revoked immediately.
2. Refuses prior `reconcile-*` requests, claims, staging and unknown state. Those
   may represent a live or ambiguously dispatched worker or incomplete durable
   transition. They require the separate installation/job reconciliation protocol;
   resume cannot silently adopt them or widen a saved request's shorter deadline.
3. Reads original private no-follow intent/arm records and checks their complete
   schema, intent digest, policy, ownership, bytes and filesystem identities.
4. Constructs the budget with the **saved arm**, never the restart time. Missing
   failure timing is charged conservatively from original `t0`, including the
   positive detection phase cap. Both `min(t0 + 180, t0 + 300)` and that phase cap
   apply. A late restart can therefore be refused before preflight, even while
   some nominal recovery reserve remains. Test caps are synthetic, not measured
   operational allocations or an approved production policy.
5. Calls strict `recovery_preflight(intent, deadline=...)`. The trusted boundary
   must authenticate the accepted package/policy/complete baseline, current
   recovery ownership and independent listener. Missing, false, malformed, late
   or failed preflight cannot reach fencing, restoration or a start. A scripted
   True is component evidence only, not any of those implementations.

Original record bytes/identities and the journal entry set are rechecked around
every recovery boundary operation and terminal persistence. Replacing an original
file with byte-identical content is not adopted. Only this invocation's successful
terminal write adds its expected outcome entry. Original intent/arm remain intact.
Terminal-looking records and old registration files are never completion or start
authority; the entire recovery and stopped oracle still run.

Unknown original failure is reported explicitly as
`restart-original-cause-unavailable`, not invented from a successful exit or a
candidate checkpoint. Recovery failures remain separate. Fixed resume notice
codes are admitted by the existing alert protocol. Independent transport is
attempted even if input reads, restore/outcome persistence or alert receipt storage
fail; transport validation/admission is not human notification or external delivery.

## Bounds and remaining gaps

Cross-boot, missing/regressed clock, expired original budget or detection cap,
pending dispatch/claim, staging and changed inputs return unresolved without
restoration/start. This path does **not** implement a new bounded expired/reboot
continuation, terminal settlement, latch retirement, new admission or safe adoption
of a prior worker. The same object cannot retry; any later owner must reacquire the
installation lock and revalidate the original state and budget from scratch.

The recovery/start oracle and host boundaries remain injected and externally
trusted. A component `baseline_restored` result is conditional on those boundaries,
not installed-manager/daemon/full-write-set recovery proof. `start_fenced` stays
true and `production_acceptance` false. Concrete persistent service/broker/fence,
all-root semantic/render/schema/dual-hash integration and the full approved
systemd/cgroup/daemon matrix remain due. The read-only `status.py` / `observe.py`
entrypoints do not call this path and still grant no execution.

## Tests and evidence limits

Tests reopen real synthetic journals under the existing flock and restore real
synthetic tree bytes/metadata. Every EIO/ENOSPC write/fsync/rename/directory-fsync/
readback stage is exercised in restoration and terminal persistence. A failed
restore never reaches old start; a fresh same-budget invocation revalidates and
restores the whole tree, including known partial-restore staging. Uncertain
terminal state never becomes a successful receipt or permission to retire intent.

A separate disposable process durably arms, changes a synthetic file, proves lock
exclusion and receives actual SIGKILL. A new lock owner reopens the original arm
and restores that real synthetic tree. Its raw JSON receipt labels manager, daemon
and semantic-oracle boundaries **scripted**. No unit is installed or daemon
contacted; these are process/lock/filesystem/ordering tests, not host recovery,
complete detection time, availability samples or production downtime measurements.

REA angle: reuse the original journal and budget plus the existing ordered recovery
sequence and idempotent tree-restoration primitive, rather than inventing a fresh
clock, treating an old terminal as authorization or creating another rollback owner.
