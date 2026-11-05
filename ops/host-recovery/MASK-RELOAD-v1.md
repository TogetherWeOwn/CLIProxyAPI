# Journaled mask reload v1

`host_recovery/mask_reload.py` supplies an **embedding phase**, not an installed
broker, activation interlock, operational runner or recovery authority. It joins
the existing private operation journal, persistent mask handles and authenticated
non-reconnecting system-manager session. No new installation lock or recovery
owner is acquired. Existing `ForwardContainment` and operational IPC/runners do
**not** invoke this phase; their fixed-deny/identity-only semantics stay unchanged.

## Original boundaries and ordered publication

- Require the same fixed forward or dockerd/containerd bindings in the masks and
  `ManagerJobSession`. Bind the original journal/epoch, mask directory/units,
  manager owner/bus generation, library hash and original session deadline in the
  phase target. Root provisioning, persistent load-path precedence, exclusive
  configuration writers and complete activation graph remain external reviewed
  prerequisites. An owned component directory is not that provisioning proof.
- Require an exact, still-pending original `contain_forward` or
  `cold_quiesce_runtime` record with matching role set. The phase cannot reopen,
  adopt or replay a prior request, run after its outer return, extend its deadline
  or use a replacement session. Publish the original operation before mask
  publication; masks must already have completed their fsync/readback barrier.
- Under the journal's existing mutex, recheck original peer/lock/input/manager and
  clock authority and the live mask handles. Refuse any known fixed-unit manager
  job **before** reload. Reload can discard accepted queued jobs; disappearance
  cannot substitute for authenticated cancellation. This phase does not cancel
  jobs, poll for retirement or adopt unrelated jobs. Provisioned activation
  ownership remains essential: point reads are not an atomic exclusion lock.
- Persist/read back `operation-NN-mask-reload-pending.json`, bound to the original
  operation and phase target. Send exactly one `Manager.Reload` to the pinned
  unique owner on the original connection. No shell, arbitrary method, endpoint,
  environment bus selection, reconnect or fallback is used.
- After the actual authenticated empty method return, obtain typed properties
  from each fixed unit on that same connection. Repeat the complete projection,
  reject fixed-unit jobs and revalidate original boundaries. Persist a separate
  return record; then repeat the observations and all authority checks again.
  A return-fsync fault or later drift cannot create an acknowledged phase.

`Reload` changes the manager configuration globally, not just the named unit.
Operational provisioning must authorize that scope and contain all configuration
writers. Disposable Actions fixtures are not authorization to reload a shared or
production manager. No host-manager operation is permitted by this source change.

## Typed effective-mask projection

Do **not** relax `SystemdMutators.observe` or synthesize missing loaded-service
properties. This separate projection requires:

- Exact `Unit.Id`, `LoadState=masked`, a supported mask fragment path (the exact
  independently pinned mask entry or `/dev/null`) and an empty typed `DropInPaths`.
- Actual D-Bus types: string variants, unsigned `Service.MainPID`, the exact
  `(uo)` idle job `(0, /)`, and the 16-byte `Unit.InvocationID`. Only the actual
  all-zero 16-byte identity maps to an inactive empty identity; strings, truncated
  IDs and padded/defaulted fields refuse. `ControlGroup` is read from the
  **Service** interface, not inferred from a systemctl display.
- Either active/running with the original invocation/cgroup and a positive PID,
  or inactive/dead or failed/failed with PID zero and original-or-cleared
  invocation/cgroup. Intermediate states, replacement invocations/cgroups,
  unexpected drop-ins or pending jobs refuse. Two complete reads must agree.
- Reobserved original disk masks and original session/peer/lock/input/deadline.
  These remain revoking point checks, not an invocation-atomic manager primitive.

An active masked service is deliberately supported: masking/reload does not kill
its processes. Receipts expose only counts/digests and `effective_masks_observed`
/ `manager_reload_returned`. Activation exclusion, retirement, pending drain,
complete fencing, recovery execution, start, settlement and production acceptance
remain **false**, including when `active_unit_count` is zero.

## Failure, persistence and reconciliation

Any uncertain persistence, callback, native reply, property type, identity or
clock permanently closes this phase, original journal and session. Partial files
and masks remain; no overwrite, cleanup, retry, unmask or automatic repair occurs.
The original operation is **not** returned/settled by this phase. A lost return or
process death is not a completed recovery, and an on-disk phase return is not a
fresh authority grant. The read-only broker history reader classifies a canonical,
original-operation-bound phase as `unreturned` or `returned_unproven`. It checks
both exact schemas, the phase target digest, the pending-to-return byte digest and
literal boolean flags. An outer return or later stop record cannot hide an
unreturned reload. Orphan returns, unsupported methods, unknown/staged records,
noncanonical bytes and changed publication still reject the complete report.

This classification preserves bytes and original deadlines across broker/boot
epoch changes. It does not execute manager calls, reconstruct effective masks,
adopt a journal, renew a deadline, retry a reload or report historical success.
Even a returned phase requires fresh cold reconciliation; complete runtime
reconciliation and operational composition remain required before use.

The session's trusted original-authority check must not itself assume that the
forward unit remains loaded across reload. That does not permit dropping those
checks from other paths. Forward stop/cancellation/retirement and the transition
into this projection still need an operational composition under the original
pending barrier. Existing production-facing entrypoints remain disabled.

## Evidence scope

New ordinary tests use actual owned synthetic files, protected mask handles and
private durable records, with **scripted** manager/authority/ABI calls. Reached
EIO/ENOSPC hooks cover pending and return publication; assertions distinguish a
retained uncertain return from an acknowledged phase. Native decoder tests are
scripted ABI tests, not shared-library qualification.

The existing Actions-only real-manager mask method now invokes this phase on a
real root/PID1 connection and uses actual typed property decoding. Its original
independent systemctl state, live/dead pidfd, explicit stop/whole-unit kill,
authenticated completion and refused fresh direct/dependency-launch assertions
remain. Original request/authority provisioning in that fixture is synthetic,
not a running supervisor or installed broker. The separate queued-start fixture
now invokes the [fixed waiting-start cancellation phase](JOB-CANCELLATION-v1.md),
not this reload API, while retaining its independent completion/execution checks.
Neither fixture supplies operational cancellation/retirement authority.
No source change alone claims a passing Actions result. No local suite or build
is run; exact-head GitHub Actions remains CI of record.

Still required: operational cancellation/retirement/actual-exec exclusion and
complete boot/reexec/activation ownership, cold-runtime/shim containment,
quarantine/policy/registration/drain, independent restored-baseline/readiness/result
verification, authenticated provisioning, expired/reboot continuation, complete
package/replay/source-drain/fault/timing qualification and measured phase caps.

REA angle: inspect systemd v255 `dbus-unit.c`, `dbus-service.c`, `dbus.c` and
`load-fragment.c` for actual property types/interface registration and mask
loading, then qualify the existing source primitive against real PID1 instead of
weakening the loaded-unit reader or equating reload return with quiescence.
