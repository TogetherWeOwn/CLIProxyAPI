# Fixed waiting-start cancellation v1

`host_recovery/job_cancellation.py` is an embedding phase before fixed-mask reload,
not an operational broker API or complete activation fence. Existing runners and
IPC mutation denies are unchanged. No shared-host manager operation, installation,
privilege change or release action is authorized by this source.

## Original authority and one-shot effect

Use the original still-pending `contain_forward` or `cold_quiesce_runtime`
operation, its journal/mutex and its authenticated non-reconnecting
`ManagerJobSession`. Require matching fixed unit roles and already-published,
descriptor-bound `PersistentUnitMasks`. Publish the original operation before
those masks. Trusted provisioning, exclusive configuration/activation ownership
and the session's original live supervisor/installation-flock/manager/input
barrier remain external prerequisites; test-owned pins are not approval.

- Snapshot the complete bounded manager job inventory on that same connection.
  Only exact fixed-unit `start/waiting` jobs can become cancellation targets.
  Running starts, stops and unsupported jobs refuse. No caller supplies a numeric
  ID, job object path, method, arbitrary unit or replacement connection.
- Persist a separate canonical per-role pending record with the original
  operation, configuration digest, manager/bus identity and entire observed job
  tuple. Revalidate the original journal, peer/lock/input, masks and inclusive
  deadline. Confirm the same job tuple still exists before the effect.
- Issue one `Job.Cancel` to that exact observed job object and unique manager
  destination. An empty method return is only a return: persist it separately.
- Require an authenticated exact `JobRemoved(canceled)` event on the original
  connection. Preserve early events during the call; wait only within the original
  inclusive deadline. `done`, missing/duplicate/conflicting events, signal-before-
  cancellation, disconnect, owner loss or uncertainty refuse without retry.
- Persist the matching completion separately; recheck its identity and original
  boundaries after publication. Finally refuse any remaining fixed-unit job.
  Unrelated jobs are never canceled or adopted. A subsequent fixed stop retains
  its distinct job ID/completion; cancellation events cannot masquerade as stops.

No new installation lock or deadline is created. A failed/ambiguous write,
readback, callback or native reply permanently revokes this phase, journal and
session. Partial records/masks remain; reopening cannot adopt or resubmit them.
The outer operation is never returned or settled by this phase. A zero-target
snapshot issues no cancellation and proves no retirement.

## Historical evidence, not reconstructed authority

The read-only history reader consumes strict canonical pending/return/completion
schemas and digest links. It classifies `unreturned`, `return_without_completion`
or `canceled_observed`; every classification denies retirement/drain/start.
Orphans, staged/unknown bytes, malformed job tuples, nonliteral flags and
conflicting manager/job identities refuse the entire report. A later cancellation,
reload, stop or outer return cannot conceal an incomplete cancellation. Full
capture remains bounded and no record is repaired, removed or replayed.

These are point observations. The job may cross an execution boundary before a
cancellation is processed; this phase does not claim actual-exec exclusion,
all-job retirement, quiescence, daemon/shim containment, cold recovery, pending
drain, restoration/start/settlement authority or production acceptance. Persisted
masks are not effective before a separate successful reload. Complete boot,
reexec, activation graph and writer exclusion still need qualification and
operational composition.

## Verification scope

Ordinary tests use actual private mask/journal files and scripted manager effects.
They require reached EIO/ENOSPC hooks for pending, return and completion, distinguish
return from completion, and keep cancellation/reload/stop identities separate.
History tests use synthetic records, not a restarted broker or actual boot drill.

The existing Actions-only queued-start fixture invokes this source phase with
real PID1 transport and persistent mask publication, while retaining its independent
accepted-job witness, positive execution control, held dependency gate, distinct
stop completion, pidfd deaths and zero negative execution timestamp. Original
request/authority and the not-yet-executed target's nonzero invocation binding are
explicitly synthetic. This is not installed supervisor/broker or full-package
qualification. Source alone implies no passing test. Exact-head GitHub Actions
results are required; no local suite, CI mirror or host manager drill substitutes.

REA angle: reuse the qualified v255 `Job.Cancel` object path and same-connection
`JobRemoved` semantics already exercised by the inert queued-launch fixture;
never cancel a caller-supplied reusable numeric job ID or treat disappearance as
completion.
