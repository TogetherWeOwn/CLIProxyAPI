# Original-operation masked forward stop v1

**Embedding source only. Not installed or enabled by IPC or either service
runner. No restoration, service start, settlement or production authority.**

`host_recovery/masked_forward_stop.py:MaskedForwardStop` composes the existing
mask, cancellation, reload and fixed stop primitives. The trusted caller retains
the original installation lock, approved mask-directory handles, pinned native
library and one non-reconnecting manager connection. It supplies the original
live supervisor/kernel-flock/manager/input barrier through that session. No
replacement lock, authority callback, endpoint, unit, job ID, signal, deadline or
command is accepted per request.

## Ordered effects and retained uncertainty

1. Construct fresh masks and `ForwardStopJobs` sharing the original journal and
   session. Bind the entire sequence configuration, including fixed whole-unit
   SIGKILL semantics, into the original `contain_forward` pending target digest.
   The original operation deadline must equal the already-shortened session
   deadline. Saved/returned operations, used objects and changed targets refuse.
2. Publish only absent persistent mask names, fsync and reobserve their identities.
   Run the existing exact waiting-start cancellation phase. It persists exact
   pending, return and authenticated canceled completion separately; running or
   unknown jobs refuse. Absence cannot manufacture a cancellation.
3. Run the existing separately journaled reload phase. Observe typed effective
   masks while retaining the original connection and pending operation. Active
   masked processes are still active; masks do not kill them.
4. Persist the distinct fixed stop pending/actual return with `ForwardStopJobs`.
   Even an inactive unit requires its own stop and matching completion. If that
   completion is not already observed, issue at most one fixed
   `KillUnit(unit, "all", int32(9))` on the same authenticated connection. The
   existing outer pending and durable stop records precede this effect. There is
   no separate durable kill-return record: a crash retains the unresolved outer
   operation, never a reconstructed kill acknowledgment or replay grant.
5. Wait only within the original inclusive deadline for the exact stop completion,
   persisting it separately. A KILL reply, absent job or canceled-start completion
   cannot substitute for `JobRemoved(done)` matching the actual stop reply.
   Reobserve the effective inactive mask and job/completion state after completion
   persistence and final external boundaries. Wrong results, identity loss,
   unknown jobs or storage uncertainty permanently close the sequence/session/
   journal. No retry, automatic repair, unmask, outer return or settlement occurs.

The native argument encoder adds only the signed integer needed for the fixed
whole-unit SIGKILL call, rejecting other values/types/methods and mismatched
argument counts. This is not an arbitrary signal or method API. An effect can
race completion or process loss: an ambiguous/failed KILL reply refuses rather
than being treated as successful merely because a later unit looks inactive.

## Same-connection unit-object retention

Before mask publication, job watching or execution snapshots, the sequence calls
fixed-name `RefUnit` once per role on the original connection. It reads each exact
unit object path and the typed `Unit.Refs` list, requiring exactly one reference
owned by that connection's native unique bus name. Each subsequent execution
snapshot checks the retained path and own reference again. A successful method
return alone is not reference readback. Missing/duplicate own references, changed
paths/client identity, unsupported properties, permission refusal, lost replies
and original-deadline loss permanently refuse.

**Intentional reload is a reconstruction boundary, not uninterrupted lifetime.**
After the separately durable reload return, acknowledge a `UnitRemoved` match
and revalidate own references before any stop submission. A removal of a fixed
name or retained path from that point onward refuses. Unrelated removals are not
adopted; observed removals share the bounded event count and increasing manager
cookie. No removal watcher is claimed across the deliberate reload: systemd
v255 frees units and deserializes their state/references during `manager_reload`.
Pre/post reference/path/timestamp readbacks do not prove continuity across it.

References prevent ordinary garbage collection between reconstruction boundaries.
They do not freeze configuration, exclude execution, fence reload/reexec/boot or
prove control-process/writer coverage. The manager owns sender references for
the original connection's lifetime; closing the connection releases them. A
partial/ambiguous reference sequence is never retried, unreferenced-and-recreated
or reconstructed from saved state.
No separate connection or cleanup command extends the original deadline.
The original pending target binds `sender-ref-unit-v1`, and receipts expose only
`fixed_unit_reference_count`, not bus names or unit paths. All authority-denial
fields remain unchanged. Permission failure is not permission to change policy.

REA/source semantics: systemd v255's [manager RefUnit dispatch](https://github.com/systemd/systemd/blob/v255/src/core/dbus-manager.c)
loads and validates the unit; its [unit reference method and Refs getter](https://github.com/systemd/systemd/blob/v255/src/core/dbus-unit.c)
track the calling sender and report each sender once per reference. The
[manager reload implementation](https://github.com/systemd/systemd/blob/v255/src/core/manager.c)
and `unit_free` explicitly remove units before deserialization; that boundary
cannot be advertised as the same in-memory object. These source references are
not qualification of another manager version or an installed privilege policy. Components use scripted ABI/manager boundaries; the separate
real-manager fixture requires independent `systemctl show Refs` readback for the
same live connection after both composed shutdown paths.

## Fixed-unit execution timestamp observations

Before mask publication the sequence reads each fixed unit's exact `Id` and
`ExecMainStartTimestampMonotonic` twice over its original authenticated connection.
The native reader requires a typed unsigned 64-bit variant, preserving values
above 32 bits. Missing, malformed, changed, out-of-range or infinity timestamps
refuse before effects. Zero is an observed value, not proof of no past execution.

The volatile initial values must still match after cancellation and reload,
before each fixed stop, during completion observations and across final barriers.
A newer execution that already exited cannot be hidden by an inactive projection
when its recorded start timestamp changed. Runtime composition also checks these
values before publishing the empty-domain observation. Uncertainty permanently
closes the same sequence/session/journal, with no retry or outer return.

Public receipts contain only a fixed-unit count and
`fixed_execution_timestamps_unchanged`, not timestamps, names or paths. These are
point samples of manager-maintained main-execution metadata, not a continuous
execution audit. Timestamp granularity, manager reset/reexec, control processes,
other units, aliases/templates, activation paths and external writers remain
outside this witness. Equal values do not prove actual-exec or launch exclusion,
all-job retirement, coverage or drain. Retained records do not reconstruct the
volatile observations after process loss. No operational authority is enabled.

## Same-connection fixed job admission witness

Before the execution snapshot or mask publication, the sequence installs and
acknowledges an authenticated `JobNew` match on the original connection. It
shares the bounded event count and strictly increasing manager-sender cookie
with the existing `JobRemoved` witness. Unsupported headers, signatures, paths,
duplicate admissions, identity loss and overflow revoke the session. Unrelated
units are not adopted; their events still consume the bound.

For fixed units, a newly observed job is supported only during the corresponding
one-shot stop dispatch, and its exact ID/path must match the actual `StopUnit`
reply. Both early and late admission signals are handled within the original
deadline. A completion cannot stand in for a missing admission signal. Existing
waiting starts remain the separate exact cancellation phase's responsibility;
a new admission outside the supported stop window fails closed, even if it
later disappears or never executes.

Final observation requires matching admissions and done completions for every
fixed stop, canceled completions for every inventoried waiting start, and no
fixed-unit jobs in `ListJobs`. Runtime composition also requires this before
empty-domain publication and rechecks afterwards. Receipts add only
`fixed_stop_admission_count` and `fixed_jobs_absent_observed`. No new durable
record, outer return, replay, clock reset or operational grant is introduced.

This is a volatile bounded observation, not a manager-side admission interlock:
unexpected jobs may already execute before the observer rejects them. Matching
JobNew/reply identities do not establish exclusive causal ownership of a job
submitted concurrently by another caller. No all-manager retirement, continuous
activation/writer exclusion, alias/template coverage, reexec/boot continuity or
crash reconstruction is claimed; `manager_jobs_retired` remains false.

## What this does not establish

The returned `masked_inactive_observed` and `fixed_stop_completion_observed` are
point/finite-job observations, **not** all-job retirement, actual-exec exclusion,
exclusive activation graph ownership, cgroup quiescence, runtime/shim containment,
cold/quarantine reconciliation, pending drain or complete fencing. Unit-name
manager calls are not invocation-atomic. Authenticated provisioning must exclude
replacement activation/configuration writers; this source does not infer it from
mask files, constructor types or journal digests. A loaded-unit authority check
that no longer holds after reload refuses; it is not weakened or replaced here.

All corresponding `proven`, `retired`, `drained`, recovery/start/settlement and
production-acceptance fields remain false. Operational runner/IPC denies remain
unchanged. The separate cold-runtime and independent stopped-baseline/readiness/
result oracle must precede any recovery execution wiring. No reboot continuation
or original-budget renewal exists here.

## Qualification scope

Ordinary components use actual private mask/journal files and scripted manager,
peer/authority and effect boundaries. They cover ordered durable barriers, exact
cancellation versus stop identities, inactive completion, reached faults in all
eight subphase publications, missing/failed completions, ambiguous replies,
revocation and read-only retained-history composition. ABI argument tests use
scripted native calls. Authenticated original provisioning is not proved by them.

The separately enabled disposable Actions system-manager fixture additionally
runs the source sequence against real PID1/libsystemd, an owned TERM-ignoring
parent/child and an independent completion witness. It requires dead pidfds,
truthful cgroup disappearance/empty observations and fresh direct/dependency start
refusal. The original mask-alone-does-not-kill and queued-launch controls remain
separate methods. The composed fixture gives the manager five seconds for its
fallback stop so the source's explicit KILL must return before completion;
that test-only cap is not an adapter recovery allocation or production timeout.
Original request authority in this fixture remains explicitly synthetic. Test
authorship is not a passing result: record exact-head Actions conclusions and raw
receipts separately. No shared-host manager operation is permitted.
