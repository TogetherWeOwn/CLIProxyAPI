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
