# Supervisor restart reconciliation v1 — recovery-only source subset

**Not an installed persistent supervisor, complete start fence, executable reboot
recovery, acceptance result or operational instruction.** No host units, daemon
configuration, privileges, credentials, pins or production state are changed.

## Ownership and ordering implemented

`host_recovery/supervisor.py` adds `recovery_owner`, a context that retains the
installation-directory flock for the complete reconciliation invocation. A live
contender refuses instead of returning a success-looking value. Closing the
context invalidates its reference so it cannot dispatch with a released/reused fd.
The new owner specifies installation, original attempt, manager unit/invocation
and boot identity; invocation syntax is not manager authentication.

A reopened journal retains the original immutable intent. No candidate checkpoint,
registration, terminal-looking file or successful prior worker exit authorizes
forward promotion, new admission, restoration or service start. There is no latch
retirement, terminal settlement or automatic state cleanup.

Before a recovery dispatch request:

1. Read restricted bounded intent/arm records, validate the intent and arm pin,
   require the same installation/attempt and usable clock continuity.
2. Refuse any staged/durable prior reconciliation request or receipt. Such evidence
   may mean a recovery job exists, even if enqueue acknowledgment is absent.
3. Require current manager-owner observations on both sides of the complete
   start/writer/pending-operation fence acknowledgment. Re-read pinned intent/arm
   and the directory entry set before dispatch stages; unexpected state refuses.
4. Persist the exact recovery request with file-fsync, rename, directory-fsync and
   readback **before** calling the manager's separate recovery enqueue boundary.
   The request digest binds owner, intent, arm, conservative timing and deadline.
5. Recheck owner/fence and inclusive time after persistence, before enqueue. A slow
   fsync, owner loss, changed state or expired budget cannot be followed by enqueue.
6. Accept only an exact digest-correlated, strict boolean separate-owner enqueue
   receipt. Persist it independently and check the deadline again. This is an
   **enqueue acknowledgment only**, never evidence of running recovery, daemon or
   mutator quiescence, successful restoration, readiness or a terminal outcome.

Every invocation attempts at most one enqueue. Failed/ambiguous request persistence
never enqueues. If the enqueue reply is lost, or any receipt write/deadline fails,
retain the request and unresolved state, independently attempt the alert, and do
not retry. On reopen, even an acknowledged request needs actual manager/job
reconciliation. The implementation cannot safely infer that the old job vanished.

The independent alert is attempted even when directory reads or receipt persistence
fail. Its supplied transport receipt does not imply durable external delivery or
human acknowledgment; operational sink wiring remains due.

## Original-clock accounting

A restart cannot invent the original failure instant. Without a durable, trusted
failure timestamp, this subset charges the recovery reserve conservatively from
`t0`, the original arm: `min(t0 + 180, t0 + 300)`. This can refuse work that a richer
proven timeline would permit; it never expands the reserve. The enqueue caller may
only shorten that deadline. The reported detection upper bound is the elapsed
window **at the initial reconciliation observation**, not a measured detection,
restoration or outage duration. All later work is still charged to the same bound.

Cross-boot, regressed/missing clock, malformed/missing arm or already-expired
reserve remains unresolved. This subset does not launch a new recovery window in
those cases. A separate reviewed continuation must retain original attempt and
host-down/censoring evidence, identify a new bounded recovery invocation and never
report an on-time original success. Immediate bounded reboot recovery is therefore
still **unimplemented**, not proved by refusing promotion.

## Actual tests and their limits

The component suite uses private synthetic temporary directories, real flock and
fsync/readback, fake clocks, scripted manager callbacks and deterministic EIO/ENOSPC
faults. A separate Python process reaches the durable-request-before-reply boundary;
the parent proves lock exclusion, sends SIGKILL, waits for exit, then reopens state
and proves no redispatch. This is an actual process/lock/persistence drill but
**not** a systemd manager, separate recovery unit, daemon or boot/start-fence drill.

Other negatives cover every request-write fault stage, missing/corrupt/changed arm,
terminal-looking candidate records, owner loss before/after persistence, unknown
entries, cross-boot/expiry/regression, uncorrelated receipts, lost reply, receipt
persistence failure, directory-read failure and independent alert despite disk
failure. No loopback or test-suite runtime becomes production downtime.

## Still required before operational use

- Actual persistent manager-owned service/event loop and attested unit/invocation,
  authenticated narrow dispatch transport, distinct pinned recovery unit and
  manager job/invocation reconciliation after ambiguous dispatch.
- Independently enforced complete boot/internal-restart/start/writer fence and
  daemon pending-operation drain. No injected Boolean is its implementation.
- Coordinator/manager/daemon/restore integration and actual complete semantic
  baseline/start oracle; no restoration or start operation is provided here.
- Separately identified, reviewed bounded cross-boot/expired continuations,
  settlement and new admission without deleting unresolved state.
- Operational independent alert route, strict source/render/schema/policy and
  dual-hash integration, genuine probe/container/source completeness and full
  disposable systemd/cgroup/daemon package/availability matrix.

REA angle: reuse the existing fd-relative durable journal/flock and manager
unit/invocation semantics. An idempotency identity and write-before-dispatch expose
ambiguous ownership instead of guessing from a helper's exit status.
