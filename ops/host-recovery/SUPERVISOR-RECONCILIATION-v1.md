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

## Existing dispatch: explicit observation-only reconciliation

The default reopen behavior above is unchanged. `recovery_owner` now separately
accepts explicit `observe_existing=True`; that mode cannot enqueue even when no
request exists. `observe_pending` makes one bounded pair of read-only observations
under the installation lock. No retry, job cancellation, worker launch, restore,
terminal outcome, latch retirement or service-start permission exists here.

The saved restricted request must have its exact digest, original intent/arm,
installation/attempt/supervisor unit/boot, strict false permission fields and a
non-extended conservative deadline. Only the supervisor invocation may differ
across a same-boot restart. Missing requests, staged/unknown reconciliation files,
changed requests, malformed or conflicting enqueue receipts, changed arm/intent,
clock discontinuities and expired original/request deadlines fail closed. Any
supplied caller deadline can only shorten the saved request's deadline.

`jobs.SystemdRecoveryJobs` generates only fixed `systemctl show` argv for
`cpa-recovery@<request_id>.service`, never a user-supplied unit or arbitrary command.
The explicit template fragment and complete static-property digests are checked,
including the reviewed worker command, ownership and non-restarting/non-delegated
no-capability sandbox. The trusted manifest must authenticate these pins and bind
the worker command to the request-instance identity; a hash or matching dictionary
is not authentication. No template is installed. This observer itself cannot
dispatch; the separate one-shot dispatcher below uses the same request-instance
identity. Generic callback dispatchers remain independently trusted boundaries,
not authenticated by a matching receipt.

A strict observation reports only `pending`, `running` or `inactive_unverified`.
A pending numeric manager Job is not running recovery. Job absence, inactive or
failed state and a cleared invocation cannot distinguish a lost dispatch from a
job that already ran. A worker exit, including an apparently successful one, does
not prove baseline restoration or old readiness and is never an outcome oracle.

The first nonempty observed recovery invocation is persisted with the exact
request/unit/boot binding before observation is acknowledged. It must be distinct
from the current supervisor invocation. Future observations can reuse that binding
but cannot rewrite it or adopt a replacement/vanished invocation. The manager,
complete-fence boundary, request/arm and entry set are rechecked around observation
and persistence; a changed second observation remains unresolved. Persistence
faults still attempt independent alert transport. A visible record after an
uncertain write is no permission or completion receipt.

A separate-process regression reaches the durable observed-invocation binding,
proves lock exclusion, receives SIGKILL and exits. Reopen can observe the same
scripted invocation but refuses its replacement; it never dispatches. Another
test uses actual bounded local subprocess transport to read scripted systemd
properties. These are process/filesystem/transport component tests, **not real
systemd template compatibility, daemon fencing or executable recovery evidence**.
All start/fence-proven/recovery-completed/production-acceptance fields stay false.
The persistent service/event loop and trusted dispatch/worker handshake remain due.

## Lock-retaining observation loop core

`watch_pending` now follows an existing dispatch, or follows a durably acknowledged
new enqueue **in the same installation-lock context**. It never closes/reopens the
lock between enqueue and observation or between ticks. The existing one-shot
`observe_pending` remains one-shot; a used/closed/failed context cannot enter a new
watch. An uncertain enqueue cannot enter this loop: it must be reopened explicitly
in observation-only mode, with no automatic redispatch.

The caller must provide a positive interval, inclusive deadline, strict integer
observation limit (1–4096), strict boolean stop check and interruptible local wait.
For an actual service process the stop/wait pair can use `threading.Event.is_set`
and `Event.wait`; manager/daemon calls still require their own deadline-enforcing
trusted boundary. No wait, shutdown or query grants a new reserve. The effective
end is at most the saved request deadline, and each wait is shortened to the
remaining interval. Early/spurious wait returns and non-advancing clocks refuse
instead of busy-spinning. Observation count bounds work even with tiny intervals.
No timer thread, detached watchdog, manager retry or second recovery owner exists.

Each tick uses the same pinned request/arm and complete owner/fence checks around
the existing observation pair. Pending jobs may become a running invocation, whose
first identity is durably bound. Replacement/loss remains unresolved. Inactive or
exited workers immediately escalate as outcome-unverified; the loop cannot wait
for or invent a restoration oracle. Stop, SIGTERM-driven interruption, limit or
deadline exhaustion and uncertain callbacks all retain the original intent and
attempt independent alert transport even if its receipt persistence fails.

Status holds only the latest job, bounded count and sampled monotonic times.
`sampled_elapsed_seconds` is the interval to the last valid loop sample, **not** a
complete detection/recovery/persistence/alert or outage measurement. No on-time
success or availability bound can be derived from it. Callback overrun/host loss
still prevents a hard-real-time guarantee, and this loop cannot enforce a deadline
inside an unresponsive injected boundary.

Tests use deterministic clocks for scheduling, with separate actual subprocess
SIGKILL and SIGTERM/Event-wait synchronization. The live contender cannot take the
installation flock. SIGKILL preserves request/invocation binding for observation
on reopen; SIGTERM returns unresolved with a local scripted alert receipt. The
signal fixture initially emitted literal backslash-n and failed synchronization;
that red receipt is retained, not a signal-handling failure or manager result.

**This is the bounded loop core only, not an installed persistent manager service.**
No runnable unit/entrypoint, authenticated manager owner, trusted broker/worker
handshake, complete fence or operational external alert sink is supplied. The
separate fixed-argv dispatch subset below does not implement those boundaries. All
start/fence-proven/recovery-completed/production-acceptance fields stay false.

## One-shot request-instance dispatch adapter

`dispatch.SystemdRecoveryDispatch` adds only a fixed-argv, nonblocking enqueue for
`cpa-recovery@<request-digest>.service`, not service installation or a worker. It
requires the exact digest-bound request envelope, a non-extended original-arm
reserve, same boot and explicit accepted unit/fragment/static-configuration pins.
There is no arbitrary unit/command, restart, reset-failed, cancellation or retry
operation. Any attempted call exhausts the adapter, including validation/query
failure. A replacement adapter is not authority to retry a retained request.

`RecoverySupervisor.authorize_dispatch` exists only inside the synchronous enqueue
call made after durable request persistence/readback. Its ordered `observe`,
`enqueue`, `acknowledge` phases each revalidate private request bytes, owner, arm,
entry set, clock and the complete-fence callback under the installation lock. Each
phase is consumed before external callbacks; repeated/reordered/reentrant/failed
validation revokes the lease. A partial/denied lease cannot be suppressed to produce
an enqueue acknowledgment. Before/after the call, after close, and on reopen there
is no lease, even with identical durable request bytes. Generic injected managers
that never use this lease remain external trusted boundaries; this change does not
authenticate them or silently turn their test receipts into real enforcement.

The dispatcher first requires an inactive-unverified pinned job with no manager
job or prior invocation. This is necessary, **not proof no job ever ran**: only the
live supervisor's single-dispatch lease authorizes the initial enqueue. A pending,
running or previously invoked worker is observed, never restarted. It requires
strict empty successful local stdout and post-reply lease/boot/deadline validation.
A lost/nonempty/late reply or changed fence/owner leaves dispatch uncertain. The
original request remains; no acknowledgment claims running recovery or restoration.
The same lock-retaining loop can subsequently observe the request instance.

This adapter is **not an authenticated privilege broker, installed manager service,
worker request handshake or independently enforced fence**. The actual fixed worker
must still receive/validate the request instance, package/intent identity and its
own manager invocation through a trusted narrow boundary. All service-start,
recovery-completed, complete-fence-proven and production-acceptance fields remain
false. No real systemd/daemon operation was performed by its tests.

A separate-process test uses scripted manager/command/authorization boundaries,
pauses after the scripted start reply but before enqueue acknowledgment, proves
actual flock exclusion, receives SIGKILL and reopens the retained request without
redispatch or a recreated lease. Another uses an actual local executable fixture
to verify fixed argv generation. These are process/lock/persistence/transport
component receipts, **not manager/daemon or full-package recovery evidence**.

## Stable command-configuration pins

The earlier static-property digest included `systemctl show`'s complete `ExecStart`
display, whose timestamp/PID/exit suffix can change without configuration changes.
`manager.static_properties` now projects a **single supported complete display**
into `host-recovery-execstart-config-v1`: executable path, byte-for-byte displayed
argv and ignore-errors policy. Only the known runtime suffix is excluded. It is
never shell-parsed or executed. All other static settings remain pinned; dynamic
unit state/invocation/job/PID checks remain separate and mandatory.

Multiple commands, missing/unknown fields, delimiter/control-bearing or ambiguous
argv, malformed runtime suffixes and unsupported future formats refuse. This is
an intentionally restricted display grammar, not a general systemd parser or a
claim of compatibility across systemd versions. Fixtures cover stopped/running
telemetry changes and command/sandbox changes; **real installed-version validation
is still due in an approved disposable environment**. Pins over the old raw display
do not match this versioned projection; no operational pin has been replaced.

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
  authenticated narrow dispatch transport, distinct pinned recovery template and
  request-instance worker handshake. Read-only job/invocation observation above
  still needs actual manager compatibility and recovery-outcome reconciliation.
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
