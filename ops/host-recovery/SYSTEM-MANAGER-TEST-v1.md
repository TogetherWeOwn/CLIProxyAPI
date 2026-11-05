# Real system-manager transport fixture v1

The `recovery-system-manager` job in `pr-test-build.yml` exercises the existing
`ManagerJobSession` against **real systemd PID1 on a disposable GitHub-hosted
Ubuntu runner**. It is separate from the synthetic private-bus matrix and ordinary
Python discovery. Missing capabilities fail the separate job; ordinary discovery
skips the four methods explicitly. Never run this fixture on a workstation, shared
agent host, self-hosted runner or production machine.

## Boundaries exercised

- Require explicit Actions opt-in, `RUNNER_ENVIRONMENT=github-hosted`, numeric
  run/attempt identities, root, actual systemd PID1, cgroup v2 and pidfds. Neither
  the production bus socket nor the root/PID1 credential checks are patched.
- Create exactly two fixed, run/attempt-scoped **transient inert test services**,
  one per test method. No persistent unit installation, boot activation,
  application, provider library, Docker/containerd, live path or management API is
  involved. Commands receive an empty environment plus the explicit allowlist;
  checkout credentials are not persisted and the job has read-only repository
  permissions.
- A test payload forks one child. Both ignore TERM; a pipe establishes child
  readiness and a kernel-peer-checked seqpacket message carries both process IDs.
  Before stopping, read both actual `/proc` cgroup memberships, the actual manager
  MainPID/invocation and the transient fragment/effective-property projection.
  Open live pidfds before termination so later PID reuse cannot supply death proof.
- Load the installed runner libsystemd through a real private root-owned
  `ProtectedFile` copy, checksum and retained descriptor. This is a **test-local
  runtime pin**, not independently approved production package/provisioning or
  reproducible-build evidence. The source fixture remains runner-checkout code,
  not a qualified immutable broker import closure.
- Subscribe and submit one fixed forward StopUnit on the same non-reconnecting
  production transport. Require its own authenticated matching JobRemoved `done`
  event and absent returned job ID; an empty inventory never supplies completion.
  Pump under the original fixture deadline without sleeping, repeated submission,
  quiet-time acceptance or a fresh timeout allowance.
- Observe both pidfds dead and the owned unit MainPID/Job zero. If its cgroup
  remains, require recursive `populated=0`; a removed group is recorded only in
  conjunction with this actual completed owned stop and both process deaths.
  A second method checks a fresh stop/completion for an already stopped unit.

## Startup, bounded use and cleanup

Only the test pipeline starts its units. Readiness completes before assertions;
run/attempt-scoped names, SHA in the raw log and exact-head artifact names bind the
execution to its Actions run. Each unit has `Restart=no`, `RuntimeMaxSec=60s`,
`TimeoutStopSec=1s`, whole-control-group termination and KILL enabled. These are
synthetic test-service lifetime controls, **not production network timeouts or
accepted recovery phase allocations**. No alarms, schedules, databases, containers
or other recurring staging runtimes are provisioned.

Cleanup is registered before each possibly ambiguous submission and stops/resets
only that exact owned transient name, then requires it no longer be loaded. An
`always()` Actions step repeats idempotent exact-name collection after test failure
or cancellation; the native runtime cap and ephemeral runner destruction remain
backstops. Cleanup never enumerates a prefix to choose kill targets. Raw test and
cleanup logs are retained even on failure. Do not call an unsuccessful or skipped
cleanup a pass.

## Idle job display compatibility

The first real-manager run reached both inert services and an authenticated
completion, then failed the stopped-state assertion: systemd 255 prints an idle
job as `Job=`, not `Job=0`. The existing reader's numeric-only expectation could
never acknowledge that real idle display. Complete failure output and cleanup
receipts are retained; no failed job is called qualification.

`manager.properties` now maps **only an explicitly present empty Job property**
to its numeric zero representation, after the complete exact property-schema
check. Missing/duplicate Job still refuses; pending numeric jobs and every other
empty field retain their value. The real tests keep their original zero
assertions, and two parser/observer regressions cover this compatibility boundary.
The matching versioned source is systemd v255
[`systemctl-show.c`](https://github.com/systemd/systemd/blob/v255/src/systemctl/systemctl-show.c),
`print_property`'s Job `(uo)` branch: a positive numeric ID is printed, otherwise
`bus_print_property_value(..., NULL)` emits the explicit empty property. This is
source correspondence, not permission to treat a missing field or absent job
inventory as completion, retirement, activation exclusion or drain.

## Persistent-mask reactivation qualification

A third method adds exactly two run/attempt-scoped fixture fragments under
`/run/systemd/system` and one exclusive `/etc/systemd/system/<owned-unit>` symlink
to `/dev/null`. This is **test-only installation on the disposable hosted runner**,
not an operational package installer or shared-host change. Existing files or
masks refuse; no overwrite, force mask, general unmask or directory deletion is
allowed. A root-owned marker and strict file metadata are checked before cleanup.
There is no `[Install]` section, enablement, schedule or recurring resource.

The method starts an inert TERM-ignoring parent/child service, captures its actual
invocation, cgroup and live pidfds using the same helper as the transient methods,
then calls the package's descriptor-bound `PersistentUnitMasks` primitive to
exclusively create/fsync/readback the higher-precedence persistent mask. Its
receipt explicitly denies effective activation exclusion. The fixture separately
reloads the manager; no reload or root provisioning is inferred by the primitive.
It asserts that the mask **does not stop existing processes**: the original
invocation/MainPID remains active and both pidfds remain live. A separate actual
`ManagerJobSession` stop, explicit whole-unit SIGKILL and matching completion must
terminate them. The test must not depend on pre-mask stop settings surviving a
manager reload. Only then
are a fresh direct start and a new `Requires`/`After` dependency start attempted;
both must refuse. The dependency payload's actual execution timestamp must remain
zero and no new process may reach the fixture readiness socket. Raw command
statuses/errors and observed manager states are retained, not normalized into a
complete-fence receipt.

The test also exposes a necessary integration distinction: masking changes the
manager's `LoadState` from `loaded` to `masked`. Existing strict containment
adapters require their original loaded fragment/effective-property pins; they do
**not** consume these fixture masks or gain permission to ignore changed pins.
Operational integration needs a separately bound mask/configuration transition
and its durable intent, rather than relaxing those readers or declaring mask
presence to be authority. The first reached Actions run failed with
`manager-properties-incomplete` after reloading the mask, before the new exclusion
assertions; both cleanup attempts also timed out stopping the TERM-ignoring
fixture. Those failures are retained. The corrected fixture uses an exact,
separate seven-property masked-state projection with raw observations, never
fills a missing property, and retains all process/identity/exclusion assertions.
Production `manager.properties` is unchanged. Cleanup now explicitly kills an
active owned group before its bounded stop; no success is claimed from a timeout.

Cleanup is registered before writing either fragment or starting the payload. It
stops only the two exact names, validates and removes only their owned fragments
and mask, fsyncs both directories, reloads the manager and requires `not-found`.
The separate `always()` cleanup repeats this exact procedure after failure or
cancellation, with the existing runtime cap and ephemeral runner as backstops.
No cleanup step selects targets from a prefix inventory. Missing or failing
cleanup remains a failing Actions step.

This qualification covers only **fresh** direct/dependency starts after masking
and a completed owned stop. It does not prove cancellation of already-queued or
already-authorized launches, template/alias/socket/timer/path/boot coverage, manager
re-exec/reboot behavior, root/broker exclusivity, actual daemon/shim/task containment
or old-epoch death. Durable mask intent/history, full pending-job retirement and
actual-exec launch exclusion remain required. The fixture must not be mistaken
for an implementation of those mechanisms. Tests execute only in Actions; no
local full suite, manager contact or build substitutes for exact-head results.

## Already-queued launch cancellation fixture

A fourth method uses four additional exact run/attempt-scoped `/run` fragments:
two inert oneshot dependency gates and two `/usr/bin/true` payload units. A
peer-credential-checked seqpacket socket holds each gate inside its real
ExecStart. No sleep, quiet-time interval or synthetic manager callback establishes
the ordering. The original fixture deadline, native job subscription, root/PID1
checks and one non-reconnecting bus remain in force.

A positive control submits a payload start through that bus, requires its actual
job ID/path to be `start/waiting` behind the held gate, then releases the gate.
Its matching authenticated `JobRemoved=done` and positive actual execution
timestamp must establish that this fixture can execute the payload. A separate
fresh pair is held in the same way, then receives an exclusive persistent mask
and directory fsync. Before reloading the manager, the test requires the original
waiting job to remain visible and calls `Job.Cancel` on that exact returned job
object. It requires the matching authenticated `canceled` completion, then reloads
and verifies the mask, submits a separate stop and requires that stop's distinct
`done` completion. A stored mask is not claimed effective before reload, and
neither mask presence nor disappearance from inventory supplies cancellation
proof. The held gate is not released until all these barriers complete.

After releasing the dependency,
require the actual gate process's pidfd death, successful gate completion, zero
payload execution timestamp and inactive/no-PID/no-job state. An empty job list
alone cannot supply any of those results.

Start/stop calls and the multi-job signal observer here are **test-only**.
The fenced branch now uses `WaitingStartCancellation` and `PersistentUnitMasks`
for actual source journal/persistence/native cancellation, and independently
requires the same accepted job's `canceled` completion. The target has not run:
its nonzero invocation pin and the original request/authority are explicitly
synthetic, not observed execution or operational provisioning. See
[fixed waiting-start cancellation](JOB-CANCELLATION-v1.md). No arbitrary broker
method, operational retirement or drain grant is exposed. Both positive and
negative cases must pass in Actions before this method is called qualified. The
existing exact-owned cleanup validates/removes only these four fragments and the
one new mask; the separate `always()` cleanup repeats it. Gates have bounded
native start/stop limits, the socket read is bounded and the runner is ephemeral.
No new recurring preview/staging runtime is created.

The first reached run failed before queue submission: the fixture incorrectly
expected the oneshot ExecStart PID in `ControlPID`, which was zero. The corrected
fixture requires its authenticated socket peer PID to equal actual `MainPID`;
cgroup and live pidfd checks remain. This matches systemd v255
[`service.c`](https://github.com/systemd/systemd/blob/v255/src/core/service.c),
`service_enter_start`'s oneshot branch, which calls `service_set_main_pidref` before
entering `SERVICE_START`. The raw failure and exact first fixture are retained;
it is not a production defect or a reached cancellation result. Both cleanup
paths passed despite this initial failure.

The next exact-head run reached both queued starts but failed before explicit
cancellation: after mask installation and reload, the original job ID was absent
from the job inventory. It therefore cannot qualify a canceled completion, and
its raw failure remains retained. The corrected ordering explicitly cancels and
witnesses the accepted job **before** reload can change its configuration/lifetime.
No missing job is converted into an acknowledgment; all original completion,
pidfd, positive-control and actual-execution assertions remain required. This
fixture correction does not implement operational reload/job reconciliation.

This is a controlled queued-before-exec case, not already-executing launch
revocation, manager re-exec/reboot, arbitrary activation-graph exclusion, old-epoch
death or complete pending drain. Durable mask transitions and operational job
retirement/actual-exec admission still remain separate requirements. No current
fixture result is implied by this source description.

## What a green job does not prove

This fixture supplies manager ABI, actual completion, tested whole-unit descendant
termination and cleanup evidence for the inert units, plus the narrowly tested
fresh-launch mask behavior above. It does **not**
prove exclusive activation/actual-exec admission, arbitrary pending-job retirement,
Docker task/shim placement, cold runtime teardown/quarantine relaunch, durable
registration/drain, installation writer exclusion, independent baseline/readiness
verification, broker provisioning, reboot/expired recovery, source-bound replay or
full-package acceptance. No operational runner or IPC mutation deny is changed.
No fixture timing becomes production downtime or a measured 120/180/300 budget.

REA angle: use the existing sd-bus implementation and the runner's real PID1,
transient-unit, cgroup and pidfd semantics rather than expanding synthetic manager
callbacks into an unsupported full-system claim.
