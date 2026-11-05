# Real system-manager transport fixture v1

The `recovery-system-manager` job in `pr-test-build.yml` exercises the existing
`ManagerJobSession` against **real systemd PID1 on a disposable GitHub-hosted
Ubuntu runner**. It is separate from the synthetic private-bus matrix and ordinary
Python discovery. Missing capabilities fail the separate job; ordinary discovery
skips the three methods explicitly. Never run this fixture on a workstation, shared
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
then creates/fsyncs the higher-precedence persistent mask and reloads the manager.
It asserts that the mask **does not stop existing processes**: the original
invocation/MainPID remains active and both pidfds remain live. A separate actual
`ManagerJobSession` stop and matching completion must terminate them. Only then
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
presence to be authority.

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
