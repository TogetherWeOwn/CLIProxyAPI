# Real system-manager transport fixture v1

The `recovery-system-manager` job in `pr-test-build.yml` exercises the existing
`ManagerJobSession` against **real systemd PID1 on a disposable GitHub-hosted
Ubuntu runner**. It is separate from the synthetic private-bus matrix and ordinary
Python discovery. Missing capabilities fail the separate job; ordinary discovery
skips the two methods explicitly. Never run this fixture on a workstation, shared
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

## What a green job does not prove

This fixture supplies manager ABI, actual completion, tested whole-unit descendant
termination and cleanup evidence for these two inert units only. It does **not**
prove exclusive activation/actual-exec admission, arbitrary pending-job retirement,
Docker task/shim placement, cold runtime teardown/quarantine relaunch, durable
registration/drain, installation writer exclusion, independent baseline/readiness
verification, broker provisioning, reboot/expired recovery, source-bound replay or
full-package acceptance. No operational runner or IPC mutation deny is changed.
No fixture timing becomes production downtime or a measured 120/180/300 budget.

REA angle: use the existing sd-bus implementation and the runner's real PID1,
transient-unit, cgroup and pidfd semantics rather than expanding synthetic manager
callbacks into an unsupported full-system claim.
