# Dedicated runtime topology input v1

**Input validation only. No broker, containment proof, service installation,
recovery execution or start permission.** The unresolved supervisor and identity-only
worker remain unchanged. Shared or unknown runtimes are unsupported; HTTP AuthZ
cannot stand in for the daemon-internal restart fence.

## Source surface

`host_recovery/topology.py` defines an immutable, bounded `Topology` byte snapshot
and `load_topology(content, sha256=..., installation_id=...)`. The latter consumes
`topology.json` from the existing protected `ContentSnapshot` reader, requires
root/root content ownership, compares a separately provisioned raw SHA256, and
binds the installation identity and package source revision to the content
approval. The caller still acquires the protected index/handles, excludes writers,
retains the original installation lock, authenticates the approval and revalidates
at later barriers. Constructing a Python snapshot or supplying a matching digest
is not authentication. No adjacent digest is discovered or trusted.

All JSON objects have exact required keys. Duplicate/nonfinite JSON, excessive
size (32 KiB), unknown/missing fields, ambiguous types and unsupported choices
refuse with fixed secret-free errors. `manifest()` returns a fresh decoded copy;
callers cannot mutate the captured bytes. `status()` returns a digest and
`input_validated_only`, with provisioning, complete fence, execution, start and
production acceptance explicitly false. It never publishes topology paths,
service owners, raw configuration or secrets.

## Closed manifest shape

There is deliberately no live-path example/default. The test fixture is synthetic
and not an operational installation manifest.

- `schema`: `host-recovery-topology-v1`; `installation_id`: the existing bounded
  installation identity format, independently matched on load.
- `runtime`: installation-only ownership; **fresh-empty-only** adoption; systemd
  cgroup driver; `restart_policy=no`, zero maximum retry count, AutoRemove false;
  live restore, Swarm, external launchers, boot autostart, socket/path/timer
  activation and force restart all false. `cold_barrier=required` and supported
  metadata projection `regular_tree_v1` are mandatory. That metadata name does
  not claim Docker metadata-format support or authorize editing it.
- `runtime.slice` and `runtime.cgroup_path`: one direct dedicated system slice and
  its exact relative-to-cgroup-mount path. The first input format excludes nested
  or dash-hierarchical slices, user-manager domains and system/user/machine slices.
  `runtime.units`: distinct fixed dockerd/containerd service names and effective
  configuration digests; conventional shared service names and templates refuse.
- `roles`: distinct broker, observer, supervisor, forward and recovery numeric
  UID/GID pairs, fixed units, effective-unit and launch digests. Broker is root/root;
  every other role is nonroot with distinct UIDs and primary GIDs. Only recovery
  uses a unit template. This describes primary identities, **not proof of actual
  supplementary groups, capabilities, ACLs, containment or unit sandboxing**.
- `tools`: dockerd, containerd, runc, systemd, kernel, broker, observer and interpreter
  each require explicit bounded version, full lowercase source revision and
  artifact SHA256. Actual source-to-binary correspondence, import closure and
  installed-version qualification remain separate.
- `resources`: distinct data-root, exec-root, containerd root/state paths; private
  dockerd socket below exec-root and containerd socket below containerd-state;
  an explicit nondefault containerd namespace. Conventional shared Docker/containerd
  paths and `/var/run` aliases refuse. These are expected paths, not opened
  descriptors or a claim of exclusive runtime/network/storage ownership.
- `protected_roots`: package, approval, baseline, broker state, supervisor state and
  private worker evidence. `write_roots`: auth, config, Compose and plugin roots.
  Every directory root must be canonical, bounded and pairwise disjoint, including
  from runtime storage. The initial conservative format excludes OS infrastructure
  roots (including `/etc` and `/usr`) rather than permitting broad restoration.
  Mount aliases, bind mounts, symlinks, actual ownership and metadata require
  protected descriptor acquisition and independent qualification; lexical
  separation alone cannot prove separation.
- `pins`: full package/candidate/rollback/producer source revisions; package import
  closure, candidate/rollback images, plugin archive **and** library, producer
  schema, approved policy and baseline SHA256. Hashes describe correspondence,
  not acceptance of a new release pin or authorization to replace installed bytes.

The parser validates the selected conditional topology, not the whole deployment
or original A+B policy. Supplementary groups/socket ACLs, network isolation,
persisted runtime metadata/version support, effective manager activation graph,
actual full task/shim containment and independent approval provenance cannot be
proven by these strings/booleans. Missing proof keeps all operational denies.

## Fixed forward containment submission

`host_recovery/broker_containment.py:ForwardContainment` is an embedding adapter,
**not installed, provisioned, or exposed by the observation-only IPC server**.
It joins the original supervisor's live peer/kernel flock/input checks to the
private operation journal and the existing strict manager reader. The captured
forward unit/effective configuration must match the original topology pin and
numeric forward owner. Runtime, recovery and supervisor domains cannot overlap
the forward target. It acquires no second installation lock.

- One attempt per adapter and one durable `contain_forward` pending record per
  original journal. The broker journal mutex covers the complete operation, not
  just publication. A different adapter cannot replay a consumed operation.
- Read back/sync pending before any submission. Recheck original peer, lock,
  inputs, unit, configuration and original shortened deadline before the fixed
  stop and again before whole-unit SIGKILL. Never accept caller argv/unit/PID,
  arbitrary commands, start/restore methods or worker-provided callbacks.
- A successful helper exit only records return. Two fresh recursive cgroup and
  pinned-unit observations bracket return persistence. `forward_stopped_observed`
  describes those point reads only; missing cgroup, surviving descendants,
  pending jobs or inconsistent observations are not stopped proof.
- Any uncertainty closes the adapter/journal and retains pending/staged/return
  bytes. No retry, job recreation or lost-reply repair occurs. The embedding
  broker still owns helper reaping and independent alert attempts, including
  when persistence fails; this adapter is not an alert service.

Manager stop/kill addresses a **fixed unit name**, not an invocation-atomic kernel
handle. Independently enforced exclusive activation ownership is still required;
point reads alone cannot exclude an intervening activation or recall submitted
work. This adapter does not claim tracked-job cancellation/retirement, daemon
handler drain, cold teardown, activation fencing or a complete fence. Every
pending-drained, restoration/execution/start/settlement and acceptance flag stays
false. The supervisor remains fixed-deny, the worker identity-only and all IPC
effect methods denied until the complete operational boundary is qualified.

Tests use actual synthetic foreign flock/Unix peers and private durable records,
with **scripted manager/stop/kill/cgroup replies**. They are not installed-systemd,
root-broker or runtime qualification. New methods run on GitHub Actions; no local
suite or build is required to substitute for exact-head Actions evidence.

## Fixed dedicated-runtime containment submission

`host_recovery/broker_runtime.py:RuntimeContainment` adds fixed stop submissions for
both pinned dedicated runtime units, then one recursive `cgroup.kill` write through
a separately preopened exact slice descriptor. **Embedding source only, not an
installed broker, enabled IPC mutation or complete cold barrier.** There is no
relaunch, runtime API, restoration, business-object start or settlement method.

- Borrow the original supervisor authority and existing broker operation journal;
  serialize the whole operation under its mutex without acquiring an installation
  lock. Require the prior original forward-containment return, not a stopped/drained
  assertion derived from that return. Publish/sync/read back the one-shot
  `cold_quiesce_runtime` pending record before either stop or the kernel write.
- Runtime units, numeric root ownership, effective configuration, fragment hashes,
  original invocation/cgroups and dedicated slice match independent bindings and
  the original topology. Stop dockerd before external containerd. Each submission
  rechecks the live supervisor peer/flock, original inputs, original capped clock,
  unit and configuration. No caller argv, arbitrary unit, PID or numeric job cancel
  is supported. Manager unit-name calls remain non-atomic with invocation reads.
- `RuntimeDomain` borrows an independently pinned device/inode descriptor. Recheck
  its exact no-follow path and cgroup2 mount/fd mount-ID correspondence before use;
  refuse bind/subtree mounts, disappearance or recreation. The calling broker must
  be outside the target. Open only descriptor-relative `cgroup.kill`, validate the
  kernel file and run the broker's internal authority check immediately before and
  after the single write. No PID fallback, retries or alternate cgroup path.
- Fresh unit and recursive populated observations bracket return persistence.
  `runtime_empty_observed` describes **point observations only**. Manager retirement,
  activation exclusion, complete containment qualification, quarantine inventory,
  pending drain, complete fence, restoration/start/settlement and production
  acceptance remain false even if the slice appears empty.
- Unknown manager jobs refuse. Only this adapter's exact returned StopUnit job
  can remain pending (see below); it is not retirement or drain evidence. This
  adapter cannot retire/cancel jobs or resume after a lost reply. Missing/malformed events, failed/short kill writes, D-state population,
  peer/input/clock/configuration drift and uncertain persistence retain history and
  close the adapter/journal. Its embedding owner still must attempt independent
  escalation despite storage faults and retain helper ownership.

Tests use real synthetic lock/Unix peers and ordinary disposable files, **scripted
manager replies and a patched cgroup2 mount boundary**. The proc mount parser has
separate synthetic tests. No test writes to the host's cgroup hierarchy or calls
its systemd/daemon. These are component negatives, not installed privilege,
activation/retirement, kernel-kill or complete runtime qualification. Exact-head
GitHub Actions, not a local suite/build, supplies execution evidence.

## Tracked runtime manager-job submissions

`host_recovery/manager_jobs.py:RuntimeStopJobs` replaces fire-and-forget runtime
stops in `RuntimeContainment` with fixed system-bus `StopUnit(unit, "fail")` calls.
It does not change the forward-unit adapter or enable any operational IPC/runner.

- The topology now requires a separate `tools.busctl` source/version/binary pin;
  old topology inputs without it refuse rather than silently inheriting a helper.
  Trusted embedding must provide the protected helper reader and command owner;
  scripted hash readers in tests are not provisioning or executable-load proof.
- Original request/epoch/outer pending and exact unit/invocation bindings precede
  a durable per-role stop-pending record. Record the observed system-bus ID and
  unique manager name, use that unique destination (never a replacement name),
  and durably retain the actual returned job ID/object path. Lost replies,
  persistence faults or drift preserve history and prohibit redispatch. Mode
  `fail` avoids deliberately replacing an incompatible queued job.
- Typed bounded `ListJobs` reads reject malformed, duplicate, conflicting or
  untracked jobs for either fixed runtime unit. Unrelated jobs are never targets.
  Only exact returned stop identities may remain pending during recursive kill.
  Live original peer/flock/input/deadline and helper/configuration checks revoke
  at bus and persistence boundaries. No numeric-job cancellation is implemented.
- `pending_observed` and `absent_not_retired` are observations only. The legacy
  busctl mode has no subscribed completion witness. Separate busctl connections
  cannot atomically bind a submission to one bus generation or unit invocation;
  observed drift refuses but unobserved replacement races remain. The optional
  single-connection mode below observes completion, not activation exclusion or
  a cold barrier. Empty job/unit/cgroup snapshots do not establish retirement.
  All retirement/drain/fence/restore/start/settlement claims remain false.
- Read-only crash history recognizes the bounded pending/returned job records,
  rejects orphan/conflicting/uncertain ordering, and never reconstructs a permit.

The method signatures and JSON nesting were checked against public systemd v255
`src/core/dbus-manager.c` (`StopUnit`: `ss` to `o`; `ListJobs`: `a(usssoo)`) and
`src/busctl/busctl.c` (`json_transform_message`/array/struct serialization).
This is source inspection, not installed-version or real-manager qualification.
New tests script all bus responses and helper hashes; no host bus is contacted.

## Optional single-connection completion witness

`host_recovery/manager_bus.py:ManagerJobSession` supplies an optional embedding
transport to `RuntimeStopJobs(session=...)`. It is not installed or constructed
by an operational runner. It opens one explicit system-bus socket, ignores bus
address environment variables and never reconnects or falls back to busctl.

- The caller retains an independently pinned, root-owned `ProtectedFile` handle
  for libsystemd, supplies the original authority barrier and owns session cleanup.
  Loading uses the retained descriptor after checksum validation and repeats the
  checksum afterward. Version/ABI, dependencies, loader environment, immutability
  and actual root provisioning still require package qualification. Merely passing
  a matching checksum is not approval. No package installation is performed here.
- Before any stop, query bus ID and manager unique name on this same connection,
  authenticate the bus-reported UID 0/PID 1, wait for both match-install replies,
  subscribe to manager signals, and recheck identity. Calls use the unique owner.
  Native asynchronous calls are pumped under the original deadline and revoking
  authority check; no extra network/wait allowance or replay is added.
- Validate exact `JobRemoved(uoss)` sender/path/interface/member, bounded serials,
  ID/path/unit and closed result set. Hold an early signal until its actual stop
  reply binds the identity. Duplicate, conflicting, malformed or overflowed events,
  owner loss (even reacquisition), disconnect and authority loss revoke the session.
  No callback retains a borrowed native message; only bounded copied fields survive.
- Durable original pending still precedes the stop; the actual return precedes a
  separately durable completion record, which binds its digest, bus/name and sender
  serial. Missing signals remain `absent_not_retired`. `completion_done_observed`,
  `completion_failed_observed`, `completion_canceled_observed` and other explicit
  results are distinct. Failed/canceled completion is never successful quiescence.
  Read-only history checks correspondence and does not revive a live session.
- Completion is **not retirement/exclusive ownership**: StopUnit may merge a
  compatible queued stop, and a unit-name call is not an invocation-atomic effect.
  Concurrent activations, activation graph/actual launch exclusion, service/task
  containment, old-epoch death, pending drain and quarantine remain separate required
  proofs. No numeric-job cancel, restoration/start or settlement is enabled. The
  forward-unit adapter still lacks this tracked completion transport.

Actions runs a separate `dbus-run-session` native matrix using libsystemd and a
synthetic manager on its disposable private bus. Only those tests replace the
production address and root/PID1 expectations, and they still authenticate the
actual test peer's bus-reported UID/PID. This is real ABI/protocol/ordering evidence,
not actual systemd, system-bus, root-provisioning, kernel-cgroup, daemon or cold-fence
qualification. The ordinary suite skips that matrix explicitly; its separate step
must pass. No local suite/build or live-host contact is needed.

## Required next boundaries

The independently provisioned privileged broker remains unimplemented. It must
consume fixed methods only, authenticate live peer/pidfd/manager invocation and
original kernel lock ownership, durably record one-shot operations before
submission, preserve ambiguous replies and use no second installation lock.

Recovery must close admission, revoke grants, stop/cancel tracked jobs and kill
all qualified dedicated slice tasks/shims/creators. Actual kernel/manager
observations must establish old-epoch death before quarantine relaunch. Protected
persisted policy provenance and complete full-ID/task inventory reconciliation
must precede a complete-fence acknowledgment. CLI death, an HTTP response, a
manifest flag or a dead dockerd MainPID is not that proof.

Only an independently pinned verifier may establish complete stopped baseline,
exact old object/deployment identity, readiness and supervisor result/settlement
facts. Existing scriptable callbacks are not proof producers. Cross-boot or
expired starts/settlement remain denied in the first vertical slice. Original
120/180/300 budgets are unchanged; cold teardown/relaunch, drain, persistence,
verification and notification costs all count.

No source was transferred, units installed/started, daemon contacted, privileges
changed, producer executed or production operation performed for these component
tests. A source-free systemd preflight does not qualify the disposable runtime.
The full dedicated-runtime fault matrix, real ingress/RPC/producer/source drain,
A+B/deployment equivalence, measured caps and integrated acceptance remain due.

REA angle: encode the inspected Moby restart policy and systemd slice teardown
constraints as closed expected input, while refusing to turn static configuration
or HTTP authorization into runtime internal-restart/drain proof.
