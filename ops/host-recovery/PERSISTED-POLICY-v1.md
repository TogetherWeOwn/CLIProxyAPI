# Offline persisted Docker policy observation v1

`host_recovery/persisted_policy.py` adds a read-only prerequisite to the connected
cold-runtime submission. It neither launches a daemon nor adopts, registers,
repairs or normalizes metadata. Existing operational runners still deny execution,
restoration, service start and settlement. This is not a complete cold barrier.

## Exact source and supported scope

The reader supports the inspected Moby source
[`6430e49a55babd9b8f4d08e70ecb2b68900770fe`](https://github.com/moby/moby/commit/6430e49a55babd9b8f4d08e70ecb2b68900770fe)
only. It refuses a topology naming another dockerd source revision; this revision
check is not binary authenticity or loader/installation provenance.

- [`container/container.go:154-187`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/container/container.go#L154-L187)
  loads `config.v2.json`, then `hostconfig.json`. `ImageID` is serialized as `Image`.
- [`container/container.go:237-259`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/container/container.go#L237-L259)
  accepts absent hostconfig as an empty default. This reader deliberately refuses
  it instead: an absent explicit policy is not approved restart-disabled metadata.
- [`daemon/daemon.go:304-315`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/daemon/daemon.go#L304-L315)
  migrates empty restart policy names. This reader does not perform or accept that
  migration. Both `Name="no"` and integer `MaximumRetryCount=0` must be present.
- [`api/types/container/hostconfig.go`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/api/types/container/hostconfig.go)
  defines restart-policy and host fields. Python booleans/floats do not substitute
  for Go integer retry counts. Case-aliased duplicate fields, non-ASCII field
  names, duplicate exact fields, malformed/nonfinite/partial JSON, UTF-16/32 and
  BOM-only Python interpretations refuse rather than disagree with Moby decoding.

This is a policy/identity projection, **not a complete Moby metadata decoder**.
Other metadata files, containerd state, plugin/swarm state, daemon configuration,
mount/deployment equivalence, provenance and earlier restart waiters remain
separate qualification requirements. No stopped-task fact is derived from
`config.v2.json` State: it can be stale after SIGKILL. No runtime metadata is edited
to manufacture a stopped state or conforming policy.

## Protected inputs and read boundaries

Trusted provisioning supplies, out of band:

1. The original `SupervisorPeerAuthority` and its immutable `Topology` binding.
2. An independently pinned `DirectoryApproval` for exactly
   `data_root/containers`, including device, inode, owner, group and supported mode.
3. Canonical bytes mapping each approved full object ID to its independently
   approved **complete raw hostconfig hash**. Never learn or repin that approval
   from the same mutable metadata being checked. Constructing this object in a
   fixture is not administrative provisioning or authenticated approval.

Reuse the original protected intent/registration reader from quarantine inventory;
no second installation flock or daemon helper is introduced. Expected inventory
is exactly the original old full ID plus at most one durably registered candidate.
The directory names and approved map must both match that set. Unknown, partial,
unregistered or missing objects refuse; no label filter or guessed adoption.

Every object directory and required policy file is opened descriptor-relative and
no-follow. Require protected supported ownership/modes, same device, regular
single-link files, no extended metadata, bounded reads and unchanged path/inode/
content signatures. Both metadata files are limited to 1 MiB. Verify persisted
ID/image against the original registry and rollback/candidate image pins; require
explicit restart disabled, zero retries, AutoRemove=false, Privileged=false and
the topology's exact cgroup parent. The whole raw hostconfig must match its
independent approved digest, including fields outside that narrow projection.

Two snapshots, per-file readbacks and a final original-registry recheck must agree.
Original peer/flock/manager/input/deadline checks remain live across reads. Any
exception permanently revokes that observer; errors contain fixed codes, never
restricted metadata. Public evidence contains digests/counts and explicit denies,
not object IDs, paths, configuration contents or approval blobs. Repeated stable
reads still cannot prove continuous writer exclusion or exclusive ownership.

## Connected ordering and lifetime

`MaskedRuntimeStop` accepts this protected policy boundary only when it shares the
original authority, runtime units/effective pins and cgroup domain. Its fixed
target now includes the policy configuration. After both stop completions,
recursive kill, empty observation and original process-death checks, read policy
before completing the sequence. Recheck it through final observations, outer
return durability and peer ACK while the original process witnesses remain held.
Policy drift or a read fault prevents a successful return/ACK even if containment
already occurred; a persisted outer return cannot be replayed or called drained.

The connected runtime server requires the policy boundary. Direct legacy embedding
without it can still exercise containment components, but explicitly reports
`persisted_restart_policy_observed=false` and cannot be exposed by that server.
The wire observation adds `persisted_restart_policy_observed=true` only for the
checked path, always alongside `runtime_relaunch_allowed=false` and all existing
drain/fence/recovery/start/settlement/production denies. No operational entrypoint
is enabled. The observation is volatile, not a reconstructible cold-epoch or
ownership certificate; retained broker-history records grant nothing new.

## Verification and remaining gates

New owned-files/real-peer/flock tests and connected manager composition tests are
**authored, not verified until exact-head GitHub Actions completes**. Manager,
root provisioning, task/process/domain and daemon boundaries remain scripted.
No local suite, build, manager or runtime execution is needed or authorized.

Actual-execution launch guards, complete activator/writer/job exclusion, old-epoch
death, provenance from the first create, quarantine-only relaunch, complete runtime
inventory/registration/drain, independent stopped-baseline/readiness/result
verification and operational recovery/resume remain unfinished. Full pinned-package
replay/source-drain, fault/timing and measured positive cap evidence remain required.
This policy observation closes none of those gates or the parent acceptance.

REA angle: reuse the pinned Moby on-disk load/default/migration semantics and the
existing original-registry/protected-file boundaries, not an ad-hoc metadata
rewrite, a Docker API authorization claim or a new recovery owner.
