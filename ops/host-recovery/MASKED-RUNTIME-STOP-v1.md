# Original-pending masked runtime stop v1

`MaskedRuntimeStop` is an embedding adapter for the **two fixed dedicated runtime
roles**, `dockerd` then `containerd`. It reuses the original-pending forward
sequence's implementation rather than introducing a second recovery owner or
installation lock. No operational IPC or runner enables this adapter. No daemon
is created, relaunched, adopted, registered or started here.

## Sequence and authority

Trusted provisioning supplies one original `OperationJournal`, unused
`PersistentUnitMasks` and `RuntimeStopJobs`, the latter's non-reconnecting
`ManagerJobSession`, and a descriptor/independent-inode-pinned `RuntimeDomain`.
Both fixed unit cgroups must be immediate children of that exact domain. The
calling broker must remain outside it; the domain's existing mount, descriptor
and no-follow path checks remain unchanged.

A prior original `contain_forward` return is required for sequencing, **not as
proof of forward quiescence or drain**. The new target binds the same original
binding/epoch, both masks, both units, the manager connection/library/deadline,
prior forward operation and recursive domain descriptor. The caller must durably
publish `cold_quiesce_runtime` with this exact target and original deadline.

Under the journal's existing mutex:

1. Exclusively publish/fsync/read back both fixed masks. Partial publication is
   retained for reconciliation, never overwritten or adopted.
2. Cancel any exact accepted `start/waiting` jobs using their object paths and
   separately durable pending/return/matching `canceled` completion records.
   Other fixed jobs refuse. There is no numeric-ID cancellation fallback.
3. Publish reload pending, issue one authenticated Reload, verify both typed
   effective-mask projections, and separately persist/recheck its return.
4. Submit the fixed dockerd stop with separate pending/return records. If not
   already completed, issue at most one whole-unit KILL. Wait for the exact
   authenticated `done` completion and persist/recheck it. Repeat for containerd,
   in that order. Inactive projections still need their own stop completions.
5. Only after both stop completions, perform one descriptor-relative recursive
   `cgroup.kill` write. Wait for explicit `populated=false` under the same original
   inclusive deadline, not a renewed kill/collection allowance. Missing domain,
   unknown values, read/write failure, peer/lock/manager/input/configuration drift
   or expiration refuses. Recheck empty observations across trailing authority
   and effective-mask reads.

The adapter never publishes the **outer** cold-quiesce return or drains the
operation. Lost replies, persistence faults and partial effects permanently close
this instance, its manager session and journal. No replay, repair, new epoch,
deadline renewal, restoration, service start or settlement follows.

## Evidence and limits

Ordinary tests use actual private masks/journal files but **scripted manager and
cgroup-domain boundaries**. They cover both-role ordering, all 14 separate phase
publications with reached EIO/ENOSPC hooks, absent/failed completions, changed
pins, deadline/peer loss, failed recursive kill and late repopulation. They are
component evidence, not an installed cold-runtime barrier.

The separate Actions-only native fixture adds an inert two-service pair and a
third TERM-ignoring parent/child service in one explicitly started owned slice.
The third service is not targeted by either fixed stop/KILL: its pidfds must stay
live through both stops and die only after the source recursive slice write.
Actual root/PID1 credentials, bus, library, typed properties, masks, job signals,
pidfds and cgroup2 domain checks are not mocked. Each fixed service must also
refuse a fresh direct start. See [native fixture boundaries](SYSTEM-MANAGER-TEST-v1.md).
New assertions must pass at the exact Actions head before qualification is claimed.

The original request, authority, forward return and epoch in that fixture remain
**synthetic**. The services are not Docker, containerd or real shims. Empty
observations and dead fixture pidfds do not prove complete runtime containment
coverage, activation/writer exclusion, manager reexec/reboot behavior, old-epoch
death, quarantine policy/inventory/registration, pending drain, full recovery or
independent baseline/readiness/result verification. These remain prerequisites.
All complete-fence, recovery/start/settlement and production-acceptance flags
remain false. Fixture duration is not a measured recovery phase cap or downtime.
