# Original-pending masked runtime stop v1

`MaskedRuntimeStop` is an embedding adapter for the **two fixed dedicated runtime
roles**, `dockerd` then `containerd`. It reuses the original-pending forward
sequence's implementation rather than introducing a second recovery owner or
installation lock. The explicit connected containment interface can embed this
adapter, but no installed service or operational runner enables it. No daemon
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

Under the journal's existing mutex, first capture a bounded descriptor-relative
inventory of the pinned runtime cgroup and its descendants. Two matching scans
bracket live pidfd acquisition and exact `/proc` cgroup membership checks. Missing
or changing groups, duplicate/migrating PIDs, overflow, unsupported pidfds, process
exit during capture or deadline/authority loss refuses before masks/effects. There
is no numeric-PID signal or fallback. Capture supports at most 128 groups, depth
16, 256 processes, 4,096 entries per group and 8,192 bytes per process-list read.
The same original deadline applies throughout; no retry/stabilization window is
added. These are supported inventory limits, not measured recovery phase caps.

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
5. Only after both stop completions, durably publish the v3 recursive-kill pending
   phase, binding the original operation, pinned domain configuration, both exact
   completion-record hashes and the required descendant-limit/freeze policies.
   Set the pinned domain's `cgroup.max.descendants` to **zero**, verify the exact
   kernel readback, then request its own `cgroup.freeze=1` and wait for the kernel's
   completed `frozen=1` event. Recheck original authority before one
   descriptor-relative `cgroup.kill` write. Separately persist its returned phase;
   a successful write alone is not an empty-domain observation. Recheck the zero
   limit and own completed freeze through empty publication, outer return and ACK.
   No retry, thaw or limit-reopening operation exists.
6. Wait for explicit `populated=false` under the same original inclusive deadline,
   not a renewed kill/collection allowance. Separately persist the digest-linked
   empty observation, then recheck live authority and emptiness after publication
   and across trailing effective-mask reads. Missing domain, unknown values,
   read/write failure, peer/lock/manager/input/configuration drift or expiration
   refuses even if the last observation was saved. Every final barrier also
   requires death of every captured process via its original pidfd. A live or
   invalid witness refuses even when the domain reports empty. Owned pidfds are
   released on both success and failure; a zero-process sample is explicitly
   counted as zero, never silently upgraded to coverage.

The result exposes only `observed_runtime_process_count` and
`observed_runtime_processes_dead`, not PIDs or cgroup paths. The sampled process
set is volatile, not a durable death certificate: retained kill records contain
no process-set data and can never reconstruct these witnesses after a crash. No claim
is made about processes escaped before capture, processes between the two sample
boundaries, later launches, unobserved daemons/shims or external writers.

The shared fixed-stop sequence additionally captures both units' typed unsigned
64-bit main-execution start timestamps before any masks and requires unchanged
values through stop/completion and recursive-kill/final observations. Changed
values refuse before empty-domain publication, including when a newly executed
main process has already exited. Only counts and an unchanged-observation flag
are public. These volatile samples are not continuous actual-exec exclusion,
control-process/writer coverage or a reconstructible crash witness; see the
[shared observation limits](MASKED-FORWARD-STOP-v1.md#fixed-unit-execution-timestamp-observations).

`stop` alone never publishes the **outer** cold-quiesce return or drains the
operation. The optional [connected containment protocol](CONTAINMENT-IPC-v1.md)
can separately persist that submission return through `record_return`, with fresh
post-fsync/ACK observations. An authority-bound sequence retains its witness until
the server closes it; direct embedders must close it on every exit. Lost replies,
persistence faults and partial effects permanently close the exchange and journal.
No replay, repair, new epoch, deadline renewal, restoration, service start or
settlement follows. A returned submission still never means drained.

The connected path additionally requires the protected [persisted-policy
observer](PERSISTED-POLICY-v1.md), bound in the target to the original authority,
fixed runtime units and domain. After containment, before completing the sequence,
validate original registered object/image identity and independently approved
restart-disabled raw hostconfig metadata without daemon contact. Reobserve through
return fsync and ACK; drift refuses. Direct component embedding can omit it but
reports `persisted_restart_policy_observed=false` and cannot be exposed by the
connected runtime server. Neither path allows runtime relaunch or proves complete
writer/job exclusion, old-epoch death, policy provenance or pending drain.

## Kernel descendant-creation limit

Linux v6.8 source at `e8f897f4afef0031fe618a8e94127a0934896aba`
[documents](https://github.com/torvalds/linux/blob/e8f897f4afef0031fe618a8e94127a0934896aba/Documentation/admin-guide/cgroup-v2.rst#L948-L953)
that the descendant limit rejects new cgroups when the existing count meets or
exceeds it. The [mkdir ancestry check](https://github.com/torvalds/linux/blob/e8f897f4afef0031fe618a8e94127a0934896aba/kernel/cgroup/cgroup.c#L5706-L5731)
checks **every ancestor**; zero therefore also rejects creation beneath an
already-existing descendant. Existing groups need not be removed before setting
zero. This is a kernel-enforced creation limit while retained, not just a sampled
empty-directory observation.

It does not prevent deletion of existing groups, migration to/from them, root
replacement, privileged changes to the limit, or privileged thaw. The original
independent ownership/provisioning and complete launch/writer exclusion are still
required. A missing/unsupported control, noncanonical scalar, short write, EIO,
ENOSPC, lost original authority or observed limit reopening refuses. Do not replace
unsupported kernels with a directory-listing heuristic.

Ordinary tests use scripted kernel boundaries. The Actions-only real-manager
fixture includes positive mkdir/rmdir controls at the exact runtime root and an
existing task subgroup, then requires actual `EAGAIN` refusals at both after the
source limit write. Existing stop/death/freeze/emptiness assertions remain. These
new assertions are **unverified until exact-head Actions executes them**, not
shared-host qualification or a complete lifecycle/activation fence.

## Retained recursive-kill history

v1 remains kill-only; v2 additionally records the required freeze observation;
v3 additionally requires literal descendant-seal policy/observation flags at all
three phases. Versions cannot be mixed and old records cannot acquire newer
claims. All versions remain non-authorizing history.

Three canonical restricted records use the original operation sequence:
`runtime-kill-pending`, `runtime-kill-return` and `runtime-kill-empty`. Each
publication uses the existing create/write/file-fsync/rename/directory-fsync and
readback barrier. Partial files and staged bytes remain for reconciliation;
there is no overwrite, adoption or redispatch.

The read-only history reader requires the prior original forward return,
returned mask reload, both matching `done` stop completions and their exact raw
hashes before accepting kill correspondence. It distinguishes `unreturned`,
`returned_without_empty_observation` and `empty_observed_unproven`. Orphan,
noncanonical, staged or conflicting records and an outer return hiding an
uncertain kill refuse. A saved empty observation is not a current kernel read,
old-epoch death, runtime coverage, pending drain or a start/settlement grant.
The bounded history inventory includes these three additional records. Reboot
still requires a separately identified continuation; no original budget resets.

## Evidence and limits

Ordinary tests use actual private masks/journal files but **scripted manager and
cgroup-domain boundaries**. They cover both-role ordering, the original 14 phase
publications plus three recursive-kill publications with reached EIO/ENOSPC
hooks, absent/failed completions, changed pins, deadline/peer loss, failed
recursive kill and late repopulation. New separate-process SIGKILL cases stop at
each actual kill-record directory-fsync hook; they test retained files and refusal
to replay, not kernel containment. History tests use synthetic records. All new
methods must pass in exact-head Actions before a test result is claimed. These
are component checks, not an installed cold-runtime barrier.

The separate Actions-only native fixture adds an inert two-service pair and a
third TERM-ignoring parent/child service in one explicitly started owned slice.
The third service is not targeted by either fixed stop/KILL: its pidfds must stay
live through both stops and die only after the source recursive slice write.
The source pre-stop witness must independently capture all six fixture processes
and require their death, with all owned witness descriptors closed afterwards.
Actual root/PID1 credentials, bus, library, typed properties, masks, job signals,
pidfds and cgroup2 domain/inventory checks are not mocked. Each fixed service must also
refuse a fresh direct start. See [native fixture boundaries](SYSTEM-MANAGER-TEST-v1.md).
New assertions must pass at the exact Actions head before qualification is claimed.

The first native run failed **before the sequence**: the generic persistent-file
reader rejected changing `cgroup.events` stat metadata. The corrected runtime
reader is specific to the already-verified cgroup2 domain: bounded no-follow read,
stable file device/inode/type/mode/owner/link count and path correspondence, but
no immutable-content size/mtime/ctime assertion for this dynamic kernel value.
The persistent `durable.read_file` contract is unchanged. New synthetic regression
methods retain timestamp-change acceptance and identity/replacement/overflow
refusal; these are not substitutes for exact-head native qualification. Initial
cleanup also refused the fragment-less synthesized slice; the corrected fixture
requires its strict stopped/empty builtin projection and absent kernel group,
while removed service fragments must still report `not-found`. Initial failures
and exact earlier sources are retained.

The original request, authority, forward return and epoch in that fixture remain
**synthetic**. The services are not Docker, containerd or real shims. Empty
observations and dead fixture pidfds do not prove complete runtime containment
coverage, activation/writer exclusion, manager reexec/reboot behavior, old-epoch
death, quarantine policy/inventory/registration, pending drain, full recovery or
independent baseline/readiness/result verification. These remain prerequisites.
All complete-fence, recovery/start/settlement and production-acceptance flags
remain false. Fixture duration is not a measured recovery phase cap or downtime.
