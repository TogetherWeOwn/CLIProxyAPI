# Whole-runtime inventory observation v1

**Read-only source component, not a cold barrier or operational quarantine.**
`host_recovery/quarantine_inventory.py` is not installed, exposed through IPC or
consumed by an operational runner. Every restore/start/settlement deny remains.
No relaunch, object adoption, registration write or pending-operation drain exists
in this component. A stable inventory is not an exclusion mechanism.

## Fixed observation boundary

`QuarantineInventory` requires the existing original-supervisor peer/manager/lock
observer, the matching dedicated `Topology`, separately approved Docker and ctr
helper paths and hashes, and broker-owned bounded command transport. It never
acquires a second installation lock or accepts arbitrary per-request commands,
paths, endpoints, namespaces, filters or object IDs. Helpers are independently
provisioned TCB inputs, not binaries downloaded or installed by this package.
The installed helper closure and exact runtime versions still need qualification.

Each command has before/after original peer, kernel flock, manager invocation,
protected original-input, helper-hash, boot and shortened original-deadline checks.
Any uncertainty permanently revokes this instance. No CLI exit code is interpreted
as cancellation or retirement of an earlier runtime mutation.

1. Open the independently approved original journal directory. Read and validate
   its pinned intent and zero or one exact `object-<full-id>.json` candidate record.
   Reuse the forward journal's stopped/restart-disabled registration validator.
   Reject staging, wrong names/IDs, multiple candidates, unsafe mode/ownership,
   partial records and read/readback/metadata changes. Hashes identify these private
   observations but do not authenticate an independently approved policy.
2. Enumerate **all** Docker containers with `--all --no-trunc`, without label
   filters. Require exact equality with the original full old ID plus the already
   registered candidate, if any. Missing or additional objects refuse. A matching
   label/image does not adopt a lost-create object; no journal record is written.
3. Inspect every exact full ID through the existing filtered Docker reader. Require
   the expected immutable image, candidate installation/attempt ownership,
   `RestartPolicy.Name=no`, zero retries, `AutoRemove=false`, and an unambiguous
   stopped `created`/`exited` state. Paused/restarting/dead/running states refuse.
4. Enumerate containerd namespace metadata and allow only the fixed dedicated
   namespace (or an empty list). Enumerate that namespace's container metadata and
   tasks **even if namespace metadata is absent**. Container metadata may contain
   only the expected full IDs; tasks must be empty. A missing namespace with
   nonempty container metadata is inconsistent and refuses. Unknown namespaces or
   IDs, any task, failed queries or unsupported output refuse.
5. Repeat the whole observation, including protected-registry recapture between
   passes and after the final pass. Compare the full private projections and
   registry file signatures. Recheck authority after the final helper/hash reads.
   Public output contains only counts, original binding and evidence digests,
   fixed classifications and explicit false authority/acceptance fields.

CLI output must be bounded, ASCII, newline-terminated, unique full-ID lines (or
truly empty). Short IDs, partial final lines, duplicate/blank/whitespace/control
lines, unexpected fields and overflow fail closed. Docker's inspect JSON is
parsed by the existing strict duplicate-key/type/ownership reader.

## What this deliberately does not prove

- The old daemon epoch and its handlers are dead; jobs completed or retired.
- External/manager/boot/socket/path/timer/restart/actual-exec launch exclusion.
- Every shim/helper/task is inside the qualified runtime slice. Containerd task
  API enumeration does not inventory processes or orphan shims, and namespace
  metadata alone cannot enumerate deleted unknown namespaces with orphan work.
- A genuine quarantine relaunch, persisted-policy provenance, complete runtime
  configuration, cgroup driver/parent, command/environment or effective mounts.
- Registration reconciliation after an ambiguous create, pending drain, complete
  writer fencing, independent stopped-baseline/readiness/result verification.
- Restoration/start permission, settlement, replay completeness or production
  acceptance. Repeated point observations and a matching journal are not grants.

These remain mandatory independently provisioned and qualified barriers. In
particular, never connect this observation to `start_fence=lambda: True` or
reinterpret its two observations as atomic admission exclusion. The real
activation/launch guard and cold/quarantine lifecycle remain implementation work.

## Reference and verification scope

REA angle: reuse Docker's filtered inspection and containerd's actual read-only
CLI/task service, not a label-only container census or guessed process linkage.
The supported command shape was inspected in public containerd v1.7.24 source,
commit `7dc50c3771caf2ff6a56b9b96053bf3fe1bfa550`:
`cmd/ctr/commands/{containers/containers,namespaces/namespaces,tasks/list}.go`.
The quiet task path calls `TaskService.List` for the selected namespace. This is
reference-version static evidence, not a pin/compatibility assertion for a future
installed runtime. No public reference code is imported, built or executed.

New tests use real synthetic original peer/flock/protected files, but scripted
manager, Docker and ctr responses. They assert reached queries/faults, unchanged
journal bytes, fixed argv, permanent revocation and non-authorizing receipts.
They are component coverage only; actual Docker/containerd/shim/slice and full
package/reboot/fault/timing qualification remain required in GitHub Actions or a
separately approved disposable system, never the live/shared host.
