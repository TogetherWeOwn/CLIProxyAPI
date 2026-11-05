# Persistent unit-mask publication v1

`host_recovery/unit_masks.py` implements one-shot, descriptor-bound **filesystem
publication only**. A stored mask is not an effective manager configuration,
completion/cancellation witness, stop, quiescence, launch-exclusion or drain proof.
There is no installation CLI, reload, unmask, replacement or start method.

## Fixed targets and prerequisites

Borrow an independently approved protected directory through the existing
`open_approved_directory` boundary, without taking another installation lock.
Accept exactly one forward `UnitBinding`, or the two fixed dockerd/containerd
bindings. Templates and arbitrary role sets refuse. Capture the directory's
approved path/device/inode/owner/mode and complete bindings in the target digest.
The supplied callback is the trusted embedding caller's original peer, kernel
lock, manager/input and inclusive-deadline check, never a request parameter.

The primitive supports owned synthetic directories for testing. Operational
provisioning must separately authenticate the root-owned **persistent systemd
load directory**, its precedence, exclusive writers, fixed unit/activation graph,
package/import closure and runtime ownership. A matching directory inode or a
Python object does not authenticate this provisioning. Do not repin a conflicting
existing fragment or move it aside to make this primitive pass.

## Publication and uncertainty

- Every target must initially be absent. A regular unit, directory, alias,
  dangling link or even an identical existing `/dev/null` mask refuses. There is
  no adoption/replay path for an old or ambiguous publication.
- Create only the fixed target names with exclusive `symlink('/dev/null', ...)`
  relative to the retained descriptor. No force, rename-overwrite, unlink,
  chmod/chown of existing content or broad directory operation is used.
- Fsync the containing directory and reread each symlink's exact target,
  ownership, single-link metadata and inode/signature. Revalidate directory
  ancestry and the original authority/deadline around each external boundary.
  Unsupported extended metadata or observed replacement refuses.
- Any write, fsync, readback, identity, deadline or authority uncertainty
  permanently revokes this object. Partial masks remain, without a successful
  receipt or automatic retry/cleanup. Reopening refuses existing targets and
  requires a separate cold-history reconciler. SIGKILL after fsync but before
  acknowledgment is not transformed into a completed operation.
- Public receipts carry a target digest and count, not unit names, paths, source
  bytes or peer identities. All effective-activation, job-retirement, drain,
  restore/start/settlement and production-acceptance flags remain false.

## Forward containment composition

`ForwardContainment(..., masks=...)` optionally includes the exact mask target in
its existing containment configuration. It first publishes/readbacks its
original `contain_forward` pending record, then publishes the masks under the
same original live peer/lock/manager/input/deadline checks, and only then submits
the existing fixed stop/whole-unit kill. Every later boundary reobserves the
published links. No second operation, installation lock, journal namespace or
recovery owner is created. A mask fault retains pending intent and prevents stop;
a later stop or return fault retains both pending intent and already-made masks.

This composition **does not reload the manager**. Reload can retire queued jobs
and change the loaded property projection. The existing strict loaded-unit
reader remains unchanged; an external reload/configuration change causes refusal,
not permission to synthesize missing properties or ignore original pins. A
returned record says only the filesystem publication and stop submission returned,
never that the mask is effective or that an old job cannot execute. Operational
reload/cancellation/configuration transition and durable retirement witnesses
remain required before this can contribute to a complete cold barrier. The
optional path is not exposed by mutation IPC or enabled in operational runners.

## Evidence scope

New component tests use real owned files, protected directory handles and
symlinks, deterministic publication fault hooks, and SIGKILL after actual fsync.
Forward composition uses a real synthetic original supervisor peer/flock/journal
with **scripted manager/cgroup effects**. These are not systemd/daemon recovery,
power-loss or reboot-durability drills. No local suite/build is required or run;
exact-head GitHub Actions is the verification authority.

The existing Actions-only real-manager mask test now calls this package primitive
for its exclusive persistent mask. Its reload/stop/native completion, live/dead
pidfd and fresh direct/dependency start assertions remain separate and unchanged.
The queued-start fixture retains its separately documented test-only publication
and cancellation ordering; it does not gain an operational job API. No source
change alone establishes a passing Actions result.

Authenticated provisioning, activation/actual-exec exclusion, durable manager
transition/cancellation/retirement, runtime/shim containment, quarantine/registration
and drain, independent restoration/readiness/result verification, reboot/expired
continuations and full-package/replay/fault/budget qualification remain incomplete.
Existing operational denies, release pins and integrated acceptance gates remain.

REA angle: reuse Linux exclusive symlink creation, directory fsync, the existing
protected ancestry handles and the real-manager qualification before attempting
a broader activation transaction. Do not confuse load-path persistence with
systemd's already-loaded configuration or an accepted job's lifetime.
