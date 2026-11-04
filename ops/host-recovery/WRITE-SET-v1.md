# Multi-root filesystem recovery subset

**Source component only. Not an installed host adapter, an authenticated approval
channel, a complete semantic start oracle or permission to operate a service.**

## Restricted inputs

`host_recovery/write_set.py` loads an explicitly pinned
`host-recovery-write-set-v1` manifest from an independently approved protected
backup directory. The original durable intent's `baseline_sha256` must bind the
same aggregate manifest bytes. Each declared root has an opaque identifier, a
per-root baseline manifest SHA-256 and an explicit candidate-only additions map.
The aggregate also names the auth root, exact nine selected paths, original
seven-disabled/two-enabled flags and supported original auth type. Paths and
selection remain restricted; public receipts contain counts and a digest only.

The backup directory contains exactly `manifest.json` and one directory per
root. Each root directory uses the existing `inventory.save_baseline` layout:
restricted `manifest.json` plus exactly the referenced blob files. No adjacent
manifest, internally consistent digest or caller dictionary authenticates
approval. Durable aggregate construction, authenticated provisioning and binding
the *entire required* operational write set remain the installer's responsibility.
The loader cannot detect a required root deliberately omitted by an untrusted
approver; that is why the original independently accepted manifest is required.

`open_write_set` requires one external `DirectoryApproval` for the backup and
every live root. It opens no-follow paths with the existing protected-ancestry
checks, pins device/inode/uid/gid/mode and retains/revalidates those path identities
until context exit. Duplicate/nested paths and shared approved inodes refuse,
including a backup inside a write root. Missing/extra roots, mode/owner mismatches,
unsafe paths, links, special files, unsupported metadata, unknown entries and
malformed or tampered baselines refuse. No path or permission is created or
relaxed. There are aggregate bounds of 16 roots, 4096 baseline/addition/reserved
staging entries and 64 MiB original file bytes, in addition to per-tree limits.
Privileged bind-mount/namespace replacement and hostile root/same-UID actors are
outside this ownership boundary; path checks are not mount attestation.

## Lock, quiescence and budget boundary

The caller must retain the **existing installation-directory lock**. This
component creates no lock namespace and does not acquire a worker's competing
lock. It cannot prove a lock was acquired or identify/authenticate the recovery
owner by itself. Complete manager, daemon, pending-operation and writer fencing
must already be enforced independently. A required `check(deadline=...)` callback
revalidates that boundary and returns strict `True`; a scripted acknowledgment is
not its implementation. Checks bracket filesystem operations under the original
coordinator's phase deadline. The component retains clock continuity within its
context, but does not invent a new arm, failure timestamp or budget. Boot/owner
continuity still belongs to the coordinator/manager boundary. Checks cannot
interrupt wedged filesystem calls or provide a hard-real-time I/O guarantee.

## Recovery ordering

- `validate_recovery(intent, deadline=...)` loads and validates **all** pinned
  baselines and plans, checks the exact-nine original auth selection and inspects
  every current live root before the first mutation. A malformed later root
  therefore cannot cause an earlier root to be restored first.
- `restore_complete` repeats that all-root precheck, revalidates original baseline
  material between roots, then delegates each complete root to the existing
  idempotent restorer. Only approved candidate additions and deterministic reserved
  restore staging may be removed. Unrelated providers and all original file bytes,
  ownership and supported modes are restored, not merely the selected nine auths.
- A fresh independent all-root inventory after the last restoration prevents a
  receipt based only on the most recently restored root. The fence must continue
  excluding cooperating writers across the entire scan; sequential scans alone
  are not a filesystem transaction or a substitute for that fence.
- `verify_files` independently reloads the pinned baseline and rescans all live
  roots again. It produces a secret-free **filesystem-only** receipt. It requires
  restoration in this invocation and retains `semantic_start_oracle_proven`,
  `start_permission` and `production_acceptance` as **false**.
- Any failure poisons the instance. After a partial restore, a separately owned
  fresh context may use the same original pinned baseline and deterministic
  staging reconciliation, subject to its existing budget/continuation rules. No
  in-memory progress, file presence or prior receipt grants a retry/start.

The methods can supply the coordinator's filesystem restoration boundary. The
complete old-image/config/Compose/top-level-replay/no-plugin semantic oracle,
all-root policy/render/schema checks, actual fence and manager service are still
separate prerequisites. No service start, request/claim reconciliation, terminal
record, latch retirement, admission or external alert transport is implemented
here. In particular, the filesystem receipt deliberately **cannot** satisfy the
coordinator's strict `verify_baseline_stopped` receipt shape.

## Evidence boundary

Repository tests use only fresh owned synthetic protected roots. They include
mixed-provider auth bytes/metadata, config/Compose bytes, plugin removal,
all-root precheck failures, EIO/ENOSPC at every atomic file transition after an
earlier root has been restored, final cross-root verification failures and a real
separate-process SIGKILL during a deterministic partial restore. The latter holds
the real installation lock and reopens/restores all roots after process death.
Its quiescence/manager/daemon boundary remains **scripted**.

Coordinator composition tests retain the original durable arm and test actual
multi-root restoration, but host/image/replay/start/readiness acknowledgments are
explicitly scripted. They do not establish installed-systemd/daemon recovery,
measured phase caps, complete recovery timing, source-bound replay acceptance,
external notification or downtime. No live credentials/configuration, units,
daemon, production endpoints or release pins are accessed.
