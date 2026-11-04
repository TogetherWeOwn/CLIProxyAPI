# Approved-content and recovery-input loading v1

**Read-only component source. Not an installable package, approval service,
privilege broker, restoration permission or service-start grant.** No host path,
unit installation, credential or live operation is selected by this document.

## Trust boundary

The caller supplies an independently approved content-index digest, source revision
and numeric UID/GID. A separate recovery approval supplies the intent, package,
manifest, baseline and policy digests plus installation/attempt identity and record
ownership. These Python values are not signatures or attestations. Constructing a
matching object, reading an index beside its files or hashing an arbitrary intent
does not authenticate approval.

Both loaders take **already-open trusted directory descriptors**, not environment
paths or request-selected roots. The installation boundary still has to obtain and
bind those handles securely to the approved installation, authenticate the approved
pins, retain the installation lock and exclude cooperating writers. The acquisition
context below supplies the local protected-path/lock subset, not the approval or
installation channel. Observing a
protected directory does not prove its ancestry or installation identity. There is
no fallback to searching a home directory, extracting an archive or loading a nearby
Python module. Hostile root, same-UID mutation, a compromised manager and malicious
caller-supplied trust anchors are outside this boundary.

The loader cannot bootstrap trust in its own interpreter, imported code or installed
service. Its verified snapshot must not be misrepresented as executing that code.
Archive-to-content correspondence, the archive hash and the installation mechanism
require their own reviewed evidence. In particular, `intent.package_sha256` is a
separate approved artifact pin: it is **not** silently redefined as the content-index
hash, and this loader does not independently verify archive bytes.

## Installed-content index

The root contains `content-index.json` and exactly the indexed regular files and
their required parent directories. Empty extra directories, hidden additions,
symlinks, hardlinks, special files, cross-device entries and unsupported metadata
are refused. Root/parent numeric ownership must match the approval; writable group
or other modes and special mode bits are unsupported. No permission is relaxed.

The exact index object is:

```json
{
  "schema": "host-recovery-content-v1",
  "source_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "files": [
    {
      "path": "runtime/worker.py",
      "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "mode": 320
    }
  ]
}
```

Here `320` is JSON decimal for mode `0500`; hashes/revision above are illustrative,
not accepted pins. The external index digest hashes **its raw bytes**. Duplicate
JSON keys, nonfinite values, unknown/missing fields, duplicate paths, self-indexing,
unsafe path components and invalid pins refuse. Supported file modes are `0400`,
`0444`, `0500`, `0555`, `0600`, `0644`, `0700`, `0755`; protected directories use
`0500`, `0555`, `0700` or `0755`. The supported ownership domain is explicit and
uniform. ACLs/xattrs are not supported.

Bounds: at most 128 tree entries including root and index, eight relative path
components, 512 path characters, 4 MiB per file, and 16 MiB total captured content
including index. Directory enumeration itself is bounded. A first inventory,
no-follow descriptor-relative reads and a final identity rewalk must agree.
Missing/replaced/changed files, reads or metadata failures produce no snapshot.
Returned file contents are immutable bytes behind a read-only mapping; JSON reads
produce fresh decoded objects. No executable path is returned, imported, extracted
or executed. A later change to the installation cannot change captured bytes.
Reopening a mutable pathname for execution would be a new, unproved operation.

## Original recovery inputs

`load_recovery` reads only fixed `intent.json`, `arm.json` and
`reconcile-request.json` names from an explicit private `0700` journal descriptor.
Each record must be single-link regular `0600` content with approved UID/GID.
Staged transition evidence refuses loading; it is not cleaned or promoted. The
loader does not consume a prior claim, retire the active latch or interpret an
outcome file as authority.

It validates:

1. Strict original intent schema and canonical intent digest against independent
   approval, including separate package/manifest/baseline/policy and attempt pins.
2. The original arm's strict schema and intent binding.
3. The request's strict schema/digest, expected digest-named worker binding,
   original arm, original inclusive same-boot recovery reserve and current time.
4. The independently supplied current supervisor owner. A same-boot restarted
   supervisor can differ from the original intent invocation, but its actual
   request owner, installation, attempt and boot must agree. The live manager/peer
   bootstrap still has to prove this owner at claim time; loading cannot do that.
5. All three record identities/bytes again and the journal-directory identity.

Unknown or expired/cross-boot timing is refused, not assigned a new budget. Baseline
hash correspondence does not verify baseline blobs or restored service semantics.
Progress/outcome records cannot replace a missing original request. Storage
uncertainty raises; the caller's independent alert path remains responsible for
reporting it without logging restricted path/exception text.

`SystemdWorkerBootstrap.from_journal` wires these original inputs into the existing
one-shot identity client. It does not acquire/retain the lock itself or grant a
retry after a durable claim. The caller must still supply approved unit/command
bindings and trusted manager/kernel observations. Identity claim-time deadline,
boot, invocation, owner, cgroup and connection-bound pidfd checks remain mandatory.

No local reader can impose a hard deadline on unavailable/uninterruptible storage.
Load time is not a recovery/drain/alert availability guarantee; continued bootstrap
must recheck the saved deadline before claiming any identity. Reboot recovery and
expired recovery need the separate bounded continuation protocol, not this loader.

## Protected installation-handle acquisition

`installation.open_installation` is a supervisor-owner context for obtaining the
loader handles. It takes a separate `InstallationApproval`: installation ID and
two **independently supplied** `DirectoryApproval` values, each binding an exact
absolute path, device, inode, numeric UID/GID and mode. These values must come from
the approved installer/manager channel. The component neither discovers them from
adjacent content nor authenticates their origin. It never creates directories,
installs code, relaxes permissions or changes existing service configuration.

Acquisition starts at `/`, opens every component with directory/no-follow/close-on-
exec flags and retains the complete descriptor chain. Every ancestor must be owned
by root or that root's approved UID, have no group/other write or special mode
bits, and have no unsupported xattrs/ACLs. A sticky world-writable ancestor is not
accepted. Paths must be exact absolute paths without empty, dot or parent segments;
there are at most 64 components and 4096 characters. Leaf device/inode, UID/GID and
mode must match independent pins. Content and journal roots must be separate,
non-nested and not aliases of the same device/inode. Journal mode is exactly `0700`.

The context takes a nonblocking exclusive flock on the **journal directory inode**,
the same object used by `durable.installation_lock` and `recovery_owner`. There is
no second lock file, attempt-specific lock namespace or wait-and-success fallback.
A supervisor retaining the existing lock excludes this context and vice versa;
workers must not take this owner context while their supervisor holds the lock.
All successful and exceptional exits close the owned descriptors. A retained
`InstallationHandles` object is revoked before descriptor closure.

The chain is revalidated after acquisition, around `snapshot` and on normal context
exit. Each opened inode and protection metadata must still agree with the entry
under its retained parent; a detached old directory is not a fresh approved root.
Observed replacement, permission/ownership/metadata change or read failure poisons
the handles for the rest of that session. Directory mtime/size are not identity:
ordinary journal writes cannot create a fresh lock namespace. No open descriptor
is promised safe against an unobserved hostile same-UID/root actor.

`handles.snapshot(...)` composes the content and original-recovery-input loaders
under this same lock. Their approval owners must match the root pins and recovery
installation ID must match the layout approval. Both sets of captured bytes are
returned only after final ancestry revalidation. Loading cannot return a new
recovery allowance, consume a worker claim or grant execution/restoration/start.
Content snapshots are immutable captured bytes, not executable pathnames. This
context does **not** enter a worker bootstrap or instantiate a live supervisor.

The caller's trusted mount namespace, independently authenticated approvals,
provisioned paths/inode pins, interpreter/code integrity and exclusion of other
writers remain prerequisites. Protected path observations are not mount-namespace
attestation; administrator-controlled mount transitions are not discovered as
approval. A privileged/hostile namespace change or inode reuse after destruction
is outside this local binding model. No guarantee can bound uninterruptible I/O.
The archive hash remains separate from the content-index digest. Failure leaves
original records/latches untouched; the outer owner must attempt its independent
alert path, not log restricted exception/path text or treat closure as recovery.

## Verification and remaining wiring

Synthetic owned-tree tests exercise real filesystem reads, exact inventory and
metadata, immutable snapshots, hostile paths/links, extra/missing files, changed
content, bounded enumeration/read limits and deterministic concurrent-change/I/O
faults. Journal tests bind original intent/arm/request to external approval and
reject self-consistent replacements, expired/cross-boot clocks, staged uncertainty,
owner changes and missing originals despite terminal-looking records. One test
loads an actual supervisor-written request while that supervisor retains the real
installation-directory lock; manager/fence callbacks are **scripted**.

Installation-acquisition tests use real owned temporary roots, independently
supplied inode pins, path/link/mode/metadata negatives, deterministic replacements
and failures at descriptor-acquisition/metadata steps, checking descriptor cleanup.
They show lock exclusion with the existing supervisor primitive and a separate
process, plus release after SIGKILL without changing the original journal records.
The composed snapshot tests read real synthetic content and original requests;
there is no actual manager, daemon or installed service. Fixtures are created only
in fresh directories below the numeric test user's protected home (not `$HOME`,
which a harness may redirect below `/tmp`). Existing ancestors are never chmodded.

These are component results, not installed-systemd/daemon or full recovery evidence.
Trusted installation, authenticated approval/inode-pin provisioning, runnable
persistent services, broker wiring, the independently enforced boot/internal-restart/start/writer/pending
operation fence, full recovery execution/oracle, operational external alert route,
source-bound replay/probe completeness and the approved disposable full-system
matrix remain prerequisites. Neither this component nor its factory changes any
release pin or activates integrated acceptance.

REA angle: reuse Linux no-follow descriptor-relative filesystem operations and the
existing journal/request schema rather than execute an untrusted archive, trust a
nearby index or invent a parallel recovery authority.
