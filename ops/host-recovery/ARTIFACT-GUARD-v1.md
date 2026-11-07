# Plugin archive and installed-library guard v1

**Read-only source component and opt-in admission/stopped-barrier composition.**
Not an installer, authenticated approval channel, plugin loader, signature/build
attestation, renderer/schema validator, image-availability check or service-start
oracle. No actual producer package is loaded or executed by these tests. Existing
production/candidate/rollback pins remain unchanged.

## Explicit trust and file interface

`host_recovery/artifacts.py` supplies `PluginArtifactApproval` and
`PluginArtifactGate.verify(intent, deadline=...)`. An independently authenticated
installation policy must supply:

- the original canonical intent SHA256;
- **separate** archive-byte and installed-library-byte SHA256 pins;
- protected archive and library root `DirectoryApproval` objects, each binding an
  explicit absolute directory, device/inode, numeric owner and protected mode;
- one literal filename beneath each root and the exact library member inside the
  ZIP, plus numeric artifact UID/GID.

Names have no defaults, environment expansion, traversal or shell interpretation.
The gate reuses the existing protected-ancestry acquisition; it never chmods an
ancestor or treats an adjacent manifest/checksum file as approval. Roots can be the
same protected directory, but the artifact files must be distinct single-link
regular inodes. The gate rejects special files, symlinks, hardlinks, unsafe modes,
wrong owners, cross-device files and unsupported extended metadata.

The caller retains the **existing installation lock** and excludes cooperating
writers for the entire barrier and subsequent operation. Required `check()` must
revalidate supervisor/lock/writer-fence authority, not merely return a saved green
receipt. This code does not authenticate that callback, defend against hostile
root/same-UID actors, attest a mount namespace or install a writer fence.

## What is checked

1. Acquire both independently pinned protected roots; open both named files
   relative to their descriptors with no-follow/nonblocking/close-on-exec flags.
   Retain the opened descriptors until verification ends.
2. Check artifact ownership/metadata and bounded nonempty lengths. Stream SHA256
   using positional reads; require **both** independent pins to match.
3. Before ZIP parser construction, bound and validate the classic end-of-central-
   directory record: single disk, at most 64 members, at most 64 KiB directory,
   exact directory/end adjacency, no comments/ZIP64 locator. Archive size is at
   most 64 MiB. ZIP parser reads are additionally capped at 64 KiB per read.
4. Validate bounded unique relative member names, supported flags, stored/deflated
   compression and regular, non-group/world-writable, nonspecial metadata. Reject
   encrypted/special/directory entries, extras/comments, prefixed/trailing data,
   NUL-name ambiguity, missing/duplicate library members and unsupported formats.
   Total declared expanded size is at most 128 MiB, including other members.
5. Stream the exact selected member to SHA256 without extraction or execution.
   Its length, actual expanded byte count, CRC and SHA256 must match the installed
   library. Matching hashes of two unrelated files alone cannot pass this check.
6. **Rehash both retained file descriptors after member inspection**, then recheck
   file/path/root identity, metadata, caller authority and original deadline.
   Metadata equality alone is not byte equality at filesystem timestamp granularity.

Other member contents are bound by the approved **whole archive hash**; this is not
validation of their schemas, CRCs or policy. The conservative ZIP subset may reject
otherwise usable producer archives. Exact delivered-package compatibility must be
proved independently before operational use; never silently broaden the subset or
extract/repackage an incompatible artifact to make its old pin pass. Authenticating
the supplied archive/library pins and source/build provenance remains separate.

Success returns strict `True`, not an artifact path, executable handle or reusable
start permission. Any filesystem/parser/callback/clock/deadline uncertainty emits
only the fixed `artifact-check-unconfirmed` rejection. No archive content, names,
underlying exception text or restricted digests are included. Reads, hash loops,
ZIP inspection and postcheck rehashes share the caller's deadline. Checks cannot
interrupt stuck kernel I/O or constitute a hard-real-time watchdog.

## Barrier composition and recovery separation

`input_gate.GuardedBoundary(..., artifact_gate=<PluginArtifactGate>)` retains its
existing underlying listener/preflight or stopped-state checks, then performs the
artifact check and the fresh exact-input check under the same external deadline.
The parameter is optional for existing source callers; an omitted gate is **not**
artifact coverage or operational admission. There is no runnable production path
that can presently claim all guards are installed.

- Before arm: artifact refusal writes no intent and grants no first stop.
- After stop: artifact refusal skips forward mutation and candidate start, and
  uses the coordinator's separate recovery path. It does not reset any phase cap.
- Recovery methods delegate unchanged. A corrupt/missing candidate package must
  not prevent baseline restoration. The complete all-root/image/replay/no-plugin
  pre-start oracle remains independently required; an artifact match cannot
  synthesize that oracle or authorize old start.

Tests use actual synthetic ZIP files and protected synthetic directories, plus the
real built YAML helper and coordinator journal/order implementation. Manager,
writer/start fence, schema, recovery oracle and external alert transport remain
**scripted**. EIO/ENOSPC reads are injected. A receipt-persistence failure still
attempts the independent test transport; it is not external notification proof.

The first fixture run had three errors writing an intentionally read-only synthetic
library; an additional mutation-refusal test initially passed from that premature
write failure. Correcting the fixture and asserting the reached mutation exposed
a real metadata-only postcheck false green. The final implementation rehashes both
files, with reached same-inode archive/library mutation regressions. Retain all
first-red receipts; do not count the premature refusal as mutation coverage.

## Remaining operational prerequisites

Authenticated policy/pin provisioning, protected actual YAML/render snapshots and
actual application/plugin/Compose schema validation; source-to-build provenance;
actual candidate/rollback image availability; persistent supervisor/worker and
original outcome reconciliation; complete boot/internal-restart/start/writer/
pending-operation fence; executable complete recovery/start oracle; real replay
probe/container/all-source coverage/drain; external alert route; approved disposable
manager/daemon matrix and measured phase caps remain due. This component proves
none of them. No live service/config/credential operation or production acceptance.

REA angle: reuse the existing descriptor/ancestry approval boundary and Python's
standard ZIP reader, with a bounded classic envelope and no extraction, external
unzip command, plugin import or new broad filesystem privilege.
