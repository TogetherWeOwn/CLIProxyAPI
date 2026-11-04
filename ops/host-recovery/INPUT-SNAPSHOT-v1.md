# Protected input snapshot v1

**Read-only source/policy capture, not rendering or operational admission.** No
live defaults, config/credential reads, installation or service operations are
provided. All tests use repository-owned synthetic files. The original intent,
installation lock, trusted mapping of real inputs, writer fence and authenticated
approval channel remain caller prerequisites.

## Interface

`host_recovery/input_snapshot.py` provides a callable `ProtectedInputSnapshot` for
`ExactInputGate(snapshot=...)`. Each invocation, including the gate's post-helper
recapture, freshly opens and captures seven independently pinned files:

- Before/after config.
- Before/after Compose source.
- Before/after frozen-rendered Compose.
- One exact delta-policy document.

There is no cached request, previous-success shortcut, filesystem policy discovery,
second installation lock or mutation method. `SnapshotApproval` binds the original
intent SHA256, three distinct `InputPairApproval` objects and a policy file approval.
Each `InputFileApproval` requires an independently approved root
`DirectoryApproval`, literal single-component filename and raw SHA256. The mapping
from these roles to the actual baseline, proposed, installed and frozen-render
objects must come from the trusted installation boundary, not an arbitrary caller
choosing convenient fixture copies. Hashes and data classes alone authenticate
neither that mapping nor the policy.

The policy file is a restricted JSON object with exactly these keys:

```json
{
  "schema": "host-recovery-input-policy-v1",
  "config": [],
  "compose_source": [],
  "frozen_rendered_compose": []
}
```

Each role's array contains the exact `path`, `before`, `after` semantic-delta
objects described in [the YAML guard protocol](INPUT-GUARD-v1.md). Empty arrays
mean no changes, not omitted checks. Duplicate JSON keys, unknown/missing roles,
wrong envelope types and more than 256 changes per role refuse during capture.
The Go helper, not a second Python YAML parser, validates the individual change
objects, literal paths, semantic hashes and document contents. Successful capture
alone is not a semantic validation result.

Captured bytes become canonical base64 pairs with their externally approved raw
pins and captured policy arrays in `host-recovery-input-request-v1` format.
`InputApproval.request_sha256` still independently binds the **whole serialized
request** before helper execution. Do not derive or update that approval from the
capture under test; changing a policy file and its local hash cannot approve a new
request. The whole-request digest does not replace source, policy, helper or
original-intent pins.

## File and time boundaries

Protected acquisition reuses the existing no-follow ancestry/root-identity checks.
Roots must have private 0500/0700 modes and approved numeric UID/GID, device and
inode. Sticky/group/world-writable ancestors refuse; no permissions are relaxed.
Files must be private 0400/0600 regular single-link files on the approved root's
device without unsupported metadata. Public/readable config layouts, links,
special files and cross-device objects are unsupported, not silently normalized.
The seven file objects must be distinct even when their contents happen to match.

`host_recovery/protected_file.py` factors the existing artifact reader into one
shared retained-descriptor implementation; the archive/library guard retains its
original format and owner/mode requirements. Capture opens every input before
reading, bounds each YAML document to 4 MiB and policy to 256 KiB, then constructs
the request within the existing 36 MiB protocol cap. It rehashes **every retained
descriptor** after serialization, validates every file path and root again and
closes all owned descriptors on success or failure. Metadata equality alone never
stands in for that second byte check. The gate separately recaptures after the
helper reply, so helper completion cannot preserve a green result after observed
source drift.

The required strict-True `check()` callback and clock checks run before/throughout/
after reads, serialization and cleanup. They must confirm the calling owner,
existing installation lock and complete cooperating-writer exclusion. Every
operation consumes the caller's original inclusive deadline; no capture, rehash
or post-helper allowance is added. Fixed refusal codes do not include filenames,
source values, policy content, pins, parser diagnostics or underlying errors.

This is not an atomic snapshot against hostile root/same-UID writers or a mount-
namespace attestation. Cooperative exclusion is necessary; repeated observations
cannot prove absence of an intervening hostile mutation. Python checks cannot
cancel uninterruptible kernel I/O or enforce a hard-real-time bound. Pinned
interpreter/package identity and manager containment remain required.

## Composition and evidence

The adapter can be supplied to the existing `ExactInputGate` and
`GuardedBoundary`. Underlying listener/preflight/stopped checks, the optional
archive/library gate and the separate baseline/start oracle remain necessary.
Before-arm capture failure reaches no intent/stop. Stopped failure skips forward
mutation/candidate start and leaves recovery to the existing coordinator path;
invalid candidate input must not block baseline recovery. Receipt-persistence
failure still attempts the independent test transport.

Tests exercise actual private files/ancestry, retained descriptors, descriptor
cleanup, all seven raw pins, original intent binding, policy envelope, distinct
objects, mode/owner/root mismatches, links/FIFO, byte/serialization bounds,
replacement and reached same-inode mutation, read/second-read faults, strict
boundary revocation and deadline/clock refusal. The same-inode regression suppresses
signature differences deliberately to prove the byte check; it is not a measured
coarse-timestamp-filesystem drill. Actual built-helper/coordinator tests cover both
barriers, post-helper recapture, self-approval refusal and semantic rejection even
with matching raw pins. Manager/fence/schema/oracle/alert boundaries remain
**scripted**; no installed-systemd/daemon, external notification, real producer,
full recovery, measured phase cap or downtime acceptance is claimed.

## Still required

- Authenticated approval/policy/pin and actual installation-role provisioning.
- A pinned real renderer with protected interpolation inputs, tool/version binding
  and verification that the frozen bytes correspond to those exact inputs. This
  adapter only reads frozen files; it does not perform or attest that rendering.
- Actual config, approved plugin and Compose schema validation; image availability;
  delivered producer-archive compatibility and the complete baseline/image/replay/
  no-plugin pre-start oracle.
- Runnable persistent supervisor/worker, request/claim/outcome reconciliation and
  independently enforced boot/internal-restart/start/writer/pending-operation fence.
- Source-bound genuine probe/producer/container/source coverage/drain integration,
  external alert route and approved full-system disposable drills with measured
  inclusive phase caps, availability samples and truthful censoring.

No installation, live probe, privilege/credential/configuration change, release-pin
replacement or production operation is authorized by this capture interface.
