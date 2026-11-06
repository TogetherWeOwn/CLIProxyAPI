# Original worker result reconciliation — v1 component contract

**Source component, not an installed recovery supervisor, executable recovery
worker, complete start fence, independent recovery oracle or settlement protocol.**
No service installation, live endpoint, credential or privilege is introduced.
Existing release identities and operating approval gates do not change.

## Separate facts, separate authority

1. A durable enqueue receipt is not a worker identity.
2. A worker identity claim is not recovery authority or a recovery outcome.
3. A worker result report is not independent evidence verification.
4. Fresh independent verification is not installation settlement or a new start
   grant. The original durable intent and installation lock remain in place.

`RecoverySupervisor.record_worker_result` accepts at most one report from the
original claimed process while the original supervisor owns the installation
lock. The broker supplies kernel connection/message credentials and a live
`SO_PEERPIDFD`; the pinned manager must still observe the same running MainPID,
invocation and cgroup. The saved claim, original request/intent/arm and complete
fence boundary are rechecked around persistence. No numeric-PID fallback exists.

The exact six-field `host-recovery-worker-result-v1` envelope contains:

- `schema`;
- `request_id`, the existing original request digest;
- `intent_sha256`, the original immutable intent digest;
- `claim_sha256`, the exact durable claim digest, including worker identity/nonce;
- `outcome`: only `baseline_restored` or `recovery_unresolved`;
- `evidence_sha256`: a restricted raw-evidence digest, not a path or message.

Unknown fields, coercions, candidate-success reports and unbound digests refuse.
The digest alone authenticates neither approval nor evidence. `reconcile-result.json`
is written/read back before any result acknowledgment. An ambiguous write exhausts
the operation even when final bytes are visible; staging state is never cleaned
or treated as a healthy prefix. Failure transport is attempted despite receipt
write failure, retaining the existing volatile local alert-admission semantics.

## Fresh independent observation

`observe_result(observer=..., oracle=..., deadline=...)` is one-shot per supervisor
invocation. It validates the original saved report/claim/request and binds both
manager observations to the exact claimed worker invocation. An inactive worker
is only evidence of inactivity: it can be accepted for observation only with the
same retained invocation and a fresh independent oracle. Missing invocation,
replacement, pending job, lost manager, changed records or fence uncertainty refuse.

The separately authenticated oracle receives copies of the immutable intent and
report plus the shortened original inclusive deadline. It must independently:

- authenticate source/artifact/role/policy and referenced raw evidence;
- inspect the complete original baseline bytes/owners/modes/all roots;
- verify old object/image identity, original replay, absence of the new plugin;
- establish writer quiescence, retained start fencing and old readiness.

Its strict `host-recovery-result-oracle-v1` receipt binds the exact report/evidence,
baseline and old object with explicit true verification flags. Worker booleans,
exit status, a matching digest or a successful dictionary comparison cannot
implement this boundary. These tests use a **scripted oracle**, not those actual
host checks. No recovery execution or startup can be derived from the report.

After fresh checks, `reconcile-result-observed.json` durably binds the report,
independent receipt, observing supervisor and same-boot observation time. Original
records and saved observations are rechecked after external callbacks/persistence.
Changing any observed receipt in place refuses. All waits, provider execution,
manager/oracle work and persistence share the original request deadline; there is
no new allowance. Expired or cross-boot journals still require the separately
reviewed continuation protocol; no new clock origin is manufactured.

## Protected raw worker evidence

`result_report.WorkerEvidenceOracle` is an opt-in report-readback composition for
that same `oracle` argument, not an implementation of the current-state oracle.
An independently approved private worker-evidence directory supplies the fixed
request-digest filename; no worker-provided path is opened. Verifier read access
must already exist. Missing permission refuses; this source changes no owner,
mode, ACL or credential.

The reader retains a no-follow, bounded, single-link private regular-file inode,
checks canonical raw bytes against the result's evidence hash, and checks exact
intent/request/claim linkage and the worker-report schema. Authorizing flags,
contradictory success/error/alert fields, partial staging and unsupported shapes
refuse. A disk alert-receipt failure remains distinct from transport admission.
Worker stopped-state and timing fields remain historical assertions, not fresh
oracle inputs or measured/drained/externally delivered proof.

The independently supplied current-state oracle is still mandatory and must
supply every existing fact. The supervisor retains the reader context through its
own observation-record publication, then rechecks the original inode/path/bytes,
live boundary and deadline before marking the result observed. Replacement,
mutation, read errors, changed callbacks, reentrancy or uncertainty poison the
reader. An observation file visible before a failed trailing check is not a
verified result; restart still requires fresh independent verification. Direct
reader calls check only their own call window, not later caller persistence.

New regressions are authored for Actions, **not yet executed**. They include the
actual component worker's output, synthetic supervisor/worker report publication,
read faults, malformed repinned reports and post-publication mutation. Manager,
complete fence and fresh baseline/readiness oracles remain scripted. The runnable
supervisor remains fixed-deny and the worker identity-only. Operational recovery,
reboot/resume, complete fencing, settlement and replay/source-drain are unfinished.

## Process-root baseline observation

`mounted_baseline.open_mounted_baseline` adds an optional read-only observation
for an **externally authenticated live pidfd** bound to the old full container ID.
The approval binds the original intent, object and complete mount-list digest.
Acquiring that authority from a real daemon/manager is not implemented by passing
a guessed PID or a true callback. The existing installation lock and complete
external mount/file/process-writer exclusion must remain held.

Unlike caller-namespace bind-source comparison, this reader opens the target's
kernel procfs root and mount namespace. It traverses each destination with
no-follow directory opens, requires every approved baseline root exactly once,
checks source device/inode correspondence, and rereads full file bytes, metadata
and inventories through those target-root descriptors. A copied empty directory
is not equivalent to the approved source inode. A detached descriptor is not
proof of the process's current path: destinations, namespace and root identities
are freshly reopened and compared at each barrier. Namespace/root descriptors
and the duplicated live pidfd remain retained through the observation window.
No setns, mount, process launch, file repair or second lock occurs.

`WorkerEvidenceOracle(..., mounted_baseline=view)` enters this context before the
mandatory independent current-state oracle and retains it through supervisor
observation-record publication. A failing trailing mounted-file observation
leaves even a visible observation record unverified. Removing a configured view
refuses. The report is rechecked after mounted-observer callbacks as well.

This is bounded **point correspondence**, not continuous or atomic mount/writer
exclusion. Read-only/private flags are approved mapping requirements, not kernel
mount-option enforcement proved by these reads. User-namespace ownership
translation, symlink destinations, file binds, volumes, unapproved/subset/overlap
mappings and inaccessible procfs are unsupported and refuse; there is no caller-
namespace fallback. It does not prove loaded-plugin absence, image provenance,
readiness, start fencing, asynchronous replay drain or installation settlement.
All those independent facts remain mandatory; the operational runner denies are
unchanged. An embedding must not treat the new non-authorizing receipt as the
complete result oracle.

The new tests are authored but **unexecuted**. Self-pidfd/procfs tests use actual
synthetic directories and a synthetic approved mapping, not a running container
or authentication of one. Result-protocol ordering tests script the mounted
observer and the independent oracle; they are not native recovery qualification.

## IPC and broker composition

`WorkerListener.accept_once(..., result_oracle=...)` keeps the same connection and
pidfd after the existing identity reply. It receives and persists one result,
independently observes it, then sends a bounded digest-bound result receipt.
`WorkerClient.claim(..., result_provider=...)` supplies only outcome/evidence digest;
the client binds the envelope to the exact received claim. The provider obtains
any execution authority separately: the identity reply explicitly grants none.

`SystemdWorkerBootstrap.claim` passes this optional provider through with its
connection-bound manager checks before result transmission and after the receipt.
`broker.serve_claim(..., result_oracle=...)` composes it with protected launch/input
loading and the existing installation lock, revalidating records at context exit.
Default identity-only callers retain their old protocol. Both optional sides must
be explicitly configured; no negotiation, inferred capability or retry exists.

A result receipt means only that this supervisor observed and recorded the
report. It has `installation_settled: false` and `start_permission: false`.
Sending a receipt does not prove the worker received it. Peer loss, no report,
unknown/malformed packets, supervisor SIGKILL, oracle refusal, storage faults,
expiry and lost replies leave recovery unresolved rather than downgrade to an
identity-only success. A failure report remains saved and cannot be replaced by
a later healthy report.

## Restart semantics and limits

Observation-only reopen validates saved report/claim/observation structure and
bindings. It never recreates a live peer, reissues the result receipt, redispatches
work or automatically accepts the old observation. A fresh oracle is required,
even when a prior observation receipt is visible. A new valid observation does
not overwrite the original observation timestamp or reset any deadline.

Successful component status is `recovery_result_observed_unsettled`; only
`worker_result_observed` becomes true. `recovery_completed`,
`installation_start_fence_proven`, `installation_settled`, `forward_allowed`,
`start_permission` and `production_acceptance` remain false. The on-disk active
intent is not retired. New admission, archival and fence release remain absent.

Tests include real files/flock, separate-process Linux peer exchange, live worker
loss and supervisor SIGKILL after durable observation before receipt. EIO/ENOSPC
faults explicitly reach each result and observation create/write/file-fsync/rename/
directory-fsync/readback hook. Manager/fence/cgroup/oracle replies are **scripted**;
no installed systemd/daemon recovery, measured operating caps, full-package drain,
external notification or downtime result is claimed. The pinned full-system
supervisor/worker, enforced boot/internal-restart/start/writer/pending-operation
fence, authenticated provisioning and complete independent oracle remain due.

REA angle: reuse the existing Linux peer/pidfd and pinned manager/request/claim
protocol, plus conservative original-intent restart semantics. Do not invent
worker authority from a process exit or add a second lock/rollback owner.
