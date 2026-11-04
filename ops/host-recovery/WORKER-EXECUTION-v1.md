# Original-request worker execution — development composition

**Not an installed service, complete host fence, authenticated provisioning,
operational start oracle, measured recovery budget, or recovery acceptance.** The
persistent supervisor/separate-worker service entrypoints remain unfinished. This
composition connects the existing broker's original claim/result path to actual
filesystem recovery in component tests; it does not make the package installable.

## Authority and ownership

`SystemdWorkerBootstrap.claim(..., recovery_provider=provider)` passes the exact
identity-only claim, original inclusive deadline and a live `check(deadline=...)`
callback to `WorkerRecovery`. The ordinary `result_provider` path remains for
report-only callers; the two paths are mutually exclusive. Execution requires an
independent manager identity verifier. Kernel connection/message credentials,
connection-bound pidfd and repeated manager/worker observations still apply.

The claim continues to say `restoration_permission=false` and
`start_permission=false`. It never becomes an execution grant. A separately
provisioned boundary's `authorize_worker_recovery(intent, request, claim,
deadline=..., check=...)` must authenticate this exact request/claim and the
original package, policy and baseline, verify the independent alert prerequisite
and enforce the complete host fence. Approval digests and a scripted True reply
are not implementations of that authority. No default boundary is supplied.

The supervisor retains the **same installation lock** throughout. The worker
never acquires a replacement lock, receives the supervisor journal fd, writes a
journal terminal, clears the latch, redispatches or admits forward work.

## Recovery sequence and live checks

The worker and existing coordinator share `recover_baseline` rather than maintain
two independent rollback algorithms:

1. Fence every start, writer and pending daemon operation.
2. Quiesce and independently verify all mutators and owned daemon objects.
3. Validate the complete original recovery inputs; restore the complete write set.
4. Obtain the strict independent stopped-baseline receipt.
5. Delegate old start only after that verification; verify old readiness.

Each boundary method additionally receives `check(deadline=...)`. It **must** call
that callback immediately before internal mutations/start, including within long
restoration operations, and must enforce its deadline while running. The wrapper
checks before and after each method; that alone cannot stop an uninterruptible
operation or repair an uncooperative/compromised boundary.

The original request's arm and conservative failure lower bound initialize the
existing budget meter. No new reserve is created. A callback cannot enlarge its
phase deadline to the original request deadline, or survive its own method's
return. Any failed check permanently revokes execution, even if the boundary
catches the exception. The outer client lease is also invalid after provider
return, failure or manager/peer loss. Cross-boot/expired work refuses; separately
identified continuation and startup reconciliation remain due.

## Reports, persistence and alerts

`WorkerEvidence` requires an independently approved private directory, separate
from the installation journal and installed content. It writes one fixed
request-digest filename using file-fsync → rename → directory-fsync → readback,
then revalidates the directory/peer and bytes. Existing final/staged files are
ambiguous evidence and are never overwritten or deleted. Any failed/ambiguous
write exhausts the object and prevents a result, even if final bytes are visible.

The hash-bound `host-recovery-worker-evidence-v1` report binds the original
request/intent/claim, worker outcome, stopped receipt, alert-attempt status and raw
phase events. `worker_report_only=true`; `start_permission`,
`recovery_completed` and `installation_settled` remain false. Timing records are
component events, not a complete external availability trace or a measured phase
allocation; the final evidence-file write necessarily follows its captured input.
The supervisor must authenticate the referenced evidence, independently inspect
the actual baseline/readiness and revalidate its own original records before
observing a result. Neither worker success nor evidence-file presence settles the
installation or authorizes a fresh start/admission.

Independent alert transport is attempted even after peer, authority, clock or disk
failure, without depending on evidence persistence. The alert reports the still
unsettled installation as `recovery_unresolved`, not a prematurely durable recovery
success. Failed delivery or exhausted budgets cannot yield a success report. The
transport must implement its existing independently bounded contract; this code
does not supply an external sink, alternate route or human acknowledgment.

## Evidence boundaries

Tests use actual files/restoration, protected evidence reads/writes, separate
worker IPC/pidfd, retained installation flock, worker SIGKILL before scripted start
and reached EIO/ENOSPC hooks. Manager, execution approval, complete fence, daemon
start/readiness and semantic oracle remain **scripted boundaries**. There is no
real systemd/Docker/full-package drill or measured downtime here. Two new-code
lease regressions retain exact pre-fix source/tests and reached red/green receipts;
early fixture refusals are not counted as those regressions or disk-fault coverage.

Remaining work includes runnable persistent services, authenticated provisioning,
complete boot/internal-restart/start/writer/pending-operation fencing, operational
recovery/oracles, settlement/continuations and genuine ingress/RPC/producer/
container/all-source/drain evidence in the approved disposable matrix. No host
install, live probe, producer execution, credential/privilege/configuration or
release-pin change is authorized by this development composition.
