# Protected worker launch composition v1

**Development source, not an installable persistent recovery service or production
acceptance.** No live operation, unit installation, credential/privilege change,
release-pin replacement or forward admission is provided.

## Entry points and authority

`host_recovery.worker_runtime.run_worker` composes protected original-input loading,
`SystemdWorkerBootstrap`, the original peer connection and optionally
`WorkerRecovery`. It accepts a typed, independently approved `LaunchApproval` and
private endpoint `DirectoryApproval`, plus an explicit absolute monotonic deadline.
No file discovered beside the journal or socket can supply approval. The running
interpreter/package and approval channel remain independently trusted provisioning
prerequisites; validating captured bytes does not authenticate the running code.
Captured content is never imported or executed.

The worker opens approved content/journal/endpoint directory handles without
flocking the journal. The authenticated supervisor must retain the existing
installation-directory lock throughout the exchange. Neither the worker's open
handle nor a successful identity claim proves complete fencing or grants execution.
The worker reads no live default path. Content, journal, endpoint and (for execution)
evidence roots must be separate, non-nested and independently inode/owner pinned.
Same-UID/root hostility and mount-namespace attestation remain outside this reader.

Before connection, around every connection-bound manager/peer observation, at each
recovery lease check and after the final receipt, the worker revalidates protected
ancestry, exact content and original intent/arm/request. The original request digest
validates the initially discovered owner; discovery alone grants nothing. Original
arm, boot and deadline remain mandatory. Caller/phase bounds can shorten, never
extend them. Observed read failures, drift and deadline/boot loss refuse; snapshot
failure poisons the session. Retained validators cannot use descriptors after exit.
These are observations, not a defense against an undetectable cooperating rewrite.

Without execution arguments, the operation exchanges identity only. With execution,
all of `boundary`, private evidence directory, `persist_alert` and `transport_alert`
are mandatory. Partial configuration refuses rather than silently downgrading. The
same protected snapshots bracket the existing revocable peer check. Recovery still
requires independent operational approval, complete host fencing, baseline/start
oracle and bounded alert contracts from [worker execution](WORKER-EXECUTION-v1.md).
A matching dictionary, digest, claim or scripted boundary cannot replace them.
The worker never writes a supervisor journal terminal or settles the installation.
Execution-mode failures before bootstrap or outside the engine still attempt the
independently provided alert transport even if alert-receipt persistence fails.
Identity-only invocation has no configured alert route and claims no notification.

`claim_worker.py` is an actual identity-only process entry point intended for an
independently installed/pinned manager unit. It requires every argument explicitly:
launch file and external SHA256, numeric launch-file UID/GID, endpoint path/device/
inode, and absolute original monotonic deadline. Endpoint ownership comes from the
approved numeric supervisor owner; its required mode is 0700. Use trusted code with
Python isolated mode (`-I`). There is no execution flag, arbitrary helper/module
loader, retry, installation command or live-path default. Missing/malformed arguments
exit 2 with a fixed diagnostic. Unavailable input/identity/output exits 1. A successful
identity-only exchange emits one bounded, secret-free receipt **and exits 3** because
recovery remains unresolved. A partial/broken stdout write is not retried.

The CLI intentionally does not claim to be the operational recovery worker. A
service-level execution entry point still needs independently provisioned real
boundary implementations; adding a flag to accept callback-shaped data would not
satisfy that prerequisite.

## Evidence and limits

New tests cover actual protected input/evidence files, FD cleanup, existing-lock
contention, original budget checks, partial configuration, root/owner/inode drift,
source changes around claim and during restoration, peer loss, retained validators,
and actual isolated CLI argument failures. CLI successful-output behavior is tested
with injected launch/runtime functions, not a real systemd CLI invocation.

Two separate-process tests use the real worker runtime, strict manager parsers,
claim/result Unix-seqpacket/pidfd transport, private evidence persistence and the
supervisor's existing lock. Manager/cgroup/fragment observations, authority,
restoration/start/readiness and the supervisor result oracle are **scripted**.
The healthy case acknowledges an unsettled worker report; the negative asserts an
explicit reached-restoration marker before injected protected-source drift and
refusal, no later scripted start, no evidence/result, and a retained claim. The
first fixture used inconsistent scripted cgroups and refused before recovery; its
initial negative was not restoration fault coverage. Corrected tests assert the
reached boundary. No product-red/fix claim is made for that fixture correction.

Not proved or supplied: persistent supervisor execution/service units, complete
boot/internal-restart/start/writer/pending-operation fence, authenticated operational
provisioning, independent restoration/start oracle, cross-boot/expired continuation,
settlement/new admission, actual daemon/systemd recovery, external notification,
measured phase caps/downtime, ingress/RPC/producer/container/source completeness and
drain, disposable full-system matrix, native review or production acceptance.
