# Calling-manager identity broker composition v1

**Source subset only. Not an installed persistent service, authenticated privilege
broker, complete host fence, recovery execution/outcome oracle or production
acceptance.** No service is installed or started by its tests. No credential,
permission, live configuration or release pin changes are provided.

## Same-owner dispatch and result composition

`host_recovery/broker.py:dispatch_claim` adds an opt-in enqueue-to-result path
inside an **already retained** `recovery_owner` or equivalent protected installation
session. It does not reacquire the lock or close the borrowed supervisor. The
caller must keep the same installation lock through the entire call and after its
return while the installation remains unresolved.

- Require an independently approved same-UID/GID private endpoint, exact
  `RecoveryJobBinding` for the shortened original plan, explicit manager executable
  and independent result oracle. This path cannot obtain approval from a current
  manager row, a journal digest or a worker's result.
- Bind/listen on `claim-<request-digest>.sock` **before enqueue**. Existing endpoints
  refuse; they are never unlinked or replaced. Endpoint ancestry is revalidated
  around each dispatch authorization and worker observation.
- Use the same supervisor's durable request and ordered observe → enqueue →
  acknowledge lease through `SystemdRecoveryDispatch`. An explicit dispatcher
  cannot fabricate an acknowledgment without completing all three lease phases.
  The legacy injected-manager interface remains a trusted component-test boundary.
- Receive the original worker's kernel-peer claim and result on that listener,
  persist/read back both, then require the existing fresh independent result
  observation. Final records, owner/fence, deadline and endpoint validation must
  succeed before returning `recovery_result_observed_unsettled`.
- A lost enqueue reply, failed persistence, missing/dead worker, changed owner or
  endpoint, expired/cross-boot clock or failed oracle closes the listener, retains
  ambiguous socket/journal evidence and escalates without retry. Independent alert
  transport is attempted even when alert-receipt persistence fails.

This starts **only the pinned recovery worker unit**, not an old/candidate service.
The worker's identity claim still grants no restoration/start authority. A result
acknowledgment does not settle the installation or authorize new admission. The
caller supplies authentic installation/package/manager/fence authority; this
function is not an installed persistent entrypoint, approved provisioning,
recovery executor, complete host fence or complete independent result oracle.
The existing `serve_claim` path below remains observation-only/no-enqueue.

Tests join the real request journal, flock, dispatch state machine, strict manager
parser and separate-process seqpacket/pidfd/result exchange. A synchronized fast
worker connects before the scripted enqueue reply. Worker SIGKILL and reached
EIO/ENOSPC faults across request/enqueue/claim/result/observation persistence retain
the latch and attempt independent transport. **Manager, cgroup, complete-fence,
recovery evidence and readiness replies are scripted.** No installed systemd,
Docker, reboot, full recovery, external alert, measured phase cap or availability
acceptance is established by this composition.

## Existing-request composition and trust

`host_recovery/broker.py:serve_claim` connects the existing calling-supervisor
bootstrap, approved content/original-request loading, installation-directory lock,
request-instance manager observation and one-shot worker identity IPC. Previously
these components could be composed only by external callers/tests. The new path
requires an explicit `LaunchApproval`, independently approved private endpoint
directory, caller deadline, complete-fence callback and independent alert callbacks.
It has no CLI, live-path defaults or enqueue/restore/start operation.

The launch pins must still come from independently authenticated provisioning.
A matching digest, typed object or scripted manager row proves correspondence,
not who approved it. The existing protected configuration loader is available to
a future trusted entrypoint; accepting a constructor object here does not replace
that installation/launch boundary. Trusted interpreter, helper and manager transport
provisioning, operational external alerts and complete fence enforcement remain due.

## Original ownership and lock lifetime

1. Bootstrap the actual calling MainPID using pinned supervisor unit/command,
   numeric UID/GID, manager invocation, boot and kernel cgroup observations.
2. Acquire the **same existing installation-directory flock** through the approved
   installation handles. Capture/revalidate pinned content and original intent,
   arm and saved request under it. The caller must be that request's supervisor
   invocation; a replacement supervisor cannot adopt it.
3. Borrow the journal descriptor for observation-only `RecoverySupervisor` state.
   No second lock is acquired and no descriptor is transferred to the worker.
   Missing/staged/ambiguous state or any existing worker claim refuses before the
   listening socket is created. No new request, enqueue or redispatch occurs.
4. Open the independently approved private endpoint directory. It must have the
   same numeric owner as the supervisor and be outside content/journal roots.
   The only socket basename is `claim-<request-digest>.sock`; a retained socket is
   never unlinked/replaced. This transport currently supports same-UID workers.
5. Serve exactly one connection. Existing kernel connection/message credentials,
   connection-bound pidfd and pinned manager MainPID/cgroup/invocation checks apply.
   Worker unit numeric UID/GID must explicitly agree with the endpoint/supervisor
   owner, even if a different configuration has a matching static digest.
6. Revalidate original approved content/request, supervisor identity and endpoint
   ancestry around the independently supplied complete-fence callback and claim
   observations. Persist/read back the original worker claim once before replying.
7. Close the listener and revoke the borrowed supervisor reference before releasing
   the lock. Revalidate inputs and directory ancestry through context exit before
   returning a public receipt. Socket/claim state is retained on success or failure.

A wrong nonce/peer, pending/lost/replacement worker, changed content/request/path,
missing fence acknowledgment, expired original reserve or storage uncertainty
cannot produce a successful broker return. Bootstrap and final-context failures
also attempt independent transport, even if local alert-receipt persistence fails.
The local IPC alert receipt remains volatile admission only, not external delivery.

## Receipt limits and ambiguous replies

`identity_reply_sent_only` reports `claim_recorded` and `claim_reply_sent`. The
latter means the bounded local send completed, **not peer receipt/acceptance**.
It does not publish peer PIDs, nonces, command strings, file paths or source bytes.
Complete-fence-proven, restoration/execution/start, terminal-outcome-verified,
recovery-completed, peer-acknowledgment and production-acceptance flags remain false.

A failure after the claim/reply can leave visible claim bytes and an unresolved
peer. No return/exception can retract bytes already sent, so the claim itself
continues granting no restoration/start authority. No second claim, deletion,
worker restart, fence retirement or outcome settlement is a supported retry path.
Historical claim observation remains separate and cannot revive a peer.

All operations use the minimum of the caller deadline and original saved request
deadline. No new reserve, boot continuation or measured phase allocation is added.
Injected callbacks must enforce their own deadline; Python cannot interrupt stuck
filesystem/manager/fence I/O. Test-suite runtime is not recovery time or downtime.

## Test evidence and remaining work

Tests compose actual owned filesystem reads/flock, Linux seqpacket/credentials/
pidfd and the real manager parsers with **scripted manager/cgroup/fence boundaries**.
A separate broker process is killed after durable claim persistence and before
reply; its lock excludes contenders until exit, the worker refuses, and reopened
composition cannot replay the saved claim. This is process/lock/persistence
component evidence, not installed-systemd/daemon, reboot or full recovery evidence.

The runnable persistent owner and recovery worker, complete boot/internal-restart/
start/writer/pending-operation fence, authenticated provisioning, recovery outcome
reconciliation, restoration/semantic pre-start oracle, operational alert route and
full approved disposable package matrix remain required. The broker does not make
an otherwise incomplete adapter operational.
