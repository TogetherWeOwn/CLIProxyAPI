# Persistent original-request supervisor lifecycle — v1

**Embedding source, not an installable operational recovery package.** No unit is
installed or started, no daemon is contacted by these tests, and no credential,
privilege, policy approval or release pin is provisioned. The existing
`claim_worker.py` CLI remains identity-only. There is no CLI flag or configuration
module import that turns arbitrary callbacks into approved host authority.
`supervise.py` now supplies an executable **unresolved-only** owner with fixed deny
boundaries, signal cancellation and actual local alert wiring; see
[its launch contract and limits](UNRESOLVED-SERVICE-v1.md). It is not an operational
recovery/start grant, installer or complete host fence.

## Composed entrypoint

`host_recovery.service.run_supervisor` composes the protected installation,
calling-manager identity, original input loader and broker claim/result path.
The caller explicitly supplies `LaunchApproval`, a separate approved private
endpoint, the original absolute deadline, the complete fence, independent result
oracle, both alert callbacks, a caller-owned command transport and cancellation
read descriptor. All boundaries must already be independently provisioned.

1. Acquire the existing installation-directory lock **before** manager bootstrap.
   The calling session borrows that handle; it does not open another lock.
2. Validate the calling MainPID/unit/invocation and original pinned inputs. A
   previously durable request is required. An earlier supervisor invocation,
   expired/cross-boot request, ambiguous staged state or prior worker claim is not
   silently adopted, retried or redispatched.
3. Serve one original worker claim and result over the existing private endpoint.
   Keep the same lock through peer/manager checks, durable result-before-reply and
   fresh independent observation. The full fence and oracle are still external
   contracts, not implementations supplied by this lifecycle.
4. Close the endpoint and revoke the borrowed session, then retain the same lock
   in a passive unresolved hold. This also happens after bootstrap or exchange
   failure once the installation was acquired. The service performs no recovery,
   validation, persistence or operational retry in that hold.
5. Share one timer through input loading, initial validation, exchange and hold,
   so the loaded original deadline survives even a pre-yield validation failure.
   Check it before honoring shutdown readiness; simultaneous shutdown and expiry
   cannot suppress escalation. Retain one alarm at that deadline. Expiration attempts a
   distinct `supervisor-expired-continuation-required` notice once, including when
   receipt persistence fails. Clock uncertainty instead reports
   `supervisor-clock-continuation-required`; it is not measured expiry. This is
   escalation after a missed target, not an extra recovery allowance or an
   on-time success. Alert callbacks must themselves be independently bounded;
   no external delivery or measured cap is proved here.
6. Shutdown releases this process's kernel lock but **never clears the durable
   intent**. The returned `shutdown_unresolved` status grants no settlement,
   restoration, start, new admission or production acceptance. A positive
   `worker_result_observed` is only an exchange observation. The hold deadline
   field is local hold accounting, not complete phase/timing acceptance; null
   means clock uncertainty.

Invalid installation identity or inability to acquire/retain its approved handle
raises, rather than returning a normal shutdown receipt. Protected-context exit
validation remains required. A lock only excludes cooperating lock users; it does
not fence Docker restarts, host writers, other start paths or hostile root/same-UID
code. A retained file descriptor does not establish pathname continuity forever.

## Shutdown and process ownership

The service owner supplies a read pipe/socket that stays open and unreused for
the entire call. Readability or EOF requests shutdown. The exchange never
consumes it. Selector-based cancellation and passive hold support valid descriptors
above `FD_SETSIZE`. A signal-aware owner can write a byte to it; this wakes both an idle
listener and connected-peer I/O waits. Cancellation revokes the server's peer
lease; endpoint closure revokes worker execution even if the supervisor process
survives. Cancellation is not proof that helpers, cgroups or daemon jobs stopped.

The owner must retain `LocalCommands` and reap pending helpers without adding an
unmetered recovery wait. The persistent manager and independently enforced
boot/start/writer/pending-operation fence must keep authority after service
shutdown, SIGKILL, manager loss and reboot. This entrypoint does not implement
that fence, restart reconciliation, continuations, settlement or unit policy.
No automatic retry loop or new relative recovery budget is introduced.

## Evidence boundaries

The new synthetic suite exercises protected files, actual `flock`, separate
process SIGTERM/SIGINT/SIGKILL, pipe cancellation and kernel-peer sockets. Manager,
cgroup, fence, recovery operations, result oracle and external alert delivery
remain **scripted**. Separate-process result/hold tests use the existing scripted
broker listener; they are not a new full-system worker recovery drill. Reached
result-fsync EIO and alert-persistence ENOSPC faults are asserted explicitly.
Deterministic clock changes exercise the original deadline alarm and uncertain
clock; no sleeps or measured operational phase allocations are used.

Still required: authenticated installation/policy/role/artifact provisioning,
runnable operational supervisor/worker installation, complete independently
enforced boot/internal-restart/start/writer/pending-operation fence, actual recovery
and complete independent restoration/start oracle, cross-boot/expired continuation,
settlement, genuine ingress/RPC/producer/container/source completeness/drain, and
the approved disposable full-system fault/availability matrix. This lifecycle
alone cannot satisfy those gates or activate integrated acceptance reviews.
