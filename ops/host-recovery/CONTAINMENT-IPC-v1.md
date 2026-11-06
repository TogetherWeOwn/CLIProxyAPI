# Connected containment submissions v1

`host_recovery/containment_ipc.py` joins the original-supervisor peer/installation
lock checks, fixed mask/cancel/reload/stop sequences and broker operation journal.
It is an explicit embedding interface, **not an installed privileged service or
complete recovery package**. No CLI or service entrypoint enables it. The existing
observation-only server, unresolved supervisor and identity-only worker retain
their denies. Authenticated provisioning and all operational release gates remain.

## Fixed boundary

A trusted broker supplies an unused `MaskedForwardStop` or `MaskedRuntimeStop`,
its original journal/epoch and the same `SupervisorPeerAuthority`. The sequence's
manager session must independently hold that same authority: its internal waits
and calls recheck the actual live kernel peer, original flock, manager invocation
and protected original inputs, not merely a callback supplied by the packet.
The broker still owns socket provisioning, its own identity, approvals, original
lock observation and the manager session's lifetime. Typed constructors and
matching hashes do not authenticate provisioning.

Only `contain_forward` (sequence 1) and `cold_quiesce_runtime` (sequence 2) are
supported. The latter requires the original forward submission's durable return;
that return proves sequencing, **not forward quiescence or drain**. Every other
method, unknown field, target mismatch, epoch mismatch or changed deadline refuses
before pending publication. There is no per-packet unit, filesystem path, signal,
executable, environment, API request, import or effect callback.

A `host-recovery-containment-request-v1` packet contains exactly:

- `schema`, one fixed `method`, independently selected `target_sha256`;
- original `binding_sha256`, original `epoch_sha256`;
- fresh 64-hex `nonce` and the preconstructed manager session's original `deadline`.

The same non-reconnecting Unix seqpacket session authenticates connection and
message credentials. The client independently observes the root broker's exact
manager identity before sending, after the reply and after ACK. Neither a socket
UID nor a receipt hash suffices. No reconnect, response retry, new epoch, shortened-
then-expanded deadline or cross-boot allowance is provided.

## Publication and lifetime

Under the journal's existing internal mutex (not a second installation flock):

1. Revalidate original authority and strict operation order. Receive only within
   the already fixed manager deadline; an enclosing transport deadline cannot
   expand it.
2. Persist/read back the exact original pending operation before any mask, manager
   or recursive kernel effect. Dispatch the fixed sequence once.
3. Require its exact operation/target, matching stop completions, inactive masks
   and literal deny flags. Runtime submission additionally requires the original
   captured pidfds dead and the exact runtime domain explicitly empty.
4. Publish a separate outer `returned` record, always `pending_drained=false`.
   Recheck original peer/lock, fixed job absence, inactive effective projections,
   execution timestamps and, for runtime, kernel emptiness/process death after
   return durability. A return-file presence or an earlier observation is not a
   substitute for these checks.
5. Send the exact digest-linked response. Check the matching peer ACK and repeat
   the completed read-only observations. Retain runtime witness descriptors through
   these barriers, then close them on every exit. Embedders using authority-bound
   sequences directly must close them too; no witness can be reconstructed from
   a prior receipt after process loss.

The response summarizes only fixed submission observations and digests. It never
sets manager retirement, activation exclusion, cgroup quiescence proof, pending
drain, complete fence, recovery execution, service start, settlement or production
acceptance to true. An ACK is transport, not terminal settlement.

Malformed requests, lost replies/ACK, changed peers/inputs/units, failed storage,
expired clocks and partial effects permanently close the exchange/journal. Saved
pending/returned bytes remain for reconciliation. Even if the peer saw a response
prefix, it cannot replay an effect, retire the installation or obtain authority
for another phase. The server does not acquire/transfer the installation lock,
clear the active intent or automatically advance to a runtime relaunch.

## Verification and remaining integration

The new connected tests use real original lock-owning subprocesses, kernel
seqpacket credentials/pidfds and private journal/mask files. Manager, cgroup,
privileged broker identity and runtime boundaries remain **scripted**. Tests cover
pending storage hooks, return directory-fsync uncertainty, live-lock loss while a
manager reply waits, original-input drift, stale/malformed packets, reactivation
and repopulation after return, response/ACK loss and witness lifetime. They are
unverified until the exact-head GitHub Actions run completes; no local suite or
CI mirror is required or allowed.

Installed broker/observer/runtime anchors, actual-execution launch exclusion,
all-writer/job coverage, cold/quarantine persisted-policy/registration/drain,
independent stopped-baseline/readiness/result verification, operational runners,
reboot/expired continuation, genuine replay source completeness and the full
fault/timing/package matrix remain required. This interface alone closes none of
those gates and invents no measured phase caps or production downtime result.
