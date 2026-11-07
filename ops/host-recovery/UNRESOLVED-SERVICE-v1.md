# Executable unresolved supervisor owner — v1

**Runnable conservative source, not an operational recovery package or host start
fence.** `supervise.py` is the first executable owner of the persistent lifecycle.
It deliberately supplies fixed **deny** boundaries for recovery claims and the
result oracle. It cannot dispatch, restore, start, grant a claim, settle an
installation or make a production-acceptance claim. There is no execution flag,
configuration-module import, installer, default host path or service-start command.
The worker CLI remains identity-only.

## Launch and lifetime

The approved manager must invoke trusted package code with Python isolated mode.
Provisioning the interpreter/code, manager command, configuration digest and
numeric owner remains an independent prerequisite. This source does not provision
or authenticate those approvals by discovering matching values next to itself.
All arguments are required:

- `--approval`, `--sha256`, `--uid`, `--gid`: the existing protected launch reader's
  path, independent digest and configuration-owner pins.
- `--endpoint`, `--endpoint-device`, `--endpoint-inode`: the independently approved
  private worker endpoint directory, not a new lock namespace.
- `--alert-endpoint`, `--alert-endpoint-device`, `--alert-endpoint-inode`: a separate
  private directory containing the fixed `alert.sock` socket.
- `--alert-receipts`, `--alert-receipts-device`, `--alert-receipts-inode`: a separate
  private notice directory, never the content, journal or worker endpoint.
- `--alert-route`, `--listener-uid`, `--listener-instance`: the independently pinned
  local route, peer UID and listener instance. No credential is generated/read.
- `--deadline`: the existing absolute local monotonic service deadline; original
  request loading may shorten it, never extend it.
- `--alert-deadline`: a separate explicit absolute limit for local escalation. It
  is shared across persistence, challenge and notice attempts and is never renewed.
  A limit later than the recovery target is only a late unresolved escalation,
  not extra recovery reserve, measured phase allocation or on-time success.

The executable composes `load_launch` with `run_unresolved`, which owns
`LocalCommands` and a nonblocking shutdown pipe. `run_supervisor` acquires the
existing installation-directory lock before manager bootstrap. Manager/input or
fixed-fence refusal enters its passive unresolved hold and attempts local alert
transport. No worker claim or recovery follows. The lock stays held until explicit
SIGTERM/SIGINT, even after failed alert delivery. It does not poll/retry the manager,
rechallenge a failed/replaced listener or renew a deadline in that hold.

Signal handling writes to the nonblocking pipe; a full pipe already requests
shutdown. The same descriptor cancels manager-helper output waits, pidfd-based
exit waits after stdout EOF, and local alert challenge/notice waits. A canceled
alert attempt refuses immediately rather than adding blocking escalation during
shutdown. Blocking filesystem operations remain subject to the documented kernel
I/O limitation; pipe readiness cannot interrupt uninterruptible storage.
Previous handlers are restored before the descriptors close, and borrowed
cancellation descriptors are detached from transports before reuse. The command
owner also performs nonblocking SIGCHLD reaping throughout passive hold, using
only its retained Popen objects, never waitpid(-1). A stable pending-list identity
and a post-registration reap close the exit-before-registration race. It remains
alive until CLI process exit; helper cleanup is not daemon/cgroup quiescence.
There is no stdout/status-consumer
I/O in the service runner. Exit **3** means shutdown unresolved, never healthy or
completed. Exit **1** means input/lifecycle unavailable; exit **2** means invalid
arguments. Refusals do not print private arguments, paths or exception text.

The existing limitations of `service.run_supervisor` still apply: an untrusted or
unreadable launch file cannot identify a trusted lock owner; invalid/expired
initial deadlines refuse before lifecycle entry. A restarted owner cannot adopt an
old invocation, grant an expired/cross-boot continuation or clear a durable intent.
SIGKILL releases this process's kernel lock but leaves the original journal. Only
an independently enforced host fence could block daemon-internal restart, boot
paths and noncooperating writers after process loss; **this runner is not it**.

## Local notices and honest receipts

`ServiceAlerts` validates fixed secret-free notices and writes a digest-named
private file using the existing staged content-fsync/rename/directory-fsync/readback
primitive. Existing destinations or deterministic stages are never overwritten or
removed, including visible bytes after a failed fsync. Such evidence requires
explicit reconciliation; presence is not a successful persistence receipt.

Transport is attempted independently through `notify`, including after EIO/ENOSPC
or protected-receipt-directory failure. Before its first notice the client performs
one real challenge and compares the response to the externally pinned listener
instance. Missing, wrong or replaced listeners refuse; no automatic rechallenge,
replacement-instance adoption or ambiguous notice retry is allowed. Each distinct
notice is attempted at most once by this owner. Final directory checks and the
shared absolute alert limit must succeed before counting an acknowledgment,
including the additional ancestry validation during directory-context exit. Late
completion cannot increment either persistence or volatile-admission success.

The returned API summary separates successful receipt writes, attempted transports
and confirmed **volatile local inbox admissions**. Durable local notice files do
not prove the independent service received them; inbox admission does not prove
external delivery or human acknowledgment. Both external/human fields remain
false. The CLI deliberately emits no status record. Neither this runner nor the
existing local listener implements an external sink or durable inbox service.

## Verification boundaries

The new tests execute the actual isolated CLI on synthetic owned inputs. Its
configured synthetic manager command is unavailable: that is an intentional
manager-failure/hold path, not successful systemd identity or service recovery.
Actual flock, SIGTERM/SIGKILL, pipe cancellation, protected notice files and Unix
challenge/notice IPC are exercised. Storage tests assert all twelve reached
EIO/ENOSPC combinations at create/write/file-fsync/rename/directory-fsync/readback,
then require actual local transport admission despite persistence failure.
Reached earlier-source regressions cover a stalled alert challenge ignoring
SIGTERM, both late directory-context completions returning success, and a retained
exited helper not reaped during synthetic service hold. Final tests also reach
manager-helper stdout and post-EOF pidfd cancellation with actual local signals.
These are local lifecycle observations, not descendant/container quiescence.
No host unit is installed or started; no Docker/production/management endpoint,
auth/config/backup or producer library is contacted/read/executed.

The fixture tests do not prove executable host recovery, complete fencing,
restoration/start/readiness oracles, measured operating caps, external notification,
continuous downtime or genuine ingress/RPC/producer/container/source-drain
acceptance. Operational supervisor/worker authority, authenticated provisioning,
boot/internal-restart/start/writer/pending-operation fencing, settlement and
continuations and the approved disposable full-system matrix remain due.
