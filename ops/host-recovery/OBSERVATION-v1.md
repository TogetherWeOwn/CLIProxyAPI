# Lock-retaining read-only observation

**Source component, not an installed or operational recovery supervisor.**
`observe.py` is a bounded manager-launched observation entrypoint. It follows an
already-dispatched recovery request, using the existing launch approval and actual
read-only systemd adapters. It cannot dispatch, claim a worker, fence daemon
operations, restore files, start a service, settle an outcome or clear an intent.
It never substitutes a successful callback for the missing complete host fence.
No installation, host service operation, privilege change or live probe is enabled
by this document.

## Launch and lifetime

Like `status.py`, the process must itself be the independently pinned supervisor
MainPID, numeric UID/GID, cgroup, boot and invocation. It is not an attaching client
and cannot run concurrently with an existing installation lock owner. Every launch
argument is explicit: `--approval`, `--sha256`, `--uid`, `--gid`, `--deadline`,
`--interval` and `--max-observations`. The existing
[launch trust boundary](LOADING-v1.md#pinned-launch-configuration-and-read-only-status)
is unchanged: approval-file integrity is not authenticated provisioning.

One private calling-session context bootstraps that identity and opens the protected
content and journal roots. It takes the **same journal-directory inode flock** used
by status and the recovery-owner primitive. It captures the approved content,
original intent, arm and request, retains the lock throughout all ticks and waits,
and closes every borrowed handle on exit. There is no second lock, lock handoff,
new budget, forward owner or Bash recovery authority.

One monotonic timer retains clock continuity from bootstrap through initial reads,
all subsequent manager queries and final context exit. The original request may
shorten the caller deadline, never extend it. Cross-boot, expired and mismatched
supervisor-invocation requests refuse. This path **cannot adopt an older request on
supervisor restart** or execute a reboot continuation. It must not be represented as
that recovery protocol.

## Observation and refusal

Each tick:

1. Reobserve the same live pinned supervisor, reload both approved snapshots under
   the retained lock, and revalidate protected ancestry. Content or original request
   replacement is not adopted, even if it appears self-consistent.
2. Query only the explicitly pinned request-digest-named recovery unit, using fixed
   `systemctl show` argv and the original inclusive deadline. The actual parser
   validates fragment/command/sandbox, boot, job and invocation identity. No start,
   restart, reset-failed or enqueue command exists on this path.
3. Bracket another observation with supervisor/input validation. The two job
   observations must agree; transitional uncertainty refuses rather than retries.
   A worker invocation cannot be the supervisor invocation. Once a nonempty worker
   invocation is seen, replacement or loss refuses for the rest of this run.
4. End unresolved on an inactive worker, explicit stop or observation count limit.
   Otherwise use the shorter of the positive interval and remaining deadline for
   an interruptible local wait. Early/spurious returns, clock regression, invalid
   callback replies and expiry refuse instead of allowing a busy polling loop.

The interval has no default. Counts are strict integers in `[1, 4096]`. The CLI
uses `threading.Event` and SIGTERM/SIGINT handlers, restoring prior handlers on exit.
SIGKILL releases the kernel lock, but cannot publish an orderly receipt. Neither
signal retires the durable intent or grants a start. No result is published before
final input/ancestry/deadline validation and lock-context exit.

Invocation continuity here is **read-only and process-local**, not a durable worker
claim or a replacement for `RecoverySupervisor`'s request/job/claim journal. Progress,
claims and terminal-looking files cannot grant authority through this operation.
The returned `job` is the last accepted observation, not an attestation that the
worker is still running after the lock is released. Absence of a worker or receipt
never means recovery succeeded.

## Receipt and exit codes

Every returned `host-recovery-observation-v1` receipt has:

- `state: observation_ended_unresolved` and a fixed reason: `stop_requested`,
  `worker_inactive_unverified` or `observation_limit`;
- exact approved source/content/intent/request identities and either the last
  accepted job observation or null when stopped before the first query;
- observation count, effective deadline, sampled monotonic boundaries and elapsed
  observation time; **these are not arm-to-terminal, recovery, alert or downtime
  measurements**;
- complete-fence, recovery-execution, start, terminal-outcome, recovery-completed,
  alert-delivery and production-acceptance flags all **false**.

Exit 3 means this bounded read-only operation ended and emitted an **unresolved**
receipt, never a verified recovery. Invalid arguments exit 2 with fixed text.
Runtime/input/manager/filesystem/clock/output refusals exit 1 without a successful
receipt; restricted exception messages and paths are not printed. There is no
successful-recovery exit code. Standard output failure cannot change durable state;
this process is not an independent alert transport. Final output I/O is not given
a hard-real-time guarantee and must not be promoted into inclusive recovery timing.

## Evidence and remaining prerequisites

Tests exercise real owned filesystem roots, protected snapshots, one directory
flock, actual CLI main/signal/Event lifecycle in separate processes, SIGTERM/SIGKILL,
lock release, unchanged original records and opaque CLI refusal. Actual manager
parsers and fragment-byte checks are also composed with **scripted manager/kernel
observations**. This does not install/start a unit or prove real systemd, daemon,
recovery, external alert, replay drain or operational timing behavior.

Runnable persistent recovery and restart reconciliation, authenticated launch and
inode-pin provisioning, broker/execution wiring, the complete independently
enforced boot/internal-restart/start/writer/pending-operation fence, restoration
oracle, operational alert routing, expired/cross-boot continuations and the approved
disposable full-system matrix remain due. Read-only observation cannot replace any
of them. Release pins, production operations and integrated acceptance remain
unchanged.
