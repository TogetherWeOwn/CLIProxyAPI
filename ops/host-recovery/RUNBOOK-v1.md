# Host recovery runbook v1 — implementation draft

**Status: operational use blocked.** This version records invariants while the
host supervisor/package is being implemented. It contains no installation,
cutover, rollback, management API, credential acquisition or live-probe command.
No production action, release-pin replacement or retry is authorized. The
component test runner in README is the only currently supported invocation.

## Authority and immutable identities

- Development source baseline: `109ac91c2691c75ea0e8e42626e134dc5f63d8c1` in
  `TogetherWeOwn/CLIProxyAPI`. The changed source needs its own reviewed commit,
  package digest and binary/image identities. It is not the unchanged candidate.
- Historical accepted plugin archive SHA256:
  `05f91dc0dec3c9f9b31560b5141da557b4ac9329ce52c242a476005e3a4b727d`.
- Historical extracted plugin SHA256:
  `a9d67946f9334f3789511f0d818f175988b6ffcdca732452685c30d0fdd01147`.
- Historical plugin version: v0.2.2. New instrumented bytes **cannot** be called
  these accepted bytes. Source-to-build-to-archive-to-extracted-plugin provenance
  must be separately bound and reviewed before any new release identity is used.
- Rollback: `v8.0.51-tog.1` / `b4c6bf0e7a0b610983ad21d343aff6a7bef5fb24`.
- No official-image fold, client repinning, tag/release publication or DB migration.
  Auth/config reversal is required. Retain restricted backups until the existing
  production cutover tracking explicitly permits their removal.

## Pre-outage admission (not yet executable)

The persistent host supervisor must refuse admission unless all of these are
verified **before the first stop**:

1. Exact accepted manifest, attempt UUID, installation, manager unit/invocation,
   boot identity, package revision and every helper/unit hash. Policy approval is
   independently authenticated; a locally computed digest is not approval.
2. Candidate/rollback source and immutable image IDs are available locally;
   plugin archive and extracted bytes both match their independently bound hashes.
3. Whole-directory/tree inventory includes every unrelated provider. Exactly nine
   explicitly mapped auths have seven boolean disabled and two enabled flags.
   Preserve original bytes/owners/modes for all entries. Refuse ambiguous mapping,
   links/traversal, unsupported metadata or observed concurrent writers; never
   relax live permissions or copy credentials into fixtures to pass a test.
4. All auth/config/Compose/plugin/image write-set state is in a restricted complete
   baseline. Stage, file-fsync, rename, directory-fsync, verify readback and pin the
   baseline before arming. The backup is outside all mutation/cleanup write sets.
5. Strict actual YAML/Compose source **and** frozen rendered Compose, exact schema,
   full approved Meta stanza/policy, tool versions and interpolation-input identity
   pass. Unrelated maps and sidecar images remain unchanged. No secrets appear in
   public receipts. Revalidate the same pins and frozen rendering after stop.
6. One installation-wide lock; no unresolved prior intent. Supervisor challenge
   response acknowledges the same attempt/package/baseline and a closed start
   fence. Independent alert listener challenge has a real transport receipt.
7. Positive measured phase caps/safety margins fit 120 seconds forward and 180
   inclusive recovery within the 300-second **engineering target**. Refuse absent
   measurements/caps. Synthetic component numbers are not operating allocations.
8. Every daemon object/start/writer path is under the fence, including Docker
   restart policies, daemon restarts, Compose jobs and boot startup. A systemd
   ordering line alone is insufficient. No general Docker/root grant is implied.

Any failed/uncertain durability or acknowledgment before stop means abort
unchanged. No production budget hard ceiling or notification guarantee is claimed.

## Forward ownership and checks (not yet executable)

Only the host supervisor grants first-stop permission after durable recoverable
intent and the monotonic arm point. The launcher is a client, not another rollback
owner. All forward mutators/helpers belong to a separate manager-owned cgroup;
recovery belongs to another manager-owned unit. Broad delegation/detached mutation
is forbidden. Bind identities to manager invocation + attempt, not reusable PIDs.

Stop and verify all writers/service objects before mutation. Revalidate stopped
baseline, package, policy, sources/rendered inputs and dual hashes. Mutate only the
approved manifest write set. Assign candidate daemon ownership at create, reconcile
ambiguous replies by that preassigned identity, durably register the actual full
container ID **before start**, then start only that registered object.

Preserve both A and B:

- **A:** full approved Meta stanza, `plugins.enabled=true` and
  `plugins.configs.meta.enabled=true`, with all accepted fields.
- **B:** move the same enabled replay/pattern values to plugin Meta; remove obsolete
  top-level Meta on stock. Preserve unrelated plugins, aliases and all other maps.
  Exactly nine model aliases use `fork: true` and retain bare IDs.
- Retained patterns: `muse-spark-1.3-contributor*`,
  `muse-wonder-1.0-contributor*`, `muse-wonder-1.0*`,
  `muse-wonder-full-1.0*`.

Every accepted post-check remains mandatory, with source-bound secret-free receipts:

- Correct running image and registered object identity; loaded/registered plugin
  identity; nine bare plus nine namespaced model IDs.
- Covered-model tool-linked two-turn replay, both HTTP statuses successful;
  genuine correlated second-turn producer decision has `kept >= 1` and
  `dropped_foreign == 0`. Any correlated foreign drop defeats an unrelated green.
- Producer-instance startup marker bound by daemon inspection/opened source handles
  to full container/candidate/plugin identities. Complete stdout and every declared
  file-source coverage with cursors/rotation, raw hashes and strict schema. No
  guessed container hostname/short ID, log relabeling, swallowed source error,
  timestamp-window grep or `dropped_foreign=01` false green. An asynchronous
  producer additionally needs a genuine source-reviewed completeness/drain boundary.
  HTTP completion, EOF, silence, contiguous event IDs or absence of a best-effort
  failure marker do not prove its admitted queue or all request/retry decisions
  drained. Killing the producer can discard queued evidence, not prove completion.
  Missing boundaries, timeout, overflow, any producer failure marker or unproven
  source coverage fail closed; do not clear this post-check with a prefix report.
- Subscribed-account bare Wonder tool 200; unsubscribed auths stay disabled;
  seven/two aggregate flags and unchanged unrelated credential bytes/owners/modes.
- Stable API-key fingerprints and plugin-route quota; other-provider Claude and
  Sol tools 200; subscription behavior preserved; no client repinning.

Durable candidate terminal commit requires all checks plus verified running-state
identity. Worker exit alone never commits success. A failed terminal write keeps
nonterminal recovery intent and the start fence; independently alert and recover.

## Recovery/reversal/start fence (not yet executable)

After any armed uncertainty, failure, work deadline, worker loss, supervisor loss
or reboot: reconcile and recover, **never** resume candidate promotion. Preserve
the original cause separately from recovery/persistence/alert failure.

1. Fence every start/writer path. Quiesce/collect the whole mutation cgroup **and**
   stop/verify all old/candidate/attempt-owned daemon objects by immutable IDs.
   Killing only the main PID or cgroup does not prove Docker-owned object stop.
2. If anything cannot be proven stopped, do not restore concurrently; leave start
   fenced and escalate. No second Bash watchdog may race recovery.
3. Validate pinned recovery package and complete baseline. Restore all auth,
   config, Compose, plugin and original image state idempotently, even after partial
   writes/malformed current auth/config. A tampered/missing/unsupported baseline
   cannot authorize old start.
4. Independently verify complete bytes and metadata, original image, original
   top-level replay and absence of the new plugin **before old start**. Failed
   restoration/verification never permits start.
5. Start the registered original object only after that oracle passes; verify old
   readiness; durably persist the outcome and independently attempt notification.
   A visible but uncertain terminal file is not saved success. Absence is not
   success either. Keep unresolved recovery/start latch fenced on failure.
6. Deliberate reversal uses the same installation lock, stop-first and complete
   restore/verify/start sequence. Its accepted alias channel may remain inert on
   the fork only under a separately explicit reversal policy; failed-attempt
   recovery restores the **exact** pinned baseline, not an alias-inert exception.

An ALERT-file write/fsync/rename failure must not prevent independent transport.
Missing listener before arm refuses admission; lost listener after arm is explicit
failure with only already-approved alternate routes. Nonblocking send, transport
receipt and human acknowledgment are different outcomes. All routes unavailable
cannot be reported as guaranteed human notification.

## Time and evidence rules

Persist original arm boot/clock identity. `Dwork=t0+120`, `Dtotal=t0+300`;
`Drecovery=min(tf+180,Dtotal)`. Charge delayed detection from failure or expired
work deadline, not when recovery code notices. Quiescence, child collection,
restore, verification/start, persistence and alert are all inside the recovery
reserve/total. Repeated triggers/phases must not reset deadlines.

On expiry, forbid promotion; escalate and continue only safe bounded recovery.
Never force old start over unverified state. Deadline miss/unresolved safe recovery
keeps start fenced. A later continuation is separately identified, not an on-time
success. Reboot/uncertain monotonic continuity recovers immediately under a new
recovery invocation while retaining the original attempt; never restart its clock
to manufacture a pass. Host-down time is separately unknown/censored wall time.

Retain raw monotonic events for every budget phase, arm-to-terminal elapsed time,
actual sampled reachability intervals/start-stop boundaries and censoring. A
right-censored outage upper bound is null/unbounded, not zero. Test suite runtime
is not downtime; loopback timings are not production timings. Host/PID1 loss,
daemon unavailability, uninterruptible I/O and permanent host loss are external
availability/recovery failures, not locally guaranteed bounded completion.

## Component checkpoint: not operational recovery

The source now includes a durable intent/arm/object journal, whole-root restoration
and an injected-boundary ordering coordinator. These are **not** the host adapter.
The coordinator's named boolean check/oracle acknowledgments are interface tests,
not executable evidence of the retained checks above. Its Python calls cannot
interrupt a wedged operation; actual manager/cgroup enforcement remains required.

The journal never overwrites the original intent with a terminal file. On reopen,
any retained intent fences forward work, including a terminal-looking prior file.
There is no automatic latch retirement or new attempt admission after restart yet.
Do not delete state or bypass that refusal to make the partial package usable.
The recovery-only restart owner now preserves the original arm and installation
lock through durable request-before-dispatch. Unknown failure time is charged
conservatively from the original arm, not restart detection. Cross-boot, regressed,
missing or expired clock evidence remains unresolved and requires a separately
bounded continuation; no fresh budget is granted. A staged/durable recovery request
never automatically redispatches after lost reply or process death, even with an
enqueue acknowledgment. Its explicit observation-only mode now validates the
saved request and observes a pinned request-digest systemd template instance;
the first nonempty recovery invocation is durably bound and may not be replaced.
An absent manager Job or inactive worker stays unverified, never authorizes a
retry, and cannot clear the retained intent. The separate one-shot dispatch adapter
now generates a fixed nonblocking start for only the pinned recovery request
instance, inside an ordered live supervisor lease. This is not an old/candidate
service-start operation or a worker request handshake. No unit is installed and
no host unit was started in component verification. Trusted service/broker wiring,
complete fence and executable recovery/outcome reconciliation remain required.
Enqueue acknowledgment or job observation is not quiescence, restoration or
permission to start the service. Static manager pins now exclude only the known
runtime suffix of a strictly parsed single `ExecStart` display; unknown shapes
refuse, and old raw-display pins are not silently accepted. Actual systemd-version
compatibility still requires the disposable matrix.

The bounded observation-loop core retains that lock after acknowledged enqueue
and between ticks, with explicit interval/deadline/count and interruptible local
wait. Stop/SIGTERM, SIGKILL on reopen, expiry, an exited worker and any uncertain
boundary leave recovery unresolved without redispatch or a start grant. Its latest
sampled elapsed time is not complete recovery/alert time or downtime. Scripted
manager/observer process-signal tests do not install or prove a persistent host
service; the trusted entrypoint, complete fence and recovery oracle remain due.
[Restart ownership source](SUPERVISOR-RECONCILIATION-v1.md) uses injected manager and
complete-fence boundaries; it is not an installed persistent service or executable
reboot recovery. A reviewed settlement/full-resume/continuation protocol is still
required.

Tree restoration only operates after externally proved quiescence. Pre-admission
must reserve its deterministic staging paths in every root's accepted write set,
and list every candidate-only path permitted for removal. It independently rescans
all original bytes/uid/gid/modes after restoration. It refuses unknown entries,
unsafe metadata, type substitutions or unsupported directory access rather than
removing unrelated files or relaxing permissions. This tree oracle does not verify
original images, replay or plugin absence; the full pre-start oracle remains due.

The command/manager/daemon adapter source now separately models manager-owned
mutators and daemon-owned service objects. It pins systemd unit properties and
fragments, reads recursive cgroup-v2 populated state, requests whole-group kill,
checks full immutable daemon IDs/images/ownership/restart policy, and reinspects
service objects after kill. Tests use synthetic child processes, scripted CLI
responses and fake mountinfo/files. **No real manager or daemon drill was run.**

Both adapters still require an independently enforced start/pending-operation
fence and an authorized narrow privilege boundary; neither creates one. Restart
policy `no` does not fence Compose/manual starts or already-pending daemon work.
The generic local command transport is not such a privilege boundary. A helper
reply/death, stable inspection snapshot, main PID exit or empty cgroup is not an
all-writers-quiescent receipt. No create/start operation or unit installation is
exposed by these adapters. Do not give this partial package general Docker/root
access, supply a guessed fence acknowledgment or use it as a runnable recovery
supervisor. The persistent owner, boot/start interlock, worker dispatch and full
oracle integration remain implementation work.

The recovery-only daemon authorization decision engine now denies all starts and
unknown operations and models one prepared, pinned full-ID kill at a time. It
persists pending state before allowing the exact request, records daemon return
without claiming a stop, and requires separate strict stopped-object observation
and durable readback before local drain. Sealing revokes further kills/plans but
cannot discard a pending operation. Reopen, receipt loss, clock/boot discontinuity
and persistence faults retain a reconciliation hold. No state deletion or timeout
waiver is a supported way out.

This engine has **no installed plugin/transport, authenticated broker, start grant,
full supervisor wiring or real-daemon evidence**. Docker-internal restart/restore
paths are not proved to traverse HTTP authorization. Its local `pending_drained`
flag does not establish installation-wide quiescence and cannot authorize file
restoration or old start. The full host/boot fence remains missing. Read
[the authorization scope and prerequisites](DAEMON-AUTHORIZATION-v1.md); do not
install this deny-first subset on a live/shared daemon to fill the test gap.

The raw-file capture/parser source now retains restricted prefix artifacts and
checks exact producer records, correlation, mirrored conflicts and source offsets.
An unchanged actual prior producer-output fixture is used only for component
checks, with its unstamped identity retained. Every report explicitly refuses
complete collection/drain/replay acceptance. There is no daemon stream opener,
real probe/container binding, mixed-log demultiplexer or accepting verifier. Read
[the collection status](REPLAY-COLLECTION-v1.md) before interpreting any report;
no injected "complete" flag or quiet-interval workaround is supported.

The local alert IPC component now implements challenge/notice admission into a
bounded volatile inbox in an independently runnable process. It checks kernel peer
UID, explicit private endpoint, fresh nonce, listener-instance continuity, exact
notice schema/digest and the caller's inclusive local IPC deadline. Missing/lost
listener, saturation, bad framing and lost acknowledgments fail closed. It does
not unlink an existing endpoint; restart reconciliation is still required.

A local admission receipt explicitly says `durable: false` and
`human_acknowledged: false`. Disk-failure tests show the IPC attempt is independent
of the recovery receipt write, not that a durable external alert or human notice
was delivered. No external sink/alternate route, installed independent service or
operational supervisor admission integration exists yet. A volatile inbox cannot
clear the complete pre-arm alert-route gate above.

## Gates still closed

Actual disposable systemd/cgroup/daemon package drills and all transition,
persistence, startup-race, ambiguous-create, process-loss, restoration, alert and
source-correlation negatives remain required. A mock manager is component evidence
only. Do not install/start units on the live host to fill that gap; route the exact
missing disposable capability instead. Integrated Security → QA acceptance stays
unstarted until complete full-package evidence exists. Release Manager incident,
residual-risk and eventual production gates are separate and unchanged.
