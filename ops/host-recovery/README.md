# host-recovery-v1 — source implementation in progress

**Component source only. Not an installable recovery supervisor, a live run
instruction, a release artifact, or production acceptance.** There are no live
path defaults, service installation commands, management API calls, or credentials
in this subtree. Do not execute the received launchers or use this partial source
as a substitute for the accepted production binaries.

## Implemented so far

- `host_recovery/deployment.py`: explicit intent/image/projection-pinned read-only
  old-container command, full Config/HostConfig and effective-mount correspondence.
  Repeated stopped/deployment observations follow fence revalidation; no raw
  environment/mount values leave the reader. An opt-in boundary supplements the
  existing baseline oracle before one-shot old-start delegation and never supplies
  missing oracle facts. Tests use scripted daemon/fence/readiness observations
  and a real synthetic reply helper, **not Docker/systemd**. Complete host fencing,
  mounted-byte/runtime-plugin/readiness verification and authenticated provisioning
  remain due; success has `start_authorized: false`. See
  [deployment guard and limits](DEPLOYMENT-GUARD-v1.md).
- `host_recovery/durable.py`: no-follow fd-relative filesystem access, one
  installation-directory lock, bounded regular-file reads, restricted atomic
  writes with file fsync → rename → directory fsync → readback acknowledgment.
  Failed/ambiguous writes raise even if destination bytes are visible. Staging
  evidence is retained, not silently cleaned or treated as a terminal record.
- `host_recovery/inventory.py`: complete bounded directory/tree inventory,
  original bytes/uid/gid/mode, a separately supplied exact-nine auth selection,
  strict seven-disabled/two-enabled validation, and immutable restricted baseline
  blobs/manifests. Mixed directories retain unrelated providers. No hardcoded
  synthetic filenames are used by the implementation. Unsafe links, hardlinks,
  special files, xattrs/ACLs, cross-device entries, unsupported modes and observed
  concurrent inventory changes fail closed. These are **not restore operations**.
- `host_recovery/budget.py`: explicit 120/180/300-second policy validation,
  positive phase caps and safety margins, monotonic same-boot accounting,
  detection charged from the actual trigger/work deadline, non-resetting phase
  deadlines, and forward-promotion refusal after a recovery trigger. This is an
  accounting primitive, **not yet a manager-enforced watchdog**. A measurement
  digest is structurally required; verifying/authenticating the accepted drill
  and policy belongs to supervisor admission. Test caps are synthetic, not a
  measured operating policy. There is intentionally no default allocation.
- `host_recovery/journal.py`: immutable restricted attempt intent and separately
  durable arm point; exact stopped/no-restart daemon-object registration before
  candidate-start eligibility. Registration/terminal uncertainty never replaces
  the original intent or grants a start. Recovery revokes forward eligibility.
  Reopening a journal always fences forward work, including when a terminal file
  is visible. **Settlement/archival and new admission after supervisor restart are
  not implemented**; this intentionally conservative latch is not yet a complete
  usable supervisor lifecycle.
- `host_recovery/supervisor.py`: recovery-only restart ownership/dispatch source.
  A context retains the installation lock across strict owner/fence boundary
  acknowledgments, durable request-before-enqueue and receipt persistence. Missing,
  malformed, changed, cross-boot or expired arm evidence never gets a fresh budget.
  Unknown failure time is conservatively charged from the original arm. A staged
  or durable dispatch request, including an acknowledged one, requires manager
  reconciliation instead of automatic redispatch after process loss. A real
  separate-process SIGKILL/lock test uses **scripted manager callbacks**, not a
  systemd recovery unit. A bounded `watch_pending` loop now retains the same lock
  after acknowledged enqueue and across read-only pending/running observations.
  Explicit interval/deadline/count/interruptible-wait bounds never reset recovery
  time; stop, expiry, inactive worker and uncertainty escalate unresolved. Actual
  SIGTERM/SIGKILL tests use scripted manager/observer boundaries. No runnable
  persistent manager service, installed fence, recovery execution, cross-boot
  continuation, settlement or start grant exists.
  See [restart ownership and limits](SUPERVISOR-RECONCILIATION-v1.md).
- `host_recovery/outcomes.py` and the supervisor/worker/broker result path: optional
  one-shot report on the same claimed kernel-peer connection. Original request,
  intent, claim and evidence digests are persisted before a result acknowledgment;
  a fresh independently provisioned baseline/readiness oracle is required before
  recording observation. Restart can inspect saved reports but cannot revive the
  peer, replay receipts, redispatch or reuse an old observation as verification.
  `worker_result_observed` is separate from recovery completion/settlement/start
  permission, which remain **false**. Same-lock manager/file rechecks surround
  persistence and external callbacks. Actual peer/process-death/SIGKILL/flock and
  storage-fault tests still use **scripted manager/fence/oracle boundaries**. No
  operational worker, full fence, oracle or settlement implementation is supplied.
  See [result protocol and limits](RESULTS-v1.md).
- `host_recovery/jobs.py` and explicit supervisor observation mode: read-only
  observation of a pinned `cpa-recovery@<request-digest>.service` instance after
  ambiguous dispatch. Preserve the original request/arm and bind the first observed
  recovery invocation durably, then refuse replacement or loss of that identity.
  Missing jobs and inactive/exited workers remain unverified; no enqueue, retry,
  restore, terminal settlement or start grant is added. Local helper/systemd output
  is not authenticated by a matching dictionary; manifest approval, trusted local
  transport and the independently enforced fence remain external prerequisites.
  Tests use scripted properties, a real reply helper and process SIGKILL, **not a
  real manager or daemon**. The loop core above is not a runnable persistent service.
- `host_recovery/dispatch.py`: one-shot fixed-argv enqueue of the pinned recovery
  request instance only, under the supervisor's ordered synchronous dispatch
  lease. Observe → enqueue → acknowledge authorizations revalidate the durable
  request, owner, complete-fence callback and original deadline under the same
  installation lock. Duplicate/reordered/failed lease phases cannot acknowledge
  dispatch. Active/pending/previously invoked jobs require observation, not restart.
  Lost replies exhaust the adapter and retain the request without redispatch.
  **An enqueue acknowledgment is not a worker handshake or recovery outcome.**
  Scripted manager/local helper tests do not install/start a host unit. The trusted
  service/broker wiring and independently enforced fence remain missing; generic
  injected managers remain external trusted test boundaries.
- `host_recovery/worker.py`: one-shot request-instance identity handshake over an
  explicit private Unix-seqpacket endpoint. Kernel connection and per-message
  credentials must match; Linux 6.5+ `SO_PEERPIDFD` pins the actual connecting
  process, with no numeric-PID fallback. `jobs.observe_worker` requires the pinned
  running unit's MainPID and kernel unified-cgroup membership. The supervisor
  retains its installation lock and rechecks owner/fence/request/arm/invocation
  around a durable once-only worker claim, then acknowledges identity only.
  **Restoration and service-start permissions remain false.** Lost replies,
  persistence faults, peer loss and restart do not recreate claims. Explicit
  observation-only reopen can inspect a validated historical claim and its manager
  invocation, never revive/authenticate the old peer, redispatch or settle recovery.
  A replacement supervisor cannot claim an unclaimed original-owner request.
  Same-uid/root
  hostility is outside this private-endpoint boundary. The worker must bootstrap
  its expected supervisor PID/owner/request/intent from a trusted manager path,
  not environment assertions or a socket reply; that service wiring remains due.
  Real Linux IPC, descriptor-transfer and process-SIGKILL tests use **scripted
  manager/fence/cgroup observations**, not installed manager/daemon recovery.
- `host_recovery/bootstrap.py`: read-only calling-supervisor identity bootstrap.
  Two fixed manager queries bracket kernel boot/cgroup observations; the pinned
  non-root numeric UID/GID, command/sandbox, running MainPID and invocation must
  agree. The MainPID must be this calling process, never an arbitrary target PID
  or environment assertion. Reobservation cannot adopt a replacement invocation,
  boot or cgroup; uncertainty revokes the instance. It supplies `observe_owner`
  only, not the independent fence or dispatch boundary. Tests use **scripted
  manager/cgroup reads**, including real local-helper and separate-process checks.
  Accepted manifest/command trust and runnable service wiring remain due; no
  units, start permissions or credentials are introduced.
- `host_recovery/worker_bootstrap.py`: one-shot manager-bound worker claim client.
  It requires an independently accepted request/intent pin and unit bindings,
  verifies its own numeric owner/MainPID/cgroup, and discovers the original
  supervisor MainPID only as a connection hint. Before sending and after receiving
  a claim, the connection-bound pidfd must remain live around repeated pinned
  manager/cgroup/boot/request observations. The received worker invocation must
  match the client's independent observations. A replacement supervisor, changed
  worker, lost reply or expired original reserve refuses without retry. **This
  acquires identity only, not restoration/start permission.** Package/manifest
  approval and trusted root-handle acquisition, persistent service wiring,
  complete host fence and recovery execution remain due. Real local IPC tests
  still use **scripted manager/cgroup/fence boundaries**, not installed-systemd
  or daemon recovery evidence.
- `host_recovery/loading.py`: read-only installed-content and original-request
  loaders, starting from **independently approved pins and trusted, already-open
  root descriptors**. An adjacent index or self-consistent journal cannot supply
  approval. Exact bounded no-follow content inventory, numeric uid/gid, protected
  modes, source revision, per-file hashes and final identity rewalk produce only
  immutable captured bytes; files are never imported/executed or reopened for
  execution. The separate journal reader binds approved intent/package/manifest/
  baseline/policy/attempt pins to the actual original arm and digest-named request,
  current supervisor owner and saved same-boot deadline. Staging ambiguity and
  changed/missing/private-record failures refuse without clearing the latch.
  `SystemdWorkerBootstrap.from_journal` passes these loaded inputs into the existing
  one-shot identity client; all live manager/peer checks still apply. **This is not
  archive attestation, approval discovery/signature verification, trusted handle
  acquisition, a lock owner, a baseline-content oracle or an installed service.**
  The caller must hold the installation lock and exclude cooperating writers.
  Local reads cannot repair uninterruptible storage or provide a hard-real-time
  bound. No restoration/start permission is added. See [loading contract](LOADING-v1.md).
- `host_recovery/installation.py`: protected-path acquisition of the loaders' two
  directory handles from independent installation/path/device/inode/owner pins.
  No-follow ancestor/edge checks, protected ownership/modes/metadata and separate
  roots are mandatory; world/group-writable ancestors, including sticky `/tmp`,
  refuse. A nonblocking flock on the existing journal-directory inode retains the
  **same installation lock**, not a new lock namespace. Validated handles compose
  both read-only loaders, recheck ancestry before returning captured bytes, and
  revoke on observed changes, faults or context exit. No directories/permissions
  are created/changed. This is **not authenticated approval/pin provisioning,
  mount-namespace attestation, installation, a live supervisor or execution/start
  permission**. Real filesystem/process/SIGKILL/lock tests remain component
  evidence, not installed-systemd/daemon recovery proof. See the
  [acquisition boundary](LOADING-v1.md#protected-installation-handle-acquisition).
- `host_recovery/launch.py` and `status.py`: exact externally digest-pinned launch
  configuration, protected no-follow approval-file reads and a bounded read-only
  calling-supervisor status entrypoint. It composes manager self-identity with the
  existing locked content/original-request loaders and rechecks both after manager
  reobservation. Unknown/mixed fields, owner/installation mismatch, changed files,
  unsafe ancestry, lost identity and expired original deadlines refuse. Output is
  secret-free `inputs_verified_only`; complete-fence, execution, start, terminal
  outcome and production-acceptance flags stay **false**. CLI refusals never echo
  restricted paths or exception text. The external launch digest is an integrity
  anchor, **not proof of who approved it**; authenticated provisioning, trusted
  interpreter/helper/launch, persistent service and independent alert wiring remain
  due. This process must itself be the pinned MainPID, not an attaching client or
  second lock owner. Tests use **scripted manager/kernel observations** and real
  owned files/locks plus CLI failure subprocesses, not installed-systemd recovery.
  See [the launch/status contract](LOADING-v1.md#pinned-launch-configuration-and-read-only-status).
- `host_recovery/observation.py` and `observe.py`: a bounded read-only manager-launch
  entrypoint retaining that **same installation-directory lock** across ticks and
  interruptible waits. Each tick revalidates the original approved snapshots and
  calling supervisor, brackets pinned recovery-job observations and refuses worker
  invocation replacement/loss. One timer cannot renew the original deadline.
  Count/stop/inactive endings remain unresolved; expired, changed or uncertain
  inputs refuse. SIGTERM/INT interrupt the wait; SIGKILL releases the lock without
  altering the original request. **No dispatch, fence acknowledgment, claim,
  restoration, settlement, start or completed-recovery path exists.** Exit 3 emits
  an unresolved read-only receipt, not success. This neither adopts old requests on
  supervisor restart nor wires operational alert transport. Process/filesystem
  tests and actual parser composition use **scripted manager/kernel observations**,
  not installed units/daemon recovery. See [observation and limits](OBSERVATION-v1.md).
- `host_recovery/broker.py`: pinned calling-manager/input loading to one original
  request's worker identity exchange under the **same installation lock**. It
  borrows that locked journal, checks a separately approved private endpoint and
  worker numeric owner, and revalidates original content/request/manager/path around
  the explicit complete-fence boundary. No enqueue method or live CLI exists.
  `identity_reply_sent_only` means a local identity reply was sent, not that it was
  accepted or recovery ran. All execution/restoration/start/outcome/acceptance
  grants remain false. Original deadlines and retained socket/claim state prevent
  replay after ambiguity. Bootstrap/context-exit failures also attempt independent
  alert transport despite receipt disk failure. Actual IPC and separate broker
  SIGKILL tests still use **scripted manager/cgroup/fence boundaries**, not installed
  systemd/daemon/full recovery. Provisioning, runnable persistent service, complete
  fence and outcome integration remain due. See [composition and limits](BROKER-v1.md).
- `host_recovery/restore.py`: bounded whole-root restoration of original bytes,
  uid/gid/modes, with an explicit accepted list of candidate-only additions.
  Unknown entries, type changes, unsafe links/metadata and tampered baselines
  refuse restoration before mutation. Reserved deterministic staging names allow
  retry after partial writes/fsync/rename failures. A final independent rescan
  checks the complete tree. One ownership domain and owner-accessible directories
  per root are supported; unsupported access is refused, never relaxed. This
  does **not** verify image/replay/plugin semantics or stop any writers.
- `host_recovery/write_set.py`: aggregate-pinned multi-root filesystem recovery
  using independently approved protected paths and the **same caller-held
  installation lock**. Every declared baseline/current inventory and the original
  exact-nine auth selection is checked before the first mutation. All-root final
  verification preserves unrelated providers, config/Compose bytes and supported
  metadata and removes only approved additions/staging. A required independently
  enforced quiescence callback and original phase deadline bracket operations;
  this is not that fence's implementation. Fresh contexts can reconcile partial
  restores; failures poison the current context. Filesystem-only receipts grant
  no service start or semantic oracle. Real multi-root/process/SIGKILL and storage
  fault tests still use **scripted host/daemon/semantic boundaries**. Authenticated
  aggregate provisioning, complete semantic guards and actual manager integration
  remain due. See [multi-root scope and limits](WRITE-SET-v1.md).
- `host_recovery/baseline_gate.py` and `inputguard/baselinecmd`: fresh restored
  all-root file capture plus a distinct non-authorizing rollback-input helper.
  Strict original replay-layout/subtree, no-plugin-config and closed rendered
  Compose/image-reference checks run after the existing independent stopped-state
  oracle and again before one-shot old-start delegation. Incomplete oracle facts,
  lost replies, source/fence/role/policy drift or uncertainty refuse. This is not
  the full rollback application schema, observed daemon image/effective mounts,
  runtime plugin absence, readiness or complete host fence. Real files/helper
  tests still use scripted manager/daemon/oracle/alert boundaries. See
  [restored-input scope and limits](BASELINE-GUARD-v1.md).
- `inputguard/`: bounded strict YAML exact-delta comparison using the existing Go
  YAML parser. Exact old/new semantic hashes and independent raw-byte pins compare
  config, Compose source and frozen-rendered Compose without wildcard exclusions.
  Tests preserve unrelated plugin/alias maps and service images, reject ambiguous
  YAML and verify exact inverse plugin/replay changes. A bounded stdin-only Go
  helper now accepts exact JSON/base64 bundle requests and emits fixed receipts.
  `host_recovery/input_gate.py` executes an independently pinned, open helper inode
  with bounded full-duplex pipe I/O and original inclusive deadlines. An opt-in
  `GuardedBoundary` composes fresh comparison with preflight and stopped forward
  revalidation, preserving existing listener/schema checks and the independent
  recovery path. Actual built-helper/coordinator tests use synthetic protected
  descriptors and **scripted manager/fence/oracle boundaries**. The separate opt-in
  `applicationcmd` helper and `ApplicationInputGate` additionally validate both
  host-owned config documents using the actual application types/pure validators,
  without runtime normalization, secret hashing or path loading. Unknown/mistyped
  source groups cannot hide behind expansion/overrides. Its distinct receipt
  prevents a comparison-only helper downgrade. The separate `composecmd` helper
  and `ComposeInputGate` add actual pinned compose-go single-file interpolation,
  schema/model loading and correspondence to both frozen models, without daemon,
  file discovery or ambient environment. Missing values, nested defaults, unsupported
  multi-file features and incorrect frozen models refuse. This is not the Docker
  CLI config command or full runtime/graph/plugin validation. No runnable host
  supervision, authenticated approval/pin provisioning or recovery/start authority
  is supplied. See [strict subset and protocol](INPUT-GUARD-v1.md),
  [application validation scope](APPLICATION-GUARD-v1.md) and
  [Compose renderer scope](COMPOSE-GUARD-v1.md). The separate `metacmd` helper,
  `ProtectedMetaSnapshot` and `MetaInputGate` compose a reviewed-source-pinned
  conservative Meta replay-config shape with those checks and a distinct receipt.
  Both sides validate; proposed global/Meta plugin activation must be explicit.
  Malformed/unknown Meta options refuse rather than relying on the producer's
  error-discarding parser. Other plugins remain opaque. This is not full A+B
  migration-policy approval, installed-artifact identity or producer execution;
  see [source/profile and unsupported-field limits](META-GUARD-v1.md).
- `host_recovery/input_snapshot.py`: reusable protected seven-file capture for the
  exact-input gate: three before/after source/frozen-render pairs and an independent
  delta policy, all bound to the original intent and external raw pins. The shared
  `protected_file.py` reader retains no-follow descriptors through final byte
  rehash and path/root checks. Every barrier and post-helper check captures fresh
  bytes under the caller's same installation lock, writer boundary and deadline.
  Private files, distinct objects, bounded bytes, policy envelope, replacement,
  storage faults and boundary/clock uncertainty fail closed. Built-helper tests
  use **synthetic files and scripted host boundaries**, not real rendering, schema
  validation, authenticated provisioning or installation-role mapping. Reading a
  frozen file does not prove its renderer/input correspondence. See
  [capture interface and remaining prerequisites](INPUT-SNAPSHOT-v1.md).
- `host_recovery/compose_snapshot.py`: wraps that capture with two protected JSON
  interpolation maps and a fixed renderer/project identity. Retained environment
  descriptors enclose base capture/recapture; final byte rehashes refuse observed
  drift. All nine files have separate role identities. Same-lock capture and fresh
  rendering compose at both forward barriers. Real files/built helpers still use
  **scripted manager/fence/oracle boundaries**, not installed host recovery.
- `host_recovery/artifacts.py`: protected, original-intent-bound archive and installed
  library availability/dual hashes plus streamed exact ZIP-member correspondence.
  Opened descriptors are retained; both files are rehashed after parsing and path/
  owner/metadata/fence/deadline uncertainty refuses. No extraction or plugin loading.
  An optional artifact gate composes with the existing admission/stopped exact-input
  barrier without replacing listener/schema checks or blocking recovery on a bad
  candidate archive. Tests use actual synthetic files/ZIPs and the built YAML helper
  with **scripted host/fence/schema/oracle boundaries**; no actual producer-package
  compatibility or integrated recovery acceptance is claimed. Authenticated approval,
  image availability and operational wiring remain due. See
  [artifact subset, trust and limits](ARTIFACT-GUARD-v1.md).
- `host_recovery/coordinator.py`: component forward/recovery ordering, injected
  manager/daemon boundaries, registration-before-start, strict post-check and
  restoration-oracle acknowledgment shapes, original versus recovery errors,
  inclusive deadline accounting and independent alert attempts. Calls receive
  phase deadlines and are checked afterwards; the concrete manager must enforce
  them while calls are running. An observed manager failure timestamp is charged
  from that event, not from delayed detection. `resume()` now connects a reopened
  original journal to that same recovery sequence with its original arm and
  conservative detection cap, recovery-only preflight and repeated original-input
  checks. Prior dispatch/claims/staging, expired/cross-boot state and uncertainty
  refuse; terminal-looking files cannot skip recovery. Real synthetic restoration
  and SIGKILL tests still use scripted host/oracle boundaries. See
  [resume subset and limits](RESUME-v1.md). No blocking-call watchdog, persistent
  supervisor loop, reboot/expired continuation, actual manager or executable
  post-check implementation exists here yet. The local alert inbox
  described below is separate and is not wired into operational admission. Mock acknowledgments
  are **not** complete host/package/start-fence evidence.
- `host_recovery/commands.py`: bounded local subprocess output and same-clock
  deadlines, a fixed minimal environment and no shell/session escape. Helper
  failure, output overflow or lost reply is an uncertain operation, not a daemon
  cancellation. Deadline cleanup kills only the helper; the owning supervisor
  must reap it and independently quiesce the complete manager/daemon boundary.
  This is **not a privilege boundary or a hard-real-time watchdog**.
- `host_recovery/manager.py`: explicit systemctl command generation, strict unit
  property/fragment pins, distinct non-nested forward/recovery unit bindings,
  whole-control-group SIGKILL and repeated manager/cgroup-v2 observations. Static
  pins project one strict `ExecStart` display into path, unchanged displayed argv
  and ignore-errors policy; embedded runtime timestamps/PID/exit data are not
  configuration. Unknown/ambiguous display shapes refuse. Old raw-display pins do
  not match the new projection; real-version compatibility remains unproved.
  Non-root, non-delegated, no-capability mutator properties are required. The
  recursive kernel populated bit, no pending job and inactive state are all
  checked; PID exit alone is insufficient. Missing/reused groups or changed
  invocation/configuration refuse or remain pending. No units are installed or
  started. Tests use **scripted manager/fake-mount fixtures**, not actual systemd.
- `host_recovery/daemon.py`: explicit local Docker endpoint, projected inspection
  without environment/mount/credential output, full immutable old/candidate IDs,
  exact installation/attempt ownership, no-restart/no-auto-remove checks and
  reinspection of every stopped object. Multiple attempt-owned objects are all
  considered for recovery; short/foreign/changed IDs fail closed. It exposes no
  create/start/update/restart/remove operation. Tests use **scripted CLI replies**,
  not an actual daemon or installed authorization boundary.

The manager and daemon adapters both require an independent, currently enforced
start/pending-operation fence. Their injected Boolean acknowledgment is an
interface requirement, **not an implementation or proof of that fence**. Source
property pins alone do not authenticate policy approval. The persistent supervisor,
privilege broker, boot/restart/start authorization and integration of these
adapters with the coordinator remain missing. An empty cgroup, `restart=no`, stable
inspection snapshots or a killed helper cannot substitute for those prerequisites.
No broad Docker/root permission is provided or requested by this source.

- `host_recovery/fence.py`: recovery-only deny-first Docker authorization decision
  engine. Starts/create/restart/update/exec and unknown routes are always denied.
  Only an explicitly pinned authenticated supervisor principal can inspect bound
  full-ID objects or perform one prepared exact kill. Durable pending records
  precede permission; a response alone never clears pending work, and a separate
  stopped-object observation plus durable receipt is required. Sealing revokes
  new/unconsumed mutations without discarding pending work. Faults, unexpected
  receipt files, restart or clock discontinuity close admission. **This is not an
  installed plugin, trusted transport or supervisor integration.** Docker-internal
  restart/boot paths are not proved fenced. No original/candidate start grant or
  restart reconciliation is implemented. All complete-fence/acceptance status
  fields remain false. See [the exact subset and prerequisites](DAEMON-AUTHORIZATION-v1.md).
  Synthetic protocol callbacks are not real-daemon compatibility/drain evidence.

- `host_recovery/collection.py`: explicit no-follow regular-file handles and
  restricted durable full-prefix snapshots with observed identity, offsets,
  raw hashes and genuine empty-source accounting. Observed rotation/truncation/
  rewrite, read failure and persistence uncertainty poison the capture. This is
  **not** a daemon/stdout opener, rotation follower or container provenance proof.
- `host_recovery/replay.py`: bounded strict startup/decision NDJSON inspection,
  byte-identical mirror deduplication, exact request/model/turn matching and
  correlated foreign-drop/conflicting-duplicate negatives. Any producer failure
  marker, partial/unknown record, gap or malformed integer rejects. Spool-receipt
  readback wires actual raw hashes/offsets/source-set checks to this parser.
  **Every report remains prefix-only and non-accepting.** HTTP completion, EOF,
  silence, contiguous sequences and no failure marker cannot establish an
  asynchronous producer's complete drain. There is no accepting mode, flush
  implementation or real container/source mapping here.
  See [collection status and immutable fixture provenance](REPLAY-COLLECTION-v1.md).
- `host_recovery/probe.py` and `probe_http.py`: two actual synthetic loopback
  Messages POSTs with request-origin IDs, exact tool-use/result linkage and preserved
  thinking/signature blocks. A fresh post-tool confirmation prevents initial-nonce
  shortcuts. Six private durable raw artifacts, strict response/framing limits,
  one inclusive local helper deadline and no redirects/retries/credential scraping.
  **Not live-probe authorization or real ingress/producer/container evidence.**
  All source-authentication/collection/drain/replay/production acceptance fields
  remain false. See [HTTP probe boundaries and retained regression](HTTP-PROBE-v1.md).
- Diagnostic HTTP ingress → executor → plugin metadata bridge, using the
  existing metadata ABI without a provider-kit change. See the carrier below.

The filesystem and lock operations assume an explicitly accepted ownership
contract and exclusion of cooperating writers. They do not defend against hostile
root/same-uid actors. A lock-owner structure is not proof of a real manager
invocation; the supervisor still has to verify that identity at admission.

## Diagnostic carrier

The server consumes these HTTP headers before engine-configured middleware,
request logging, credential selection and request building:

| Header | `cpa_recovery_v1` metadata field |
| --- | --- |
| `X-CPA-Recovery-Attempt-Id` | `attempt_id` |
| `X-CPA-Recovery-Probe-Id` | `probe_id` |
| `X-CPA-Recovery-Request-Id` | `request_id` |
| `X-CPA-Recovery-Parent-Request-Id` | `parent_request_id` |
| `X-CPA-Recovery-Turn` | integer `turn` |

IDs are 1–128 ASCII bytes, matching the producer carrier contract, starting with an alphanumeric character and containing
only alphanumerics, `-`, `_`, `.`, `:`. Turn is exactly `1` or `2`; turn 1 has no
parent, turn 2 requires a distinct parent request ID. No trimming, comma folding,
duplicate headers, unknown diagnostic fields, or partial envelopes are accepted.
An invalid envelope has **no diagnostic metadata**, but does not change normal
HTTP authentication/error semantics. Every `X-CPA-Recovery-*` header is removed,
even if invalid/unknown; explicit SDK headers and plugin executor headers are
also filtered. Authorization and session headers are untouched. IDs are untrusted
diagnostic data, never credentials, auth-selection hints, or proof of replay.
Requested model stays in existing `requested_model` metadata; resolved model stays
in the executor request's model field.

Ingress/handler/plugin-seam tests are component evidence, not actual Meta replay
decision evidence. A retained actual producer-output fixture now exercises the
prefix parser, without changing its unstamped identity or claiming current
producer execution. The canonical producer, startup/container/source-handle
binding, daemon collector, asynchronous completeness boundary, two-turn HTTP
probe and accepting verifier still have to be integrated. No timestamp grep,
quiet prefix or diagnostic/container label substitutes for those missing links.

## Safe component verification

From this repository's verified isolated worktree:

```sh
python3 -I ops/host-recovery/tests/run.py
go test -timeout 180s ./internal/recoverycorrelation ./internal/api/middleware ./internal/api ./sdk/api/handlers ./internal/pluginhost
go build -o test-output ./cmd/server && rm test-output
```

The Python runner explicitly adds only this repository-owned package to isolated
Python's path. It creates fresh synthetic temporary roots. No unit is installed,
no daemon is contacted and no real auth/config/backup is read. Tests use fake
clocks and deterministic fault injection, not wall-clock sleeps. Filesystem fault
injection includes EIO/ENOSPC, write/fsync/rename/directory-fsync/readback, partial
writes and terminal-looking destination bytes after uncertain durability.

The independent alert helper attempts its transport even if receipt persistence
raises. `host_recovery/alert.py` now provides a Linux Unix-seqpacket listener/client
with a private explicit endpoint, kernel peer-UID checks, fresh nonce challenge,
listener-instance pinning and exact digest-bound notice receipts. Nonblocking IPC
uses the caller's inclusive phase deadline, without retries or a new allowance.
Packet/peer/inbox caps and idle-peer expiry are explicit. Malformed/truncated or
ancillary data, missing/replaced listener, wrong peers, saturation and lost replies
cannot produce success. Existing endpoints are never unlinked/replaced by it.
Supervisor failure codes now share the transport's fixed allowlist; a real IPC
regression covers supervisor alert admission despite ENOSPC receipt failure.
Unknown error text still cannot enter the notice. This corrects the earlier
supervisor/stub-only contract gap, not the missing external alert sink.

**Its receipt proves volatile local inbox admission only**: not durable storage,
external route delivery, supervisor availability or human acknowledgment. The
separate-process disposable test exercises this admission despite injected disk
failure. No external notification sink, installed independent service, supervisor
admission wiring, restart persistence or alternate route is implemented. Do not
use a challenge alone to pass the full operational alert prerequisite.

## Remaining acceptance work (not implemented or not proved)

1. Persistent systemd supervisor with admission, durable active-attempt latch,
   separate manager-owned forward/recovery cgroups, all six semantic operations,
   boot fence and reconciliation after manager/worker loss. No second Bash
   rollback owner.
2. Integrate the new manager/daemon observation/quiescence adapters with an actual
   independently enforced narrow start/pending-operation fence and persistent
   supervisor. Complete create/start authorization, immutable IDs registered
   durably before start, ambiguous-create reconciliation and daemon/reboot restart
   prevention. Scripted adapter tests do not prove complete cgroup **plus daemon**
   quiescence or install a privileged authorization boundary.
3. Full write-set conversion and integration of the tree-restoration component
   across every approved root; complete independent config/Compose/image/replay/
   no-plugin oracle before old start; safe journal settlement, supervisor resume
   and separately identified bounded recovery continuations; actual independent
   listener challenge/receipt. Strict mock receipt shapes do not prove semantics.
4. Actual strict source YAML/Compose + frozen-rendered Compose, schema/policy,
   authenticated approval, interpolation/tool identity, artifact dual hashes and
   preflight/stopped revalidation. The historical r3 comparator is not that
   integration and is not imported as if it were.
5. Integrate the prefix-capture/parser components with real source-bound HTTP
   probe/producer/RPC/container evidence, all required sources, cursors/rotation,
   mixed-log framing and both tool-linked turns. Establish a genuine source-reviewed
   asynchronous completeness boundary; prefix inspection cannot issue acceptance.
   Recheck the corrected producer's immutable source/schema/artifact delivery.
6. Actual pinned package disposable systemd/cgroup/daemon matrix, measured phase
   caps/safety margins, independent restoration/start oracle and raw availability
   samples/censoring. No systemd/daemon capability is asserted by a component test.
7. Complete normal PR checks/reviews, a narrow authorized publication base, and
   exact reviewed-head merge. No release pin or production action is authorized.

See [the versioned runbook](RUNBOOK-v1.md) for retained invariants and blocked
operational gates. Reference archives remain provenance/negative material, not
production defaults; [provenance](provenance.json) identifies the inspected bytes.
Prior reference test counts are historical evidence, not tests rerun here.
