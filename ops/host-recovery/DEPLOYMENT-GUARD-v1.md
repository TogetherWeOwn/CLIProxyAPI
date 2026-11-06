# Old-container deployment correspondence — v1

**Read-only source component, not a complete recovery/start oracle or an
installable supervisor.** No Docker socket is opened by the tests, no service is
installed, and no credential, privilege, release pin or live configuration changes.
This guard grants no operation by itself.

## Inputs and restricted observation

`OldDeploymentGate` requires an explicit `DockerObjects` instance, independent
`DeploymentApproval`, caller clock and complete-fence revalidation callback. The
caller retains the existing installation lock. The approval binds the original
intent digest, full old image ID and a projection digest. These are externally
supplied comparison pins, not signatures, approval discovery or provisioning.
Never learn/reseal the expected digest from whichever container happens to exist.

The fixed `container inspect --format=... <full-object-id>` projection contains:

- immutable object and image IDs;
- actual configured executable path and ordered arguments;
- complete Docker `Config` and `HostConfig` maps, including environment, command,
  user, entrypoint, bind/privilege/security/restart/port settings;
- ordered effective `Mounts`, including any anonymous/image-declared volumes.

The projection is bounded to the existing local transport's 64 KiB output limit.
JSON duplicate keys, malformed/unknown projection fields and unsupported top-level
shapes refuse. SHA-256 covers `durable.canonical(projection)` (sorted mapping keys,
exact array order, trailing newline). Config/HostConfig internals are covered in
full by equality, **not interpreted as a complete Docker schema**. An independently
approved shape that the reader cannot represent remains unsupported, not permission
to drop fields. Daemon/CLI versions and authentic source-to-image/approval binding
still need installation-level qualification.

Raw config/environment/mount values are restricted transient memory only. The
reader never logs or persists them; exceptions use fixed codes. Its public result
contains only the schema, full object ID, projection digest,
`deployment_matches: true`, and `start_authorized: false`. Do not log the underlying
command stdout or use a real credential/configuration as a test fixture.

## Revalidation and composition

The gate brackets repeated stopped-object and deployment observations with the
explicit fence callback. The last state and projection reads follow the last
external callback; callback changes to identity/approval/intent cannot become new
approval. Stopped-state observation retains `DockerObjects`' exact image,
restart=no, no auto-removal and unambiguous-state checks. Every failure poisons the
gate; a later green read does not reuse uncertain verification. The final daemon
projection and deadline read are also followed by a local binding check: neither
may change the approval, original intent, old object/image IDs or reader instance.
This does not add another external fence callback or turn point reads into exclusion.

On first use the gate also retains its configured approval, object identities,
source/view observers, fence and clock callbacks, and the Docker reader's command
transport, fixed executable/endpoint tuple, clock and start-fence callback. Those
boundaries must remain unchanged through subsequent observations and the one-shot
pre-start revalidation. Matching replies from a replacement transport do not
inherit verification. Checks follow each state/projection read before another
reader can run, and clock callbacks are bracketed by configuration checks. The
monotonic clock high-water mark survives between calls; a backward clock cannot
start a fresh accounting interval. A caught reentrant refusal poisons the outer
observation. Initial composition before first use is supported, not authenticated
provisioning. This is defensive binding of the Python interfaces, not isolation
from arbitrary code execution or continuous transport/daemon authentication.

`RecoveredDeploymentBoundary` supplements an existing independent baseline oracle.
It validates that oracle's complete receipt first, captures its own receipt copy,
then runs deployment verification. Before one-shot `start_old` delegation it
requires the original intent/receipt and reruns the deployment gate. The validated
receipt is copied before external callbacks. Lost start response or
fence/deployment failure cannot reuse the delegation. It can be composed with
`RecoveredInputBoundary`; neither wrapper manufactures any missing oracle fact.
Both wrappers retain the original oracle/gate instances through the one-shot
handoff. They detach the receipt before any later callback, pass separate intent
copies to the oracle and gate, and reject changed caller/callback inputs or a
caught reentrant refusal. The start callback receives the originally verified
intent/receipt snapshots, never a later borrowed version. Swapping a boundary or
gate before or during the handoff refuses rather than transferring verification.
The actual start boundary must still revalidate all requirements atomically under
the enforced fence. No new start command is provided here.

**Snapshots are not the fence.** An installation lock does not exclude Docker
internal restart, daemon operations, unrelated writers or host startup. The
independently enforced complete fence must cover all those paths and keep them
closed through observation and the actual start operation. Repeated identical
snapshots do not prove there was no inter-query change or close a start race.

## Optional baseline bind-source correspondence

An explicitly supplied `bind_sources=WriteSetVerifier` connects the pinned Docker
projection to fresh baseline observations. The same observer is retained for the
lifetime of the gate; removing/replacing it between verification and the one-shot
start handoff refuses. Without this option the result explicitly reports
`bind_source_baseline_verified: false`; a projection hash alone never implies file
verification. No operational runner is enabled by this option.

`WriteSetVerifier.verify_bind_sources` supports only a nonempty bounded list of
complete-directory binds. Every source path must exactly equal a separately
approved open write-set root. All roots are verified, including roots not mounted
in the container. Files, metadata, unrelated provider entries, selected auth state
and absence of candidate additions must match the original aggregate baseline.
No restoration or repair is attempted. Root handles/approvals, original intent,
mount inventory and reader identity are retained through the final fence/clock
callbacks; changed inputs or read uncertainty poison the observer.

Supported mount rows have exactly `Type`, `Source`, `Destination`, `Mode`, `RW`
and `Propagation`, with `Type=bind`, `Mode=ro`, literal `RW=false` and
`Propagation=rprivate`. Each source occurs once. Destinations must be canonical
absolute non-root paths with no duplicates or parent/child shadowing. Volumes,
file/subdirectory binds, extra fields, writable/propagating mounts and unsupported
shapes refuse. An approved deployment using those features remains unsupported:
never alter the deployment or reseal its approval just to make this check pass.
The full deployment projection is still independently approved before this check.

The gate repeats source verification alongside its daemon observations and again
before one-shot delegation. A final stopped-object/projection read follows the
last source observer callback. The redacted source receipt carries only the
baseline hash, mount count and explicit non-authorizing facts. Paths and bytes are
restricted transient inputs, not public evidence.

**This verifies caller-namespace source-directory correspondence, not mounted
container bytes.** Docker can run in a different mount namespace; a source path in
its inspect output need not resolve to the caller's same inode. Read-only/private
mount observations also do not exclude writes from the host, privileged writers,
submount changes, image-layer mutation or daemon restart. Actual daemon/container
namespace inode/content correspondence, executable/plugin discovery and readiness
remain missing independent oracle facts. No missing receipt fact may be filled
from this optional flag, and no start grant follows from it.

## Optional same-view daemon observation

`daemon_view=ProcessMountView` is an additional, restricted option requiring the
baseline source observer above. Its caller must supply an **already authenticated**
daemon PID and pidfd, plus a check that retains the original daemon transport,
manager identity and complete fence. This module does not discover/authenticate a
daemon from a PID, label, environment variable, inspect reply or current pathname.
No operational service currently provisions this boundary; passing an arbitrary
process's pidfd is not daemon authentication.

`open_process_mount_view` duplicates that supplied pidfd, checks its kernel type,
fdinfo PID and liveness, and anchors a proc directory while the pidfd remains live.
It opens kernel mount-namespace and root handles for the caller and that process.
Both namespace identities must agree (`NS_GET_NSTYPE` must identify a mount
namespace), and both root identities must agree by device, inode **and mount ID**.
Same inode through a different root mount is insufficient. Different namespaces,
chroots, unsupported kernels, unavailable procfs/nsfs or denied reads refuse;
there is no setns, numeric-PID fallback, permission adjustment or path repair.

The first matching namespace/root handles remain open for the context's lifetime,
preventing their identity reuse from silently replacing the original view. Fresh
point observations bracket the baseline source reads. The final daemon projection
follows the last source/view callback. Process death, identity/view drift, context closure, failed deadline,
nonliteral/failed check, callback replacement or caught reentrancy poisons the
observer. Its retained descriptors close on every context exit; it never closes
the supplied caller-owned pidfd. Public output has only a view digest and explicit
non-authorizing facts, not raw proc paths or process/root identity tuples.

The deployment result's `daemon_source_namespace_verified` reports whether this
optional view was actually checked, not whether a daemon identity was independently
provisioned. Removing/replacing a configured view before one-shot old-start
revalidation refuses. Without the option that field is false.

**Same namespace/root does not verify container-mounted bytes.** Matching point
observations establish a shared path-resolution view only at the observed points;
they do not establish historical mount provenance when Docker created a bind,
continuous namespace/root/submount/writer exclusion, a stopped container's future
mount tree, image-layer integrity, plugin discovery, readiness, transport
provenance or any missing baseline-oracle fact. A daemon in an intentionally
private namespace remains unsupported by this option, not permission to weaken
its sandbox or reseal its approval. The complete external fence and independent
container/runtime verification remain mandatory. No start or settlement is enabled.

Tests authored for this option use real own-process/child pidfds and proc/nsfs
handles with scripted authority callbacks, plus scripted namespace/root-mismatch,
read-fault and deployment fixtures. They are not real-daemon namespace qualification,
privileged namespace-switch tests or full-package recovery evidence. Execution and
CI results must be recorded separately; authored tests are not passing evidence.

## What this does not prove

A matching projection cannot establish mounted file contents/metadata, effective
mount namespace inode identity, image filesystem integrity/runtime mutation,
plugin discovery/absence in the running process, readiness, application semantics,
network graph equivalence, pending-operation drain, or the authenticity of Docker
and its transport. Baseline restoration, original replay/no-plugin input checks,
complete writer/container quiescence and runtime/plugin/readiness verification
remain separate requirements. No complete-fence, settlement, reboot continuation,
recovery-time or production acceptance is emitted.

## Offline evidence

Tests use scripted daemon/fence/oracle boundaries and a real local **synthetic
reply executable**, not Docker or systemd. They cover command/environment/host
configuration/effective-mount drift, immutable IDs, malformed/oversized/private
responses, clock/deadline loss, false/changed fence, approval/intent mutation,
strict receipt composition, one-shot/lost-response refusal, and actual coordinator
recovery with synthetic baseline files. The latter still has scripted manager,
daemon, fence and readiness boundaries; no full-system or timing claim follows.

Initial new-reader regressions exposed an omitted final stopped-state recheck and
a mutable borrowed oracle receipt. Their exact initial source, tests and raw
failures are retained with final greens. These are development-path fixes, not a
claim of repairing a deployed incident. Operational supervisor/worker and complete
host fence remain unfinished.
