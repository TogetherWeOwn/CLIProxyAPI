# Fresh private Docker runtime qualification v1

Status: Actions-only diagnostic source; **new assertions require exact-head
Actions evidence**. This is not an operational broker, installation procedure,
authenticated runtime release, complete cold barrier or recovery acceptance.

`tests/docker_runtime_fixture.py` extends the existing containerd qualification
to the actual Docker integration. It refuses drift against the exact Docker
28.0.4 daemon/client bytes independently retained in Actions 42129659342, plus
the existing containerd/shim/runc pins. Docker's embedded VCS/import/distro
provenance remains unresolved; these byte pins do not approve production tools.
No installation, default-daemon access, image pull or production operation is
performed. All client calls have an explicit private endpoint and a fresh empty
client configuration directory, with a clean environment. Readiness uses a fixed
read-only `/v1.48/info` request over that private Unix socket, with kernel peer
PID/UID/GID matched to the actual dockerd service. It never falls back to TCP,
ambient endpoints, CLI info formatting or client-plugin metadata discovery.

## Source constraints checked before construction

Moby source reference:
[`6430e49a55babd9b8f4d08e70ecb2b68900770fe`](https://github.com/moby/moby/commit/6430e49a55babd9b8f4d08e70ecb2b68900770fe),
resolved separately from both the reported version and the release tag. This is
source-reference correspondence, not a binary attestation.

- [`cmd/dockerd/daemon_unix.go`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/cmd/dockerd/daemon_unix.go)
  requires the explicit external containerd address to bypass ambient discovery.
  The fixture supplies it and independent storage/exec roots, namespaces and
  private gRPC/ttrpc/shim sockets. Containerd's independent restart monitor and
  CRI servers remain disabled by the existing source-only configuration.
- [`daemon/runtime_unix.go:57-65`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/daemon/runtime_unix.go#L57-L65)
  puts runc state under the explicit Docker ExecRoot and selects systemd cgroups.
  A fixed custom runtime names the pinned `/usr/bin/runc` directly, without
  runtime arguments or a generated shell wrapper.
- [`daemon/oci_linux.go:775-805`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/daemon/oci_linux.go#L775-L805)
  constructs a task scope from the systemd driver and the container's cgroup
  parent. The fixture independently requires the actual Docker task scope to be
  a sibling of both daemon services inside the dedicated slice.
- [`daemon/daemon.go:1450-1453`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/daemon/daemon.go#L1450-L1453)
  passes the explicit ExecRoot to libnetwork;
  [`libnetwork/config/config.go:119-125`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/libnetwork/config/config.go#L119-L125)
  documents the Linux network-namespace base-path override. Merely selecting a
  different Docker data root would not isolate all runtime resources.
- [`container/container.go:49-51,190-191`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/container/container.go#L49-L51)
  names the persisted object/config files. The fixture reads only its own known
  full-ID host configuration after killing the first runtime. This is **not** an
  offline validator or adoption permission for arbitrary existing Docker roots.
- The inspected boot path in
  [`daemon/daemon.go`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/daemon/daemon.go)
  chooses restart candidates with `AutoRestart && ShouldRestart()`. HTTP
  authorization does not fence that path. The fixture therefore requires
  restart-disabled policy from its first create and observes the same object
  after a cold runtime relaunch; it never treats a returned CLI as drain.

## Required bounded observations

1. Exclusively create a root-owned 0700 root with an exact run/attempt ownership
   marker and four exact transient service names (two runtime invocations).
   No preexisting root, unit or domain is adopted. Runtime units have a bounded
   lifetime; the Actions job, fixture process and always-cleanup step also have
   explicit limits. Nothing persists as a staging/preview runtime.
2. Use vfs storage, private mount/network namespaces, bridge `none`, disabled
   iptables/ip6tables/forwarding/masquerading/userland proxy, no live restore and
   no Swarm workload. Mask access to the default runtime sockets/storage within
   the fixture services. No host daemon is queried or stopped.
3. Import a tar made solely from the exact-head static inert probe and empty
   mountpoint directories. No Dockerfile, external base image, registry access,
   non-fixture host bind, privileged task, process capability or exec API is used.
   Three read-only binds expose only freshly constructed synthetic auth/config/
   empty-plugin roots, never repository, host configuration, credentials or sockets.
   The task has network `none`, no-new-privileges and bounded PIDs.
4. Create without starting. Observe the full container/image ID and exact
   restart `no`/zero-retry, non-auto-remove isolation settings **before start**.
   This is observed fixture metadata, **not durable host registration**.
5. After the explicit fixture start, require actual parent/TERM-ignoring child
   readiness, sibling task placement, the exact five-process recursive source
   witness, independent live pidfds and pinned executable bytes/memberships for
   dockerd/containerd/shim/task/child. Kill the descriptor-bound slice, require
   all original deaths, source witness agreement and explicit kernel emptiness.
6. Read the fixture's persisted restart policy and full-ID inventory before
   relaunch. Launch new exact transient runtime units against the same private
   data, without calling any container start API. Require the same object/image
   to be stopped with PID 0, restart count 0 and no containerd task. Reobserve it
   and the original dead pidfds; the old task scope must not reappear. Repeated
   reads are only point observations, **not continuous execution exclusion**.
7. Independently clean up in `finally` and an Actions `always()` step: validate
   exact ownership, recursively kill only the exact domain, stop only its known
   units/slice, require domain removal and no remaining mounts before deleting
   the private root. Uncertain mounts retain evidence and fail; no lazy unmount,
   shared cleanup or prefix sweep is allowed. Hosted runner retirement remains
   the native bound after cancellation/failure.

## Synthetic restoration and exact old-object restart

Actions runs a second, explicitly hosted `--recover` invocation after the original
cold-runtime witness. The default invocation and its assertions are unchanged.
Each invocation keeps its original 90-second deadline; no recovery operation
renews it. Both use the same exact ownership/cleanup checks, and neither leaves
an idle environment. The new path is authored, pending exact-head Actions.

The recovery invocation retains a real flock on its private baseline directory.
Its owner fields are synthetic fixture inputs, not authenticated manager authority.
After all five original processes are dead and the runtime domain is empty, it
restores the deliberately damaged roots with the actual `WriteSetRecovery`.
Fresh independently opened verifier handles compare every root and metadata,
including unrelated providers, config/Compose and plugin inventory.

Before relaunch, the recovery invocation now runs twelve restoration faults:
EIO and ENOSPC at each create, write, file-fsync, rename, directory-fsync and
readback hook. Every case damages a synthetic unrelated-provider file, requires
exactly its intended hook and errno, and rejects any yielded restoration receipt.
A new restoration context then retries and a separately opened full verifier
must confirm all three roots. The original pidfds remain dead, the original
runtime domain empty and the task scope absent before/after every fault and
retry; boundary loss prevents the next retry. No task or daemon is launched by
the fault helper. The normal final restore, cold-start assertions and fresh
pre-start check still follow, within the unchanged original deadline.

These are injected exceptions at real filesystem publication hooks while actual
runtime-death observations are held, not induced kernel/device faults, process
crashes during restoration, terminal-journal faults or continuous writer exclusion.
Five component methods cover exact matrix completion, pre-mutation boundary loss,
early same-errno errors, skipped injection and loss before retry. They and the
extended native matrix require new exact-head Actions evidence before PASS is
claimed. The preceding restoration/restart drill passed on
[`3f619b63` Actions 42361044303](https://github.com/TogetherWeOwn/CLIProxyAPI/actions/runs/42361044303);
that result does not verify these new assertions.

After the original cold-start assertions prove that the same object remains
stopped, a fresh complete filesystem observation precedes an explicit start of
that exact original inert object. No new object or image is adopted. A new live
process witness binds its actual task PID/root/executable; complete baseline bytes
and kernel read-only flags are checked again through that task's mounted root.
The old process witness must remain dead throughout.

This is a concrete restoration/restart drill, **not executable operational
recovery/resume acceptance**. The inert probe is not CLIProxy or the Meta plugin;
its persistent marker cannot establish application readiness. The path reports
`operational_readiness_verified=false`, `executable_resume_implemented=false` and
`operational_recovery_accepted=false`. It does not implement original-arm journal
resumption, cross-boot/expired continuation, a complete activation/writer fence,
registration/drain, semantic start authority, package attestation, replay drain or
measured recovery phase caps. Installed entrypoints remain deny-first. A passing
test of this path cannot close those gaps or the outstanding integration findings.

## Initial reached fixture failure and correction

Exact `d6dd64e8fd6bd075265538ecede13942c9730e8f`,
[Actions 42133748379 Docker job](https://github.com/TogetherWeOwn/CLIProxyAPI/actions/runs/42133748379/job/127616544646),
failed before image import/object/task creation. Both private daemons started,
but the first formatted CLI info call exited 0 with empty server fields and an
explicit `ServerErrors` connection-refused entry. The unchanged effective-input
assertion refused it; cleanup removed the exact domain/root and the independent
always step confirmed absence. This is not a Docker containment result.

The pinned Docker CLI
[`info.go:83-123`](https://github.com/docker/cli/blob/b8034c0ed70494a90c133461d145cd072d920d7c/cli/command/system/info.go#L83-L123)
collects client/plugin metadata and returns the formatter result even after a
server error. The raw initial output includes the discovered buildx/Compose
metadata. The corrected readiness path avoids that discovery entirely and uses
the private read-only HTTP endpoint with kernel peer checks. Only a missing or
not-yet-listening socket retries within the original fixture deadline; wrong
peers, malformed/effective inputs, timeout and server errors refuse. Task,
policy, cold-start, executable/death and cleanup assertions are unchanged.
The first correction, exact `a6800d6362b75739bbf25b78d1978810e1ae4f4d`,
[Actions 42134404762 Docker job](https://github.com/TogetherWeOwn/CLIProxyAPI/actions/runs/42134404762/job/127618762939),
reached the actual peer but failed on connection reset: daemon logs independently
show plugin-manager startup trying to create `/run/docker/plugins` beneath the
inaccessible host path. Both cleanup paths again passed, before image/object/task
creation. The failure was not retried or hidden as transient readiness.

Pinned [`daemon/daemon_linux.go:24-29`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/daemon/daemon_linux.go#L24-L29)
explicitly makes Linux plugin execution use a static path instead of ExecRoot;
[`plugin/manager.go:96-103`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/plugin/manager.go#L96-L103)
creates that directory even without configured plugins. The next correction
therefore masks `/run/docker` with a fresh **service-private** 1 MiB tmpfs
(`nosuid,nodev,noexec`, mode 0700), never exposing or modifying the host directory.
The default Docker socket/storage remain inaccessible; containerd still cannot
access the host plugin path. Before creating anything, the fixture independently
checks dockerd's actual mountinfo for the single private noexec tmpfs. The mount
vanishes with its service namespace; no host unmount/permission relaxation is
introduced. Eight pure fixture methods are authored, not locally run; corrected
native qualification remains pending exact-head Actions. No production bug
red/green or approved provenance follows from these fixture corrections.

Exact `8459b1cc7b63f3a2f6409af556b40989aa76f9f1`,
[Actions 42134868063 Docker job](https://github.com/TogetherWeOwn/CLIProxyAPI/actions/runs/42134868063/job/127620331738),
reached private HTTP readiness, then failed the plugin-mount isolation assertion
before image/object/task creation. Both Docker cleanup paths passed. The old
fixture did not log the rejected mount record, so the precise mismatching field
is not established. Full Go/race/build/manager/containerd/inventory passed;
components were canceled with their private-bus and cleanup steps skipped. The
workflow conclusion is canceled, not a complete qualification pass.

Versioned [systemd v255 namespace setup](https://github.com/systemd/systemd/blob/v255/src/core/namespace.c#L2117-L2120)
defaults to `MS_SHARED` when no mount-propagation flag is specified. Its later
recursive slave setup prevents outward propagation, but `PrivateMounts=yes`
alone does not promise that the mount has no shared peer group. The correction
explicitly requests `MountFlags=private` for dockerd, retaining the strict
no-shared/noexec/tmpfs assertion. It also logs the exact plugin mount records
before validation and independently requires a different mount namespace from
the fixture. This source-grounded prerequisite correction is pending Actions,
not a verified diagnosis of the unlogged field or permission to weaken the
isolation check. A new scripted argv method checks the explicit policy; it is
not native qualification. No local tests or manager operations were run.

## Kernel read-only mount observation

The captured task-pidfd/root path also exercises the mounted-baseline reader's
`require_readonly_mount` primitive on actual kernel descriptors. An independently
checked writable task root must be rejected even when opened with `O_RDONLY`;
Docker's independently checked read-only `/sys` mount must be accepted. No mount,
remount, host bind, task exec or permission change is introduced by these controls.
New assertions require a completed exact-head Actions job before claiming PASS.

The complete mounted-baseline observer now checks `fstatvfs().f_flag & ST_RDONLY`
on each approved destination before scanning its files, and on both the retained
and freshly reopened destination after that scan. It repeats these barriers after
observation-record publication. Approved `RW=false` metadata, read-only descriptor
access and matching file bytes cannot substitute for the kernel mount flag.
Synthetic unit fixtures explicitly script this VFS result; same-inode remount and
VFS-error negatives do not claim an actual remount drill. The native positive
control is `/sys`. The separate complete synthetic-baseline integration below
requires its own exact-head Actions result; the primitive check alone is not it.

## Complete synthetic mounted-baseline integration

The same original five-process witness and exact full object/PID now feed
`open_mounted_baseline` and a fresh `WriteSetVerifier`, with no patched procfs,
VFS flag, file reader or manager mapping. `docker_baseline_fixture.py` exclusively
creates one run-scoped 0700 directory directly under `/` on the disposable hosted
runner. This avoids trusting `/tmp`; no existing ancestor permission or ACL is
changed. Its exact runtime-root ownership marker is required for cleanup. Both
cleanup paths remove this directory only after the owned runtime domain has been
terminated/removed and mounted paths in the cleanup namespace have been refused.
Uncertain cleanup fails rather than adopting another directory or unmounting it.

Only its three synthetic source directories are bound into `/baseline/{auth,
config,plugin}` with read-only default-private binds. Docker's complete mount
projection and exact bind arguments are independently compared before start,
while running and after cold startup; arbitrary or extra bindings refuse. The
baseline contains nine synthetic Meta records (seven disabled/two enabled), an
unrelated provider, nested unrelated binary bytes/mode, config/Compose bytes and
an empty plugin root. The aggregate and per-root baselines are saved by the actual
source inventory/durability code. The observation reads all roots through the
captured task's procfs root, compares complete bytes/metadata/inventories, and
requires actual kernel readonly flags before and after scanning and after yield.

A second observation reaches its yield, then changes the nested unrelated file
through the fixture's writable host alias. Its trailing scan must reject. This is
an actual byte-drift counterexample, not a mount/remount drill or proof of writer
exclusion. The default cold-runtime fixture does not repair that synthetic drift
or start another task. The separate `--recover` invocation below does both.
Successful synthetic correspondence must retain `start_authorized=false` and
`plugin_readiness_verified=false`. The original intent/approvals/authority remain
diagnostic inputs: no installed supervisor lock, registered-object authority,
semantic/image/plugin/readiness oracle or integrated recovery is supplied. All
new assertions require completed exact-head Actions before claiming qualification.

Initial `0a5a61b159ed2eaa319e85eff9c3f5deb8b50f96`,
[Docker job](https://github.com/TogetherWeOwn/CLIProxyAPI/actions/runs/42344325112/job/128318661358),
reached both the positive complete mounted-baseline receipt and the post-yield
host-alias drift refusal, but **FAILED** the original 90-second fixture deadline
before its final recursive kill. Both cleanup paths passed. This is not a native
job PASS or recovery result. The complete raw failure is retained.

The correction replaces repeated per-file Docker CLI launches with fixed read-only
`/v1.48/containers/{full-id}/json` requests over the explicit private Unix endpoint.
Every observation retains kernel peer PID/UID/GID and original manager unit/PID/
invocation/active-state checks before and after the bounded response. Reconnection
repeats the same peer/manager checks; no ambient endpoint is allowed. Complete
object/image/restart/mount policy and task PID are still checked at every barrier;
whole-daemon CLI inventory checks surround the composed baseline observations.
The connection is closed before the kill and on every exit. The original 90-second
deadline, all baseline/death/cold-start/cleanup assertions and operational denies
are unchanged. Four additional scripted protocol/binding methods are authored,
not locally run; corrected exact-head Actions must still verify this change.

Exact `1be31a098793267986628a76fbcd25f0198f0730`,
[Docker job](https://github.com/TogetherWeOwn/CLIProxyAPI/actions/runs/42344691913/job/128319776509),
again failed before completing the original deadline. It emitted the positive
mounted-baseline receipt, then refused entry to the second observation before
its drift injection. The final assertion was `baseline drift did not reach
trailing mounted observation`; no reached drift-negative PASS is claimed on
that head. Both exact cleanup paths passed. The observer intentionally masks
its inner exception, so the raw trace alone does not identify that exception.
The retained command log does establish the remaining process amplification:
5,846 MainPID, 5,844 InvocationID and 5,845 ActiveState `systemctl show` launches,
with the final reads and cleanup at the 90-second boundary. Replacing Docker CLI
inspection alone did not remove those repeated manager process launches.

The next fixture correction samples the same three manager properties with one
explicit `systemctl show` invocation per barrier, without caching, skipping a
barrier or changing the 90-second deadline. Exact keys/values are required;
missing, duplicate, malformed and unexpected fields refuse. Original fixture
clock/domain checks run both before and after the query. Socket-peer, full
object/image/policy/mount/PID and whole-inventory checks remain unchanged. One
focused synthetic-cost regression fails on the earlier three-process reader and
passes on the batched reader; this demonstrates command amplification, not native
timing or the masked exception. Three additional schema/freshness/deadline methods
are authored for Actions, not locally run. Exact-head Docker and full CI must
verify that the corrected fixture reaches the drift, kill and cold-start checks
within its unchanged deadline; no native PASS or complete-fence claim is made by
the focused result.

This is a mount-local point observation. It does not prove that nested mounts,
other writable aliases, future remounts or privileged writers are excluded. The
independent writer/activation fence, authenticated object/registry/installation
binding and complete baseline/plugin/readiness oracle remain required. No start
or settlement authority is added, and the receipt schema remains unchanged.

## Limits and retained gates

The original authority is a diagnostic root fixture, not an authenticated
supervisor/worker/broker installation. No production restore/start or settlement
permission is enabled. No daemon policy update, metadata repair or existing-root
adoption is tested. The fixture does not prove complete activator/writer/actual
exec exclusion, all-job retirement, old epoch reconciliation, ambiguous-create
registration, complete pending drain, reboot or an independent restored-baseline
and readiness oracle. It has no replay producer, credential or live probe.
Positive recovery phase caps, full-package fault/timing/replay-source completeness
and all native/security/release gates remain due. Fixture duration is neither
accepted downtime nor a production recovery ceiling.

REA angle: reuse the exact shipped Moby configuration, runtime, cgroup and boot
restore source paths and the existing pinned containerd fixture. No new paid
service, installer, binary reverse engineering or shared-daemon experiment.
