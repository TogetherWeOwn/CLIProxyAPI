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
   host bind, privileged task, process capability or exec API is used. The task
   has network `none`, no-new-privileges and bounded PIDs.
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
