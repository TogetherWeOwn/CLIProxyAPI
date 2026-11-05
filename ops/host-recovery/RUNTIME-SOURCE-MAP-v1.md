# Disposable runtime source-resolution ledger v1

Status: development prerequisite, **not an approved runtime/tool manifest**.
No installation, daemon contact, package download, start grant or release-pin
change is authorized by this ledger. Existing operational denies remain.

## Observed identities and upstream resolution

The read-only hosted inventory at source
`055678d3f0aaea617cee15280a8649990fa4207c`, [Actions run
42112291827](https://github.com/TogetherWeOwn/CLIProxyAPI/actions/runs/42112291827),
reported the identities below. Public upstream commit and release-tag lookups
were independently compared on 2026-11-05; both lookup routes resolved to the
same full commit in each row. These are source-reference matches, **not proof
that the observed executable was built from that source**.

| Executable | Observed version/build | Upstream release tag | Resolved full source commit |
| --- | --- | --- | --- |
| dockerd | 28.0.4 / 6430e49 | moby/moby v28.0.4 | [`6430e49a55babd9b8f4d08e70ecb2b68900770fe`](https://github.com/moby/moby/commit/6430e49a55babd9b8f4d08e70ecb2b68900770fe) |
| Docker CLI | 28.0.4 / b8034c0 | docker/cli v28.0.4 | [`b8034c0ed70494a90c133461d145cd072d920d7c`](https://github.com/docker/cli/commit/b8034c0ed70494a90c133461d145cd072d920d7c) |
| containerd | v2.4.2 / b7a25261e029d68978bbf290df0a62fc819b3c51 | containerd/containerd v2.4.2 | [`b7a25261e029d68978bbf290df0a62fc819b3c51`](https://github.com/containerd/containerd/commit/b7a25261e029d68978bbf290df0a62fc819b3c51) |
| runc | 1.5.2 / v1.5.2-0-g29dd3dc2 | opencontainers/runc v1.5.2 | [`29dd3dc2b13b4123162e5fe132504bb4b15569f1`](https://github.com/opencontainers/runc/commit/29dd3dc2b13b4123162e5fe132504bb4b15569f1) |

`ctr` reported v2.4.2 without a commit. The shim was not inventoried in that
revision. Do not assign either the containerd commit merely because they usually
ship together. The next inventory includes the shim and the embedded Go build
metadata of each executable; missing or conflicting correspondence remains
unresolved. The inventory records metadata, not a provenance approval.

Systemd reported `255 (255.4-1ubuntu8.18)`. Prior v255 source references explain
tested interface semantics, not the entire Ubuntu patched package. Exact distro
source/package/dependency correspondence remains unverified. Neither the runner
image nor these runtime binaries have been selected as immutable approved
production artifacts. Existing observed hashes do not establish authenticity,
loader/import closure, reproducibility or compatibility of this combination.

## Exact-source seams that the disposable fixture must cover

Read source at the commits above before using a current-version example or a
previous 1.7.x containerd reference. The following findings constrain the
fixture; they do not implement its controls.

1. **Explicit external containerd is mandatory.** Moby's
   [`initContainerd`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/cmd/dockerd/daemon_unix.go#L117-L123)
   bypasses discovery only when `ContainerdAddr` is nonempty. Otherwise
   [`initializeContainerd`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/cmd/dockerd/daemon.go#L1033-L1054)
   may reuse the system socket or start managed containerd. A fresh Docker data
   root alone therefore does not establish a dedicated runtime. Supply the
   exclusive endpoint explicitly, inspect the effective configuration and refuse
   absence or drift before any daemon effect. No default-socket probe is needed.
2. **A container task need not live in the daemon service's cgroup.** Moby's
   [`withCgroups`](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/daemon/oci_linux.go#L775-L805)
   computes `Linux.CgroupsPath` from the selected driver and container/daemon
   cgroup parent. The fixture must independently observe actual task placement
   and contain sibling scopes under the dedicated domain. An inert child of
   containerd is not an equivalent task witness.
3. **Shim placement is a separate option.** Containerd's pinned
   [runc options](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/api/types/runc/options/oci.proto#L7-L27)
   define separate `shim_cgroup`, runc `root`, `binary_name` and
   `systemd_cgroup` settings. Its actual
   [shim launch](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/cmd/containerd-shim-runc-v2/manager/manager_linux.go#L253-L289)
   starts the shim and can then move it to the supplied cgroup. Process ancestry
   alone cannot stand in for observed shim/task cgroup identity. Inventory and
   bound the actual selected shim/runc executables, task options, runtime state
   root and socket directory; do not inherit global defaults.
4. **Containerd has its own restart actor.** The pinned
   [restart monitor](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/plugins/restart/monitor.go#L43-L80)
   registers a periodic reconciler independently of Docker HTTP authorization,
   with startup handling for `always` objects. The exact plugin identifier is
   `io.containerd.monitor.container.v1.restart`, using the pinned
   [plugin type](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/plugins/types.go#L43).
   The older `io.containerd.internal.v1.restart` appears in migration code; do
   not assume an old disable list controls the current actor. A future fixture
   must verify its effective plugin policy and independently examine all
   namespaces/objects/tasks. Docker `restart=no` alone is insufficient.

## Selected next implementation boundary

Use these exact source references to develop the existing Actions-only dedicated
runtime fixture. This selects source for inspection, **not approval to execute
unresolved binaries**. Before a daemon fixture runs, record the same-run observed
executable hashes/build metadata (including shim and clients), resolve or reject
identity differences, and bind the fixture's supported combination explicitly.
Never silently follow the floating runner image or convert new observed hashes
into accepted pins. Missing correspondence is a prerequisite, not permission to
install another combination or reuse the default daemon.

The fixture needs exclusively created roots, endpoints, namespace and
manager-owned domain, no live mounts or registry credentials, no registry/image
pull, bounded startup/readiness, and exact owned-resource cleanup even on failure
or cancellation. Any required runtime configuration/install or unsupported
isolation control must be routed before execution. The first real daemon result
will still be component qualification, not complete host-recovery acceptance.

Complete launch/activator/writer exclusion, manager-job retirement, durable
registration/ambiguous creation, cold/quarantine reconciliation and pending
drain remain unfinished. Independent restoration/start/readiness/result
verification, authenticated provisioning, operational runners, reboot/replay
source completeness, fault/timing matrix and positive measured phase caps remain
separate gates. No runtime startup, source lookup or metadata read clears them.

REA angle: use the shipped tools' own build identifiers and the exact public
upstream source to identify discovery, cgroup migration and restart actors before
attempting a dedicated fixture. No opaque-binary reverse engineering, paid
service or shared-daemon experiment is required.
