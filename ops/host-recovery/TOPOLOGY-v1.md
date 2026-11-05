# Dedicated runtime topology input v1

**Input validation only. No broker, containment proof, service installation,
recovery execution or start permission.** The unresolved supervisor and identity-only
worker remain unchanged. Shared or unknown runtimes are unsupported; HTTP AuthZ
cannot stand in for the daemon-internal restart fence.

## Source surface

`host_recovery/topology.py` defines an immutable, bounded `Topology` byte snapshot
and `load_topology(content, sha256=..., installation_id=...)`. The latter consumes
`topology.json` from the existing protected `ContentSnapshot` reader, requires
root/root content ownership, compares a separately provisioned raw SHA256, and
binds the installation identity and package source revision to the content
approval. The caller still acquires the protected index/handles, excludes writers,
retains the original installation lock, authenticates the approval and revalidates
at later barriers. Constructing a Python snapshot or supplying a matching digest
is not authentication. No adjacent digest is discovered or trusted.

All JSON objects have exact required keys. Duplicate/nonfinite JSON, excessive
size (32 KiB), unknown/missing fields, ambiguous types and unsupported choices
refuse with fixed secret-free errors. `manifest()` returns a fresh decoded copy;
callers cannot mutate the captured bytes. `status()` returns a digest and
`input_validated_only`, with provisioning, complete fence, execution, start and
production acceptance explicitly false. It never publishes topology paths,
service owners, raw configuration or secrets.

## Closed manifest shape

There is deliberately no live-path example/default. The test fixture is synthetic
and not an operational installation manifest.

- `schema`: `host-recovery-topology-v1`; `installation_id`: the existing bounded
  installation identity format, independently matched on load.
- `runtime`: installation-only ownership; **fresh-empty-only** adoption; systemd
  cgroup driver; `restart_policy=no`, zero maximum retry count, AutoRemove false;
  live restore, Swarm, external launchers, boot autostart, socket/path/timer
  activation and force restart all false. `cold_barrier=required` and supported
  metadata projection `regular_tree_v1` are mandatory. That metadata name does
  not claim Docker metadata-format support or authorize editing it.
- `runtime.slice` and `runtime.cgroup_path`: one direct dedicated system slice and
  its exact relative-to-cgroup-mount path. The first input format excludes nested
  or dash-hierarchical slices, user-manager domains and system/user/machine slices.
  `runtime.units`: distinct fixed dockerd/containerd service names and effective
  configuration digests; conventional shared service names and templates refuse.
- `roles`: distinct broker, observer, supervisor, forward and recovery numeric
  UID/GID pairs, fixed units, effective-unit and launch digests. Broker is root/root;
  every other role is nonroot with distinct UIDs and primary GIDs. Only recovery
  uses a unit template. This describes primary identities, **not proof of actual
  supplementary groups, capabilities, ACLs, containment or unit sandboxing**.
- `tools`: dockerd, containerd, runc, systemd, kernel, broker, observer and interpreter
  each require explicit bounded version, full lowercase source revision and
  artifact SHA256. Actual source-to-binary correspondence, import closure and
  installed-version qualification remain separate.
- `resources`: distinct data-root, exec-root, containerd root/state paths; private
  dockerd socket below exec-root and containerd socket below containerd-state;
  an explicit nondefault containerd namespace. Conventional shared Docker/containerd
  paths and `/var/run` aliases refuse. These are expected paths, not opened
  descriptors or a claim of exclusive runtime/network/storage ownership.
- `protected_roots`: package, approval, baseline, broker state, supervisor state and
  private worker evidence. `write_roots`: auth, config, Compose and plugin roots.
  Every directory root must be canonical, bounded and pairwise disjoint, including
  from runtime storage. The initial conservative format excludes OS infrastructure
  roots (including `/etc` and `/usr`) rather than permitting broad restoration.
  Mount aliases, bind mounts, symlinks, actual ownership and metadata require
  protected descriptor acquisition and independent qualification; lexical
  separation alone cannot prove separation.
- `pins`: full package/candidate/rollback/producer source revisions; package import
  closure, candidate/rollback images, plugin archive **and** library, producer
  schema, approved policy and baseline SHA256. Hashes describe correspondence,
  not acceptance of a new release pin or authorization to replace installed bytes.

The parser validates the selected conditional topology, not the whole deployment
or original A+B policy. Supplementary groups/socket ACLs, network isolation,
persisted runtime metadata/version support, effective manager activation graph,
actual full task/shim containment and independent approval provenance cannot be
proven by these strings/booleans. Missing proof keeps all operational denies.

## Required next boundaries

The independently provisioned privileged broker remains unimplemented. It must
consume fixed methods only, authenticate live peer/pidfd/manager invocation and
original kernel lock ownership, durably record one-shot operations before
submission, preserve ambiguous replies and use no second installation lock.

Recovery must close admission, revoke grants, stop/cancel tracked jobs and kill
all qualified dedicated slice tasks/shims/creators. Actual kernel/manager
observations must establish old-epoch death before quarantine relaunch. Protected
persisted policy provenance and complete full-ID/task inventory reconciliation
must precede a complete-fence acknowledgment. CLI death, an HTTP response, a
manifest flag or a dead dockerd MainPID is not that proof.

Only an independently pinned verifier may establish complete stopped baseline,
exact old object/deployment identity, readiness and supervisor result/settlement
facts. Existing scriptable callbacks are not proof producers. Cross-boot or
expired starts/settlement remain denied in the first vertical slice. Original
120/180/300 budgets are unchanged; cold teardown/relaunch, drain, persistence,
verification and notification costs all count.

No source was transferred, units installed/started, daemon contacted, privileges
changed, producer executed or production operation performed for these component
tests. A source-free systemd preflight does not qualify the disposable runtime.
The full dedicated-runtime fault matrix, real ingress/RPC/producer/source drain,
A+B/deployment equivalence, measured caps and integrated acceptance remain due.

REA angle: encode the inspected Moby restart policy and systemd slice teardown
constraints as closed expected input, while refusing to turn static configuration
or HTTP authorization into runtime internal-restart/drain proof.
