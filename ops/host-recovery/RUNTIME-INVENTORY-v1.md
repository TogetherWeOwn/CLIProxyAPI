# Disposable runtime prerequisite inventory v1

The Actions `recovery-runtime-inventory` job records the exact source revision,
kernel release/architecture, PID1 name, cgroup filesystem type, and hosted-image
`dockerd`, `containerd`, `containerd-shim-runc-v2`, `runc`, Docker CLI, `ctr` and
systemd executable paths, SHA256 values and local `--version` output. For the six
Go executables it also records `go version -m` build/module metadata, using the
explicit setup-go reader with its path, version and before/after SHA256. The
reader must be in the hosted tool cache or standard Go installation, owned by
root or the runner, and not group/world writable. It inspects bytes, not by
loading the target program. Go environment-file/workspace lookup, automatic
toolchain selection and module proxy/checksum services are disabled. It does not contact any daemon,
inspect workloads, discover sockets, change the host, install dependencies, or
start/stop a unit. There is no runtime provisioning or cleanup to perform.

The script runs only on the disposable hosted Actions image, under an empty
environment and fixed system PATH. Missing tools, unexpected executable locations,
non-root-owned or group/world-writable binaries, version-command failures and
changed before/after binary hashes fail the job. Each version command and the
whole inventory have explicit execution limits. A missing tool does not stop the
remaining tool inventory; an unexpected shell/read failure may leave an incomplete
log and a failed job. The `always()` artifact step retains that raw log either way.

**A successful inventory is not qualification.** The Ubuntu runner image floats;
version strings and observed executable hashes do not authenticate a full source
revision, package import closure, loader/dependency provenance, immutable binaries
or approved runtime installation. A second execution can use different image bytes.
This output is evidence for choosing and pinning a supported disposable fixture,
not a manifest that may authorize an effect. All qualification, provisioning,
complete-fence, start and production-acceptance fields remain explicitly false.
The script does not mint or modify topology/tool/release pins. Module metadata
can omit a VCS revision or describe modified sources; even complete self-reported
metadata is not an attestation or a clean reproducible build. A zero-exit read
is not a semantic provenance verdict. The [source-resolution ledger](RUNTIME-SOURCE-MAP-v1.md)
records separately verified upstream commits and the outstanding correspondence
gaps; the inventory does not resolve abbreviated revisions over the network.

## Next qualification boundary

Use the observed identities to resolve full source provenance and select a
reviewed, pinned Docker/containerd/runc combination before qualifying the dedicated
fixture. A future runtime fixture must use fresh, exclusive storage, endpoints,
namespace, network resources and manager-owned domain. Never reuse the hosted
runner's default Docker socket, data root or active workload. If that combination
or safe isolation cannot be established, report the specific unsupported
prerequisite; do not substitute the default daemon or install unreviewed packages.

Required evidence still includes actual dockerd, external containerd, shim and
container-task containment (including sibling scopes), restart-disabled policy
from first creation, actual-execution launch authorization, activator/writer
exclusion, queued-job completion/retirement, cold teardown and quarantine full-ID
inventory/registration. Existing inert systemd fixtures and this read-only
inventory prove none of those runtime boundaries. The independent stopped-baseline,
readiness/result oracle, operational provisioning/runners, source-bound replay
drain, fault matrix and measured recovery phase caps remain separate gates.

REA angle: inspect the hosted tools' own local build/version metadata first, then
resolve it against the upstream source before selecting a runtime fixture. No paid
service, package download, shared-daemon experiment or private-source offload is
needed for this inventory.
