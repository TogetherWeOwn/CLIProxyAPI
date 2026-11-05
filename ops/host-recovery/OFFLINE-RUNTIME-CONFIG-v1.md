# Offline containerd configuration witness v1

Development prerequisite only. No daemon, shim, runc, container, manager unit,
registry client, image pull, installation or production operation is invoked.
Operational recovery/start/settlement grants remain denied.

## Exact boundary

The hosted Actions inventory job runs `tests/offline_containerd_config.py` as
non-root, with an empty inherited environment except a fixed PATH/locale and the
hosted-runner markers. It opens only `/usr/bin/containerd`, requires a protected
root-owned regular single-link file and the exact executable SHA256 observed in
[Actions 42116989500](https://github.com/TogetherWeOwn/CLIProxyAPI/actions/runs/42116989500):
`fc185d75979d92a4f8de99b76293dca7fe81142e9c5fd01d7da59f786f0fc8d1`.
This is a **diagnostic byte pin**, not an authenticated production artifact or
approved daemon combination. Drift fails the check; do not follow a floating
runner, silently repin, download a replacement or install a runtime to pass it.

A fresh private temporary directory contains an exact closed TOML input. The
only native invocation is the descriptor-bound executable with `--config
<explicit-file> config dump`, capped file outputs, a bounded process lifetime
and no stdin. Exact source validation precedes invocation. Input and executable
are rehashed/rechecked afterwards. The dump must preserve private data/state/temp
roots, separate explicit gRPC/TTRPC sockets and the exact disabled-plugin policy,
including `io.containerd.monitor.container.v1.restart`. Proxy plugins, legacy
server settings, an effective restart-plugin section and endpoint drift refuse.
Raw input/dump/stderr are retained. Warnings/nonzero exit refuse, rather than
accepting containerd's unknown-field tolerance. No runtime roots or sockets may
be created; exact private diagnostic files are removed on exit.

## Source findings which constrain interpretation

All references below use containerd source
`b7a25261e029d68978bbf290df0a62fc819b3c51`:

- [`command/config.go`](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/cmd/containerd/command/config.go):
  `dumpConfig` loads config and `outputConfig` decodes registered plugin config;
  this subcommand does not enter the main daemon action or initialize services.
- [`server/config/config.go`](https://github.com/containerd/containerd/blob/b7a25261e029d68978bbf290df0a62fc819b3c51/cmd/containerd/server/config/config.go):
  version 4 uses `io.containerd.server.v1.grpc` and `.ttrpc` plugin endpoints.
  The former legacy `grpc`/`ttrpc` sections are not assumed to supply equivalent
  current settings. The loader logs then tolerates unknown keys; the diagnostic
  therefore admits only its exact generated input and rejects native warnings.
- **Import-display trap:** the config starts with a default include glob and
  merges slices by appending. `LoadConfigWithPlugins` traverses each *input
  file's own* imports, not the final merged display. With exact source
  `imports=[]`, this load reads no imports, but the dump still displays
  `/etc/containerd/conf.d/*.toml`. The diagnostic requires that exact display;
  it does not erase it or mistake it for a traversed host file. **Never reuse
  the dump as daemon input:** then the displayed glob becomes a real import.
  Rejecting altered source before execution is essential.
- Shim cgroup, runc binary/root and systemd-cgroup options are **task-level**
  runc options, not proved by this daemon config display. Neither this diagnostic
  nor its explicit endpoint checks bind actual task/shim placement. Those need
  separate source-bound task creation, effective options and kernel witnesses.

## Verification and remaining gate

Twelve ordinary component methods cover the closed source, private paths,
endpoint/policy drift, import display, unknown inputs and malformed/duplicate
TOML. They use a synthetic projection; they do not execute containerd. The
separate hosted Actions step exercises actual config expansion at the byte pin.
Both require exact-head Actions evidence; no local suite or daemon experiment is
an alternative. Source-authenticity/provenance, supported runtime combination,
actual manager/domain provisioning, live task/shim/cgroup observation, complete
activation/writer exclusion and job retirement, cold/quarantine registration and
drain, independent restoration/readiness oracle, operational runners/full
package/reboot/replay/fault/timing acceptance remain incomplete.

REA angle: read the pinned configuration loader and command implementation
before assuming an older config format or treating the merged dump as a safe
runtime input. Reuse the installed byte-checked tool only for an offline
non-authorizing diagnostic; no new dependency or default-daemon experiment.
