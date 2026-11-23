# Protected gateway restart

The **CLIProxy production restart** workflow is manual and main-only. It is
dormant until the release task installs the binding and sets
`CLIPROXY_PRODUCTION_ENABLED=true` in the repository. Keep
`cliproxy-production` restricted to `main`. Use the exact ZIP digest from the
successful [staging run](STAGING.md) as the pair identifier. The release task
owns approval, activation and the 30-minute watch of health, errors, restarts
and incomplete streams. Use the workflow's `rollback` action on a regression.

## Bind the workflow to one target

Use the existing target's SSH service, or an existing private transport that
presents that same pinned SSH endpoint to the hosted runner. The environment
provides `CLIPROXY_LIFECYCLE_HOST`, `CLIPROXY_LIFECYCLE_HOST_KEY` (one
`ssh-ed25519` public host key without a comment), and
`CLIPROXY_LIFECYCLE_SSH_KEY` (a dedicated deployment identity). The client
requires that host key and sends only the action, workflow commit and ZIP
digest. Deliver the verified images and libraries privately to the target.

Use a dedicated `cliproxy-release` login with a root-managed authorized key
and OpenSSH `restrict,command="/usr/bin/python3 -IB /etc/cliproxy-release/production.py submit"`.
Give it passwordless sudo for the root-owned `/etc/cliproxy-release/queue`
alone. The helper rejects all args other than the two literal actions and
hexadecimal identities. Install `production.py`, `queue` and the local
`adapter` under the root-owned directory, inaccessible for writes by the
SSH login. Store the SHA of the deployed main workflow and exact staged ZIP
digest in `/etc/cliproxy-release/approved.json` as `workflow_sha` and
`bundle_sha256`. The host checks this allowlist again under the release lock. Forward requires
the approved workflow SHA. Rollback stays confined to the approved pair and
the local transaction state so it remains available if protected main advances.
Create root-only `/var/lib/cliproxy-release` for the lock and transaction
record. Keep one installer's controller and gate-control identity per target.

Systemd owns the bounded transaction after submission. If the runner loses
its connection, check the unit and local transaction record before dispatching
again. The host refuses replay of a forward action after the pair has reached
its mutation phase. An interrupted replacement leaves admission closed.
Submit `rollback` through the same workflow to recover an interrupted change.

## Put every path behind the release boundary

Build with `go build ./ops/cliproxy-release/gate` from the repository root.
Run the gate independently of the backend. Its listeners share one
admission counter. The direct HTTP listeners accept explicit loopback or
private IPs and derive the client IP from the connection, ignoring client
identity headers. The control socket defaults closed on each new process
generation. Use `/run/cliproxy-release/gate.sock` in a gate-owned 0700
systemd runtime directory. On clean stop the gate removes its own sockets.
Have the serving unit's runtime directory lifecycle remove stale sockets
after a crash.

Route Caddy through the separate `-trusted-ingress` Unix socket in a
gate-owned mode 2750 directory with a group limited to the two authorized
proxies. In both Caddy upstreams overwrite `X-CLIProxy-Client-IP` from
Caddy's trusted client IP, for example `header_up X-CLIProxy-Client-IP
{client_ip}`. The gate accepts a single IP on that socket only, forwards it
as `X-Forwarded-For` and strips `X-Real-IP`. Retain the Caddy auth, TLS,
access logs and path rules.

Install the backend on a private endpoint that clients cannot reach
directly and pass it as `-target`. The backend must see a non-loopback
gate address. Configure both gateway phases to trust only the gate peer
for forwarded client identity. Verify that a remote request cannot become
local by sending identity headers, and that different real clients retain
separate management counters. Direct HTTP clients and the two Caddy
instances must all reach the shared gate.

CLIProxy also serves RESP on its HTTP port. Put the usage consumer's RESP
connection on a separate restricted `-resp` listener, with no alternate route
to the backend. This listener admits only RESP command arrays and counts
the entire connection. The gateway authenticates RESP using the TCP peer,
so the usage consumer remains a remote management client on this binding.
Use the existing remote-management policy and Keeper credentials. If the
gateway requires a loopback peer for Keeper, this binding cannot serve it.
Do not enable remote management to make the restart work. Quiesce the usage
consumer and reconcile its queue before restarting, then verify that it can
authenticate and resume consumption. HTTP/1 keep-alive requests each pass admission. Active streaming
responses and HTTP upgrades keep their slot until the proxy handler returns.
Read back gateway-side work as well when client cancellation or an asynchronous
handler can outlive the proxy request. Account for any additional gateway
listeners, including published OAuth callback ports, and for requests started
before changing ingress. Establish baseline reachability and open the gate
only after the installed routes and baseline health read back correctly.

## Resolve local operations to the existing deployment

The installer-owned adapter receives only `<verb> <zip-digest> <phase>`.
It exits successfully only when it can verify the operation below. Use the
existing Compose project and exact installed runtime identities.

| Verb | Local operation |
| --- | --- |
| `prepared` | Resolve the digest to a private, local release directory, and check the phase's immutable image, executable, config and full platform library set. Check the compose, ingress identity and mount plan. Both phases use the same existing auth and KV sources. |
| `incumbent` | Read back the exact installed phase and its image, executable, config and libraries. Verify the identity of a stopped gateway from the installed binding metadata. A crashed candidate must still be eligible for rollback. Readiness is verified separately. |
| `quiescent` | Verify that all ingress reaches the gate, alternate listeners cannot admit work and pre-gate or canceled work has ended. Verify external config, plugin, mount and lifecycle writers are quiet through the switch, and management and reload work has completed. Refuse if any earlier restart can still mutate the target. |
| `switch` | Recheck the local binding, save or revalidate the untouched baseline release files, then recreate only the gateway using the selected exact image, config and platform libraries. Reuse the existing OAuth and KV mounts. Do not recreate the usage consumer, rewrite its storage, restore an old state directory, or use compose options that remove volumes or build/pull images. Return only after Compose has finished. |
| `ready` | Re-read the running identity, unchanged state mount identities, expected Meta registration and health. Run a fresh bounded probe to the private gateway with the expected model catalogue and a complete stream, without admitting general traffic. |

External host writes include operator changes to Compose, config and plugin
files. The gateway can also persist changes via management, install plugin
libraries and reload config. Use the stable gate for management requests,
check outstanding reload work in the gateway and reconcile whatever host jobs
actually have write access. A release with an unaccounted writer, a direct
backend route or an unverified restart outcome must refuse the switch.

When quiescence fails before a switch, the controller can reopen unchanged
admission if the incumbent and the same gate generation still verify. If a
candidate fails after replacement, the controller repeats the quiescence
check and restarts the incumbent using the same binding. It confirms the
incumbent before reopening, then returns a failed deployment. A failed
recovery keeps admission closed. When the gate has restarted or a command's
result is uncertain, use the journal and fresh readback before taking another
action.

### Bind the reusable Compose operations

Install `compose_adapter.py` alongside `production.py` in the root-owned
release directory. The installer supplies the executable `adapter` wrapper
and calls `ComposeAdapter` with one approved digest and the two local
`Phase` definitions. With Python isolated mode, add only the trusted
installation directory to the wrapper's module search path. Run the adapter
under the controller lock and return nonzero for any error. For
`quiescent` and `switch`, pass the result of `production.adapter_fence()`
as the `fence` keyword argument. The controller supplies the expected
generation and epoch in the wrapper's sanitized environment. The adapter
checks that fence against the real gate and separately requires site
quiescence. Keep the binding, Compose files, runtime config and probe
credentials private on the host.

Before constructing the binding, verify the ZIP digest and use
`staging.unpack` and `staging.verify_image` to reconcile both staged phases
and their library sets. The phase directory contains a self-contained
`compose.yaml`, the phase's `config.yaml` and a flat `plugins` directory
containing the full platform set. Pin the Compose and config hashes, each
library hash, the expected Meta version and the executable hash. Use the
full local Docker image ID that resolves to the verified OCI image or its
verified config digest, as appropriate for the local Docker store. Tag
names can move. Preserve the baseline config and libraries in their own
phase directory.

Each Compose file describes only the existing gateway service under the
same project name and project directory. It uses the bound image ID and
existing private bind mounts in long syntax with `create_host_path: false`.
Declare any existing networks as external. Record the canonical source,
target, read/write mode and device/inode for the stable mounts, including
OAuth and KV, once when installing the binding. Persist these identities
across invocations. Point the phase-specific config and library binds at the
phase's own files. Both are read-only by default. If the site enables writes
to either, reconcile their bytes before certifying exact phase identity.
Retain the baseline's Compose ownership and service labels. The installed
gateway must already match the pinned baseline's Compose service hash and
mount plan. If it was started from a tag or with different bind sources,
reconcile and adopt the baseline under the site's release procedure before
running the forward transaction. A stopped incumbent is checked using the
installed container's image, Compose labels and mount metadata. For a
running incumbent the live mount and PID 1 reads run under the gateway's
configured container user. Start PID 1 as that user.

The wrapper must verify the site's ingress and trusted-peer plan for
`prepared`. Supply a read-only `check_quiescence(digest, phase, gate_state)`
that returns literal `True` only with current evidence of the actual site's
conditions in the verb table. It runs at the controller check and again
immediately before replacement. The adapter also requires the controller's
closed, empty gate generation and epoch. Install the pending-operation record under the
controller's root-only state directory, scoped to the gateway service
across both phases. A timeout, interrupted client or unconfirmed Compose
result leaves that record in place. Reconcile the Docker operation and
container state under the release lock before clearing it or trying another
switch.

Supply a fixed private probe command. It receives the verified container ID,
ZIP digest and phase, and must verify that its endpoint is that container.
Use the `check` function in `staging_probe.py` with a site's private request
function and expected Meta model. It checks health, the catalogue and a
fresh stream through its terminal event. Keep credential material off the
command line. The adapter bounds the probe to 25 seconds, checks the Meta
registration for the current start and confirms the gateway stayed on the
same start before returning readiness. Verify during `prepared` where both
phases emit the registration. By default the adapter reads the last 2,000
Docker log lines from the current container start. For file logging or a
different sink, supply a bounded `read_registration(container, started_at)`
reader that returns only bytes from that exact start. The adapter still
checks the expected Meta version. The controller reopens admission
after readiness and its final gate readback.

Live installation still needs the protected SSH route, the Caddy and direct
client paths, Keeper and its queue, OAuth callbacks, and verification of
actual config, plugin, reload and lifecycle writers. Resolve those site
dependencies with the release task before enabling the workflow.

## Disposable proof

Run `CLIPROXY_FIXTURE_GATE=<built-gate> python3 -ESB ops/cliproxy-release/test_production.py`.
Set `CLIPROXY_FIXTURE_CADDY` to a Caddy executable to use two Caddy processes
for the ingress hops. The fixture exercises both hops, direct HTTP and RESP,
one blocked writer, candidate health failure, a real process replacement, client identity, gate restart and rollback of a
stopped candidate with synthetic OAuth and KV files. The
fixture releases its own loopback listeners and processes on exit.

The Compose fixture uses the same controller with two locally imported
synthetic images, a separate keeper service and task-owned bind mounts.
The [fixture workflow](../../.github/workflows/cliproxy-release-preflight.yml)
shows the local build and test commands. It covers phase mismatch, preflight
refusal, an unbound verifier, refusal after the gate restarts, and a failed
Compose command that leaves a pending record. It also checks rollback of a
stopped non-root gateway with file logging and newer OAuth and KV writes,
and a hung readiness stream. The fixture exercises the production
subprocess boundary. Its verifier applies only to the disposable namespace.
