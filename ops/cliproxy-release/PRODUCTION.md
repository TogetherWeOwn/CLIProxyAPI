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

## Disposable proof

Run `CLIPROXY_FIXTURE_GATE=<built-gate> python3 -ESB ops/cliproxy-release/test_production.py`.
Set `CLIPROXY_FIXTURE_CADDY` to a Caddy executable to use two Caddy processes
for the ingress hops. The fixture exercises both hops, direct HTTP and RESP,
one blocked writer, candidate health failure, a real process replacement, client identity, gate restart and rollback of a
stopped candidate with synthetic OAuth and KV files. The
fixture releases its own loopback listeners and processes on exit.
