# Protected first adoption

Use this operation once to move the installed tag-based Compose service under
the release gate using the **rollback** image and library set from the
approved staged pair. Forward release stays a separate protected
`deploy`. Before a forward attempt, `undo-adoption` restores the original
Compose and ingress layout. A subsequent version rollback uses `rollback`
and retains the gate and pinned Compose layout.

## Bind before dispatch

Use the host and workflow binding in [Production](PRODUCTION.md). Install
`adoption.py`, `legacy_compose.py` and `adoption_ingress.py` from the reviewed
workflow commit with the production controller. Leave
`CLIPROXY_FIRST_ADOPTION_ENABLED` unset until the site binding is ready.
Install root-only `adoption-approved.json` beside the existing allowlist with
`machine_id`, `workflow_sha`, `bundle_sha256` and `binding_sha256`. The last
field is the SHA-256 of the root-only `adoption.json`. The regular allowlist
still applies. Prepare the binding outside the mutable service paths.

In that binding, pin the legacy container ID and exact start, its existing
Compose project, service, tag, rendered hash, source Compose and config
hashes, publishes and networks. Pin the original Caddy files, their
replacement files and both proxy service plans. Include the live auth bind
and KV path identities. Use `LegacyCompose` for legacy readback and
recreation, `IngressFile` for reversible file changes and the usual
`ComposeAdapter` for the pinned baseline. Keep the old files and tag
available for undo. Reconcile the tag with the immutable image before
restoring it. The adapter never writes an auth or KV backup over current
state. The writable legacy library tree may have the runtime's `.shadow`
cache. Pin the full platform input set. Leave pinned release files read-only
and verify that their effective auth directory and KV path match legacy.

The site's root-owned `adoption-adapter` receives only a fixed verb, bundle
digest and binding digest. Check both digests on every call. Keep a
recoverable local record of any partially applied host operations. A timeout
or failed Docker command requires a fresh local reconciliation before
retrying. The protected unit owns the transaction even if SSH disconnects.

| Verb | Required result |
| --- | --- |
| `legacy` | Read-only preflight confirms the authorized running legacy container, original ingress and verified undo files. Verify that the site can prove legacy quiescence and can restore both layouts while ingress stays closed. |
| `isolate` | Establish a host-side barrier that covers the old loopback publishes, the Docker bridge paths, both Caddy routes and callback ports. Drain existing work and verify the queue and writers before stopping the exact incumbent. Leave its stopped container for Compose to replace. Bring up closed gated ingress. |
| `isolated` | Read back both Caddy routes and direct paths through the same closed gate. Verify that the original sockets and the private backend have no bypass. Check stable auth and KV mount identities and the current writer barrier. |
| `serving` | After the gate opens, verify forwarding through both Caddy routes and direct HTTP, authenticated Keeper HTTP and RESP, and the expected callback behavior. Failure triggers protected undo. |
| `undo-isolate` | Re-establish the site barrier after any partial operation. It must cover both layouts, including a missing or restarted gate. Preserve the connections needed to finish admitted work. |
| `restore` | Reconcile pending Docker work and drain canceled or asynchronous work and remaining queue records. Close gate front listeners that occupy legacy addresses. Restore the original Compose service, files and both running Caddy configurations while admission stays fenced. |
| `resume` | Verify the restored image, mounts and topology, and health through both ingress paths, direct callers and Keeper using the private observation path. Reopen the site barrier only after those checks. |

Bind direct HTTP on the original host port and the shared bridge alias. The
front and private backend can use separate networks, with only the gate
able to reach the backend from client networks. Pin the gate peer in the
startup config. Use the trusted ingress socket for both Caddy instances.
Preserve their TLS, auth and routing rules. The five loopback OAuth
publishes can move to the gate with repeatable
`-callback <loopback-address:port>=<backend-port>` options. Account for
callbacks that are started dynamically. Route Keeper HTTP through the gate
and bind its RESP destination to the separate restricted lane. Preserve its
data, current authentication policy and ability to consume usage.

A socket count, a gate count or a quiet time window alone is insufficient
for the legacy v8.0.63 service. Its HTTP shutdown closes handlers immediately.
Use current evidence that pre-gate work, canceled handlers, OAuth sessions,
plugin and config apply work, and background usage producers have finished.
Keep authenticated Keeper consumption available long enough to reconcile the
old queue before closing that lane. Its pop is destructive. Never discard
records as an emptiness probe. Account for host lifecycle automation and
operators who can write release files. If the incumbent has no trustworthy
way to establish these conditions, leave the first-adoption opt-in unset
until the release task has resolved the capability gap.

## Recover

Dispatch `undo-adoption` through the same workflow if an interrupted attempt
cannot be confirmed. It uses the original bound bundle and manifest and
remains available if the adoption opt-in is withdrawn or protected main has
advanced. Check the local journal and pending Compose records under the release lock. A
`validated` record means the pinned gateway and closed ingress passed but
opening admission and forwarding were not confirmed. Use protected undo
to recover that state. A failed journal write during recovery leaves the
controller attempting both fences before returning the failure. Automatic undo returns a failed workflow result even when the
legacy service was restored. An incomplete undo keeps admission fenced. An
attempted forward release takes over recovery through the pinned baseline.
An `undone` record ends that adoption attempt. To authorize a fresh attempt,
first disable the adoption opt-in, verify the complete restored layout
and absence of pending Compose work, then archive the old record under
the release lock and install a fresh approval for the currently authorized
incumbent and binding.

Keep GitHub, protected SSH, the release service and observation independent
of the gateway. Apply the normal exact-build staging, release review and
30-minute observation requirements when enabling this change in production.

The fixture workflow exercises the transaction and ingress file checks with
synthetic state. Where the staged bundle is already present, run
`test_exact_adoption.py` with the built gate, `CLIPROXY_FIXTURE_CADDY`, and
the local `CLIPROXY_FIXTURE_BUNDLE` and `CLIPROXY_FIXTURE_BUNDLE_SHA256`.
Load the verified baseline image into the local Docker store first. The
fixture uses task-scoped Docker resources, synthetic auth and KV, and a
synthetic Meta upstream. It exercises pinned readiness, failed validation
and tag-layout restoration without the production site's writer controls.
