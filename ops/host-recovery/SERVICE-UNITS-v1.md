# Conservative manager launch definitions — v1

**Offline source, not an installed or operational recovery package.** The unit
renderer and `service_entry.py` wire only the fixed unresolved supervisor and
identity-only worker. No recovery/start permission, installer, activation command,
credential, policy exception, boot fence or daemon access is added. Do not use
these definitions to install or start services on a live host.

## Avoid a self-referential launch pin

The launch document includes each unit's static-properties and fragment hashes.
Embedding that same document's digest in `ExecStart --sha256 ...` would make the
unit depend on its own digest through the launch document. It is not a viable
provisioning recipe. The existing explicit CLIs remain usable as component
interfaces; these manager definitions instead use a fixed argument vector:

```text
<approved-python> -I <approved-package>/service_entry.py --role <supervisor|worker> --anchor <approved-root-anchor>
```

The unit bytes do not contain launch digests, absolute deadlines, environment
substitutions or systemd instance substitutions. A later independently authorized
provisioner can compute the unit hashes, observe/pin the installed manager
properties, construct the matching launch document and finally provision its root
anchor without changing the unit bytes. That ordering avoids a hash cycle; it
does not prove installation integrity, running identity or approval by itself.

## Administrative anchor boundary

`read_service_anchor` accepts only root:root regular single-link files with
0400/0444/0600/0644 modes beneath protected root-owned ancestry. Unsupported
metadata, unsafe links, unsafe ownership/mode, changed bytes/identity/readback,
wrong roles, unknown fields and unbounded arguments refuse. Descriptors close on
failure. The parser allows precisely the existing CLI arguments, not arbitrary
argv, modules, callbacks, execution flags or environment-defined authority.

The exact anchor shape is:

```json
{
  "schema": "host-recovery-service-anchor-v1",
  "role": "worker",
  "unit": "cpa-recovery@<64-character-request-digest>.service",
  "arguments": {
    "approval": "<absolute-protected-launch-file>",
    "sha256": "<independently-approved-launch-digest>",
    "uid": 1000,
    "gid": 1000,
    "endpoint": "<absolute-private-worker-endpoint>",
    "endpoint-device": 1,
    "endpoint-inode": 1,
    "deadline": 1180.0
  }
}
```

Placeholders/numbers above are schema illustrations, **not usable paths, owner
selection, measured phase caps or accepted deadlines**. The supervisor argument
map adds exactly the alert-endpoint/device/inode, alert-receipts/device/inode,
alert-route, listener-uid, listener-instance and alert-deadline fields described
in [the unresolved runner contract](UNRESOLVED-SERVICE-v1.md). All path values use
the restricted literal absolute-path grammar; unsupported spaces, control bytes,
quoting, specifiers and environment expansion refuse rather than being escaped.
Deadlines remain explicit positive original absolute monotonic values. No restart
or new anchor may reset the attempt's allowance; existing original-request
loaders may shorten it and reject old/expired/cross-boot state.

The entrypoint reads the root anchor, verifies the pinned launch document and
checks its supervisor/request-unit identity before calling only the fixed existing
runner. The runner independently reloads/verifies the same launch pin. Public CLI
options are only role and anchor path; there is no root-owner override. Root must
provision readable ancestry/file modes for the intended unprivileged runner.
No file or directory is created, chmodded, chowned or installed by this reader.

Root ownership authenticates the administrator's local anchor, **not** a business
approval, package attestation, producer artifact, kernel/mount integrity or the
complete host fence. The installed interpreter, complete Python import tree and
unit must themselves remain independently reviewed/protected and read back by the
provisioner. An attacker controlling root, the manager, installed code or the mount
namespace is outside this boundary. The private numeric-owner reader used in tests
is not exposed by the CLI and is not evidence of real root provisioning.

## Unit semantics and honest status

`ServiceUnit` renders bytes only. Every unit name, numeric unprivileged UID/GID,
interpreter, package, anchor, read-only inputs and permitted write roots is
explicit. Worker names are exact request-digest instances; supervisor names must
also fit the durable owner protocol (no instance marker, at most 128 characters).
Final fragments exceeding the runtime reader's 65,536-byte limit refuse before
publication. No shell, environment file, install target, failure-hook rollback,
root/capability grant, broad cgroup delegation or supervisor-to-worker stop
dependency is emitted.
The manager must place each separate unit in its own cgroup; this source does not
claim to have observed that placement.

The sandbox sets whole-control-group kill, SIGKILL escalation, no privileges or
capabilities, namespace/control-group protections, strict system read-only mounts,
Unix address-family restriction and 0077 umask. Supervisor write roots must not
overlap interpreter, package, anchor or declared read-only inputs. The identity
worker has **no write roots**. The caller must declare all actual content/journal
paths correctly; the renderer is not an installer, a mount-alias detector or a
verifier of approved root roles. Installed-manager property/fragment pins remain
mandatory. Dropped-in overrides, filesystem aliases and installed byte drift must
be refused by that separate provisioning/observation boundary, not ignored.

Service stdin/stdout/stderr are null so a consumer cannot stall shutdown or turn a
receipt into a success signal. Existing private notice files/local alert IPC carry
the unresolved runner's evidence; null output is never proof of recovery. Both
runners retain their existing nonzero unresolved/refusal exit semantics. Unit
`TimeoutStopSec=1s` is manager shutdown escalation, **not** an additional recovery
allowance, a measured phase cap or a 300-second availability guarantee. Uninterruptible
I/O can still prevent timely termination. The supervisor uses `Restart=on-failure`
to match the existing authenticated bootstrap contract. Both unit definitions
carry explicit `StartLimitIntervalSec=30s`, `StartLimitBurst=3` and `RestartSec=1s`;
these are process-lifetime bounds, not recovery retries or additional reserve.
A replacement invocation cannot adopt the old original-owner request and remains
unresolved under the existing loading/lifecycle rules. The identity worker uses
`Restart=no`. Boot/expired-request reconciliation and separately authorized
continuation remain unfinished.

A render receipt records only schema, role/name and rendered hash; installed,
recovery authority, complete fence and production acceptance are always false.
The caller retains raw unit bytes for independent inspection. No unit is rendered
from untrusted shell input or automatically written to a manager load path.

## Verification boundaries

The tests use real owned files, isolated subprocess CLI refusals and the actual
`systemd-analyze verify` parser on temporary unit files. That verifier does not
start a manager service, install units or prove runtime sandbox enforcement.
Positive administrative-reader tests deliberately supply the test user's numeric
owner through the private seam; the production public reader/CLI actually rejects
those unprivileged anchors. Fixed-runner dispatch uses mocks after real launch
readback. Neither a successful parser nor a scripted callback proves successful
systemd bootstrap/recovery, root provisioning, cgroup/container quiescence or
external alert delivery.

Operational supervisor/worker authority, complete boot/internal-restart/start/
writer/pending-operation fencing, independent restoration/start/readiness oracle,
settlement/continuations, actual producer/ingress/RPC/container/all-source drain,
measured caps/raw availability and the approved disposable pinned-package matrix
remain required. No production or installation gate changes.
